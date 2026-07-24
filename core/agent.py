# core/agent.py
# LangGraph AI agent for the OSINT Pivot Engine.
# Autonomously decides which sources to query, analyzes results,
# and determines whether to continue pivoting based on findings.

import json
import logging
import re
from typing import TypedDict, List
from langgraph.graph import StateGraph, START, END
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from config import ANTHROPIC_API_KEY, MAX_PIVOT_DEPTH
from core.executor import PivotExecutor
from core.scorer import ConfidenceScorer

class AgentState(TypedDict):
    seed: str
    current_seed: str
    indicator_type: str
    pivot_results: List[dict]
    pivot_count: int
    should_continue: bool
    findings: List[str]
    summary: str
    ml_score: float
    context_score: float
    infrastructure_type: str
    context_note: str
    pivot_queue: List[str]
    visited: List[str]

llm = ChatAnthropic(
    model="claude-sonnet-5",
    api_key=ANTHROPIC_API_KEY,
)

executor = PivotExecutor()
scorer = ConfidenceScorer()

logger = logging.getLogger(__name__)


def is_ipv4(value: str) -> bool:
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, value))


def is_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def extract_new_indicators(result: dict, visited: List[str]) -> List[str]:
    """
    Extracts new pivotable indicators from a completed pivot result.
    For domains: extracts IPs from PassiveDNS A records and subdomains from crt.sh.
    For IPs: extracts domains from PassiveDNS records.
    For hashes: extracts related SHA256 hashes from MalwareBazaar tag results.
    """
    new_indicators = []
    indicator_type = result.get("type", "")
    results = result.get("results", {})

    passivedns = results.get("passivedns", {})
    records = passivedns.get("records", [])

    if indicator_type == "domain":
        for record in records:
            ip = record.get("ip", "")
            record_type = record.get("record_type", "")
            if record_type == "a" and ip and is_ipv4(ip) and ip not in visited:
                new_indicators.append(ip)

        censys = results.get("censys", {})
        for cert in censys.get("certificates", []):
            names = cert.get("names", "")
            for name in names.replace("\n", ",").split(","):
                name = name.strip().lstrip("*.")
                if name and is_domain(name) and name not in visited:
                    new_indicators.append(name)

    elif indicator_type == "ipv4":
        for record in records:
            value = record.get("ip", "")
            if value and is_domain(value) and value not in visited:
                new_indicators.append(value)

    elif indicator_type == "hash":
        bazaar_related = results.get("malwarebazaar_related", {})
        samples = bazaar_related.get("samples", [])
        for sample in samples:
            sha256 = sample.get("sha256", "")
            if sha256 and sha256 != "unknown" and sha256 not in visited:
                new_indicators.append(sha256)

    seen = set()
    clean = []
    for ind in new_indicators:
        if ind not in visited and ind not in seen:
            seen.add(ind)
            clean.append(ind)

    return clean


def run_pivot(state: AgentState) -> AgentState:
    """
    Runs the pivot chain for the current_seed indicator.
    Extracts new indicators and adds them to the pivot queue.
    """
    current = state["current_seed"]
    logger.info(f"Agent running pivot for: {current}")

    result = executor.run(current)

    state["pivot_results"].append(result)
    state["pivot_count"] += 1
    state["visited"].append(current)

    new_indicators = extract_new_indicators(result, state["visited"])
    if new_indicators:
        logger.info(f"Discovered {len(new_indicators)} new indicators: {new_indicators}")
        state["pivot_queue"].extend(new_indicators)

    logger.info(f"Pivot {state['pivot_count']} complete. Queue depth: {len(state['pivot_queue'])}")

    return state


def analyze_results(state: AgentState) -> AgentState:
    """
    Uses Claude to analyze pivot results and determine
    whether to continue pivoting or stop and summarize.
    Advances queue and sets next current_seed here.
    """
    logger.info("Agent analyzing pivot results...")

    latest_result = state["pivot_results"][-1]

    system_prompt = """You are an expert cyber threat intelligence analyst.
You will be given OSINT pivot results for a seed indicator.
Your job is to:
1. Identify any suspicious or notable findings
2. Determine whether further pivoting is warranted
3. List specific findings as short bullet points

Respond in JSON format only. Do not wrap your response in markdown code blocks. Return raw JSON only:
{
    "findings": ["finding 1", "finding 2"],
    "should_continue": true or false,
    "reason": "brief explanation of your decision"
}"""

    user_message = f"""Analyze these OSINT pivot results:

Indicator: {state['current_seed']}
Type: {state['indicator_type']}
Pivot count: {state['pivot_count']}
Max allowed pivots: {MAX_PIVOT_DEPTH}
Indicators in queue: {len(state['pivot_queue'])}

Results:
{json.dumps(latest_result, indent=2, default=str)}"""

    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_message)
    ])

    try:
        content = response.content
        if isinstance(content, list):
            content = content[0].get("text", "") if content else ""

        # Strip markdown fences if Claude wraps response despite instructions
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        analysis = json.loads(content)
        state["findings"].extend(analysis.get("findings", []))
        state["should_continue"] = analysis.get("should_continue", False)
        logger.info(f"Analysis complete. Continue: {state['should_continue']}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response as JSON: {e} | Raw: {content[:200]}")
        state["should_continue"] = False

    # If queue is empty, stop regardless of what the LLM decided
    if not state["pivot_queue"]:
        state["should_continue"] = False
        logger.info("Queue is empty. Moving to summarize.")

    # Advance queue — skip anything already visited
    if state["pivot_queue"] and state["pivot_count"] < MAX_PIVOT_DEPTH:
        next_seed = None
        while state["pivot_queue"]:
            candidate = state["pivot_queue"].pop(0)
            if candidate not in state["visited"]:
                next_seed = candidate
                break
        if next_seed:
            state["current_seed"] = next_seed
            state["should_continue"] = True
            logger.info(f"Advancing to next indicator: {next_seed}")
        else:
            state["should_continue"] = False
            logger.info("Queue exhausted after deduplication. Moving to summarize.")

    return state


def apply_context(state: AgentState) -> AgentState:
    """
    Runs the context layer on pivot results.
    Calculates both ML score and context adjusted score.
    """
    logger.info("Applying context layer...")

    if not state["pivot_results"]:
        return state

    pivot_result = state["pivot_results"][0]

    raw = scorer.score(pivot_result)
    ml_score = raw.get("confidence_score", 0.0)

    from core.context import detect_infrastructure_type
    context = detect_infrastructure_type(pivot_result)

    modifier = context.get("confidence_modifier", 0.0)
    context_score = max(0.0, min(1.0, ml_score + modifier))

    state["ml_score"] = ml_score
    state["context_score"] = round(context_score, 4)
    state["infrastructure_type"] = context.get("infrastructure_type", "unknown")

    logger.info(f"ML score: {ml_score} | Context score: {context_score} | Infrastructure: {state['infrastructure_type']}")

    return state


def summarize(state: AgentState) -> AgentState:
    """
    Uses Claude to produce a final analyst-facing
    investigation summary and context note.
    """
    logger.info("Agent generating final summary...")

    system_prompt = """You are an expert cyber threat intelligence analyst reviewing OSINT pivot results.

Your job is to produce two things:

1. A concise investigation summary (under 200 words) covering:
   - Threat level and overall assessment
   - Key indicators and what they mean
   - Notable gaps in visibility
   - Recommended analyst actions

2. A single sentence context note explaining the difference between 
   the ML score and the context adjusted score. Be specific to the 
   infrastructure type detected. If no infrastructure type was detected 
   write nothing for the note.

Write for a SOC analyst who needs to make a fast, informed decision. 
Avoid generic statements. Be precise and actionable.
Never fabricate data not present in the results.
If sources failed or returned errors acknowledge the visibility gap."""

    user_message = f"""Write an investigation summary for:

Seed Indicator: {state['seed']}
Total indicators investigated: {len(state['visited'])}
All investigated indicators: {state['visited']}
Total pivots run: {state['pivot_count']}
ML Score: {state['ml_score']}
Context Score: {state['context_score']}
Infrastructure Type: {state['infrastructure_type']}

Key findings:
{json.dumps(state['findings'], indent=2)}

Full results:
{json.dumps(state['pivot_results'], indent=2, default=str)}

Also write a one sentence context note explaining why the ML score 
and context score differ if they do. If infrastructure type is unknown 
write nothing for the note. Be specific to this indicator."""

    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_message)
    ])

    content = response.content
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                content = block.get("text", "")
                break

    state["summary"] = content
    state["context_note"] = f"Infrastructure identified as {state['infrastructure_type']}." if state['infrastructure_type'] != "unknown" else ""

    logger.info("Summary complete.")
    return state


def should_continue_pivot(state: AgentState) -> str:
    """
    Routing function only — no state mutation here.
    Decision is based on should_continue flag set in analyze_results.
    """
    if state["pivot_count"] >= MAX_PIVOT_DEPTH:
        logger.info("Max pivot depth reached. Moving to summarize.")
        return "summarize"

    if state["should_continue"]:
        logger.info(f"Continuing pivot on: {state['current_seed']}")
        return "run_pivot"

    logger.info("No more indicators to investigate. Moving to summarize.")
    return "summarize"


def build_agent() -> StateGraph:
    """
    Builds and compiles the LangGraph agent.
    """
    graph = StateGraph(AgentState)

    graph.add_node("run_pivot", run_pivot)
    graph.add_node("analyze_results", analyze_results)
    graph.add_node("apply_context", apply_context)
    graph.add_node("summarize", summarize)

    graph.add_edge(START, "run_pivot")
    graph.add_edge("run_pivot", "analyze_results")
    graph.add_conditional_edges(
        "analyze_results",
        should_continue_pivot,
        {
            "run_pivot": "run_pivot",
            "summarize": "apply_context"
        }
    )
    graph.add_edge("apply_context", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile()


def run_agent(seed: str) -> dict:
    """
    Entry point for the OSINT Pivot Engine agent.
    """
    agent = build_agent()

    initial_state = AgentState(
        seed=seed,
        current_seed=seed,
        indicator_type="",
        pivot_results=[],
        pivot_count=0,
        should_continue=True,
        findings=[],
        summary="",
        ml_score=0.0,
        context_score=0.0,
        infrastructure_type="unknown",
        context_note="",
        pivot_queue=[],
        visited=[]
    )

    logger.info(f"Agent starting investigation for: {seed[:50]}")

    final_state = agent.invoke(initial_state)

    return {
        "indicator": seed,
        "indicators_investigated": final_state["visited"],
        "pivot_count": final_state["pivot_count"],
        "ml_score": final_state["ml_score"],
        "context_score": final_state["context_score"],
        "infrastructure_type": final_state["infrastructure_type"],
        "context_note": final_state["context_note"],
        "findings": final_state["findings"],
        "summary": final_state["summary"],
        "full_results": final_state["pivot_results"]
    }