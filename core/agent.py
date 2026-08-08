# core/agent.py
# LangGraph agent for the OSINT Pivot Engine.
# Orchestrates the pivot chain, scoring, NER extraction, and summarization.



import json
import logging
import re
 
from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage, HumanMessage
 
import config
from config import ANTHROPIC_API_KEY
from core.executor import PivotExecutor
from core.scorer import ConfidenceScorer
from core.context import detect_infrastructure_type
from core.graph_scorer import GraphScorer
from core.temporal_scorer import TemporalScorer
from core.ner_extractor import NERExtractor
from core.detector import detect_type
 
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)
 
# Global instances
llm = ChatAnthropic(
    model="claude-fable-5",
    api_key=ANTHROPIC_API_KEY,
)
 
executor = PivotExecutor()
scorer = ConfidenceScorer()
graph_scorer = GraphScorer()
temporal_scorer = TemporalScorer()
ner_extractor = NERExtractor()
 
 
class AgentState(TypedDict):
    seed: str
    current_seed: str
    indicator_type: str
    pivot_results: list[dict]
    pivot_queue: list[str]
    visited: list[str]
    findings: list[str]
    should_continue: bool
    ml_score: float
    context_score: float
    infrastructure_type: str
    context_note: str
    summary: str
    pivot_count: int
 
 
def is_ipv4(value: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value))
 
 
def is_domain(value: str) -> bool:
    return bool(re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        value
    ))
 
 
def safe_json(obj: object, limit: int = 0) -> str:
    """Serializes an object to JSON string with optional character limit."""
    result = json.dumps(obj, indent=2, default=str)
    if limit > 0:
        return result[:limit]
    return result
 
 
def extract_new_indicators(result: dict, visited: list[str]) -> list[str]:
    """
    Extracts new pivotable indicators from a completed pivot result.
    For domains: extracts IPs from PassiveDNS and subdomains from crt.sh.
    For IPs: extracts domains from PassiveDNS records.
    For hashes: extracts related SHA256 hashes from MalwareBazaar tag results.
    """
    new_indicators: list[str] = []
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
 
    # NER extraction — scan text fields for threat actor mentions
    threat_actors = ner_extractor.extract_threat_actors(result, visited)
    for actor in threat_actors:
        if actor not in new_indicators:
            new_indicators.append(actor)
 
    seen: set[str] = set()
    clean: list[str] = []
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
 
 
def _parse_llm_json(content: object) -> dict:
    """
    Extracts and parses JSON from an LLM response.
    Handles list content blocks, markdown fences, and empty responses.
    Returns parsed dict or raises ValueError if unparseable.
    """
    if isinstance(content, list):
        content = content[0].get("text", "") if content else ""
 
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Empty response from LLM")
 
    text = content.strip()
 
    # Strip markdown fences
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
 
    return json.loads(text)
 
 
def analyze_results(state: AgentState) -> AgentState:
    """
    Uses Claude to analyze pivot results and determine
    whether to continue pivoting or stop and summarize.
    Advances queue and sets next current_seed here.
    """
    logger.info("Agent analyzing pivot results...")
 
    latest_result = state["pivot_results"][-1]
    result_str = safe_json(latest_result, limit=4000)
 
    system_prompt = (
        "You are an expert cyber threat intelligence analyst.\n"
        "You will be given OSINT pivot results for a seed indicator.\n\n"
        "You MUST respond with ONLY a valid JSON object. No preamble, no explanation, no markdown.\n"
        "The response must start with { and end with }.\n\n"
        'Required format:\n{"findings": ["finding 1", "finding 2"], "should_continue": true, "reason": "brief explanation"}\n\n'
        "Rules:\n"
        "- findings: list of strings, each a specific notable finding from the data\n"
        "- should_continue: boolean, true if more pivoting would yield useful intelligence\n"
        "- reason: one sentence explaining your decision"
    )
 
    user_message = (
        "Analyze these OSINT pivot results:\n\n"
        f"Indicator: {state['current_seed']}\n"
        f"Type: {state['indicator_type']}\n"
        f"Pivot count: {state['pivot_count']}\n"
        f"Max allowed pivots: {config.MAX_PIVOT_DEPTH}\n"
        f"Indicators in queue: {len(state['pivot_queue'])}\n\n"
        f"Results:\n{result_str}"
    )
 
    parse_succeeded = False
 
    try:
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message)
        ])
        analysis = _parse_llm_json(response.content)
        state["findings"].extend(analysis.get("findings", []))
        state["should_continue"] = analysis.get("should_continue", False)
        logger.info(f"Analysis complete. Continue: {state['should_continue']}")
        parse_succeeded = True
 
    except Exception:
        # Retry with minimal prompt
        try:
            retry_result_str = safe_json(latest_result, limit=2000)
            retry_response = llm.invoke([
                SystemMessage(content='Respond with ONLY valid JSON. Format: {"findings": [], "should_continue": false, "reason": ""}'),
                HumanMessage(content=f"Analyze this and return JSON only:\n{retry_result_str}")
            ])
            analysis = _parse_llm_json(retry_response.content)
            state["findings"].extend(analysis.get("findings", []))
            state["should_continue"] = analysis.get("should_continue", False)
            parse_succeeded = True
            logger.info("Analyze retry succeeded.")
        except Exception:
            logger.info("analyze_results: using fallback, continuing based on queue.")
            state["should_continue"] = len(state["pivot_queue"]) > 0
 
    # NER — scan latest pivot result for threat actor mentions and queue them
    latest = state["pivot_results"][-1]
    actors = ner_extractor.extract_threat_actors(latest, state["visited"])
    for actor in actors:
        if actor not in state["pivot_queue"] and actor not in state["visited"]:
            state["pivot_queue"].append(actor)
            logger.info(f"NER queued threat actor: {actor}")
 
    # If queue is empty, stop regardless of what the LLM decided
    if not state["pivot_queue"]:
        state["should_continue"] = False
        logger.info("Queue is empty. Moving to summarize.")
 
    # Advance queue — skip anything already visited
    if state["pivot_queue"] and state["pivot_count"] < config.MAX_PIVOT_DEPTH:
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
    Calculates ML score, graph score, temporal score, and context adjusted score.
    """
    logger.info("Applying context layer...")
 
    if not state["pivot_results"]:
        return state
 
    pivot_result = state["pivot_results"][0]
    indicator_type = pivot_result.get("type", "")
 
    if indicator_type == "threat_group":
        raw = scorer.score_threat_group(pivot_result)
        ml_score = raw.get("confidence_score", 0.0)
        graph_score = 0.0
        temporal_score = 0.0
        early_warning = False
    else:
        raw = scorer.score(pivot_result)
        ml_score = raw.get("confidence_score", 0.0)
 
        graph_scores = graph_scorer.score_all(state["pivot_results"])
        graph_score = graph_scores.get(state["seed"], 0.0)
 
        temporal_result = temporal_scorer.score(pivot_result)
        temporal_score = temporal_result.get("temporal_score", 0.0)
        early_warning = temporal_result.get("early_warning", False)
 
    blended_score = graph_scorer.blend_scores(ml_score, graph_score)
    blended_score = temporal_scorer.blend_with_ml(blended_score, temporal_score)
 
    context = detect_infrastructure_type(pivot_result)
    modifier = context.get("confidence_modifier", 0.0)
    context_score = max(0.0, min(1.0, blended_score + modifier))
 
    state["ml_score"] = blended_score
    state["context_score"] = round(context_score, 4)
    state["infrastructure_type"] = context.get("infrastructure_type", "unknown")
 
    if early_warning:
        state["findings"].append(
            "EARLY WARNING: Related malware samples detected within the last 7 days — active campaign signal."
        )
 
    logger.info(f"ML: {blended_score} | Graph: {graph_score} | Temporal: {temporal_score} | Context: {context_score}")
 
    return state
 
 
def summarize(state: AgentState) -> AgentState:
    """
    Uses Claude to produce a final analyst-facing
    investigation summary and context note.
    Runs NER on the generated summary to surface
    any threat actor mentions for analyst follow-up.
    """
    logger.info("Agent generating final summary...")
 
    findings_str = safe_json(state["findings"])
    results_str = safe_json(state["pivot_results"])
 
    system_prompt = (
        "You are an expert cyber threat intelligence analyst reviewing OSINT pivot results.\n\n"
        "Produce a structured investigation summary using exactly this format:\n\n"
        "THREAT LEVEL: [HIGH / MEDIUM / LOW / UNKNOWN] — [one sentence verdict]\n\n"
        "ASSESSMENT:\n"
        "[2-3 sentences covering what was found and what it means. Be specific to the actual data.]\n\n"
        "KEY INDICATORS:\n"
        "- [Specific finding 1]\n"
        "- [Specific finding 2]\n"
        "- [Specific finding 3 if applicable]\n\n"
        "VISIBILITY GAPS:\n"
        "[One sentence on what sources failed or returned no data.]\n\n"
        "RECOMMENDED ACTIONS:\n"
        "1. [Specific action]\n"
        "2. [Specific action]\n"
        "3. [Specific action if applicable]\n\n"
        "Write for a SOC analyst making a fast decision. Never fabricate data not in the results. "
        "If a source errored, acknowledge the gap. No markdown headers with # symbols. No bold with **."
    )
 
    user_message = (
        "Write an investigation summary for:\n\n"
        f"Seed Indicator: {state['seed']}\n"
        f"Indicators investigated: {state['visited']}\n"
        f"Pivots run: {state['pivot_count']}\n"
        f"ML Score: {state['ml_score']}\n"
        f"Context Score: {state['context_score']}\n"
        f"Infrastructure Type: {state['infrastructure_type']}\n\n"
        f"Key findings:\n{findings_str}\n\n"
        f"Full results:\n{results_str}"
    )
 
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
 
    state["summary"] = content if isinstance(content, str) else ""
 
    # NER — scan summary text for threat actor mentions
    summary_pseudo_result = {"results": {"ahmia": {"results": [{"snippet": state["summary"]}]}}}
    actors_found = ner_extractor.extract_threat_actors(summary_pseudo_result, state["visited"])
    if actors_found:
        note = f"Threat actors mentioned in summary (recommend follow-up pivots): {', '.join(actors_found)}"
        state["findings"].append(note)
        logger.info(f"NER found actors in summary: {actors_found}")
 
    state["context_note"] = (
        f"Infrastructure identified as {state['infrastructure_type']}."
        if state["infrastructure_type"] != "unknown"
        else ""
    )
 
    logger.info("Summary complete.")
    return state
 
 
def should_continue_pivot(state: AgentState) -> str:
    if state["pivot_count"] >= config.MAX_PIVOT_DEPTH:
        return "summarize"
    if state["should_continue"]:
        return "run_pivot"
    return "summarize"
 
 
def run_agent(seed: str) -> dict:
    """
    Entry point for the OSINT Pivot Engine agent.
    Initializes state and runs the full LangGraph pipeline.
    """
    detected = detect_type(seed)
    indicator_type = detected["type"] if detected else "unknown"
 
    initial_state: AgentState = {
        "seed": seed,
        "current_seed": seed,
        "indicator_type": indicator_type,
        "pivot_results": [],
        "pivot_queue": [],
        "visited": [],
        "findings": [],
        "should_continue": True,
        "ml_score": 0.0,
        "context_score": 0.0,
        "infrastructure_type": "unknown",
        "context_note": "",
        "summary": "",
        "pivot_count": 0,
    }
 
    graph = StateGraph(AgentState)
    graph.add_node("run_pivot", run_pivot)
    graph.add_node("analyze_results", analyze_results)
    graph.add_node("apply_context", apply_context)
    graph.add_node("summarize", summarize)
 
    graph.set_entry_point("run_pivot")
    graph.add_edge("run_pivot", "analyze_results")
    graph.add_conditional_edges(
        "analyze_results",
        should_continue_pivot,
        {"run_pivot": "run_pivot", "summarize": "apply_context"}
    )
    graph.add_edge("apply_context", "summarize")
    graph.add_edge("summarize", END)
 
    agent = graph.compile()
    final_state = agent.invoke(initial_state)
 
    return {
        "summary": final_state["summary"],
        "findings": final_state["findings"],
        "pivot_count": final_state["pivot_count"],
        "ml_score": final_state["ml_score"],
        "context_score": final_state["context_score"],
        "infrastructure_type": final_state["infrastructure_type"],
        "context_note": final_state["context_note"],
        "full_results": final_state["pivot_results"],
        "visited": final_state["visited"],
        "indicator": seed,
    }