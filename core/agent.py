# core/agent.py
# LangGraph agent for the OSINT Pivot Engine.
# Orchestrates the pivot chain, scoring, NER extraction, and summarization.



import json
import logging
import re
import time

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
from core.risk import (
    NON_INFRASTRUCTURE_TYPES,
    DEFAULT_THRESHOLDS,
    enforce_verdict,
    resolve_risk_level,
)
from core import disagreement

# tier.py is local-only, like the licensed connectors it detects. A public clone
# does not have it, so a null object stands in — an engine without the module is
# an engine without the licences, which is exactly the open-source tier.
try:
    from core import tier
except ImportError:
    class _OpenSourceTier:
        @staticmethod
        def active() -> str:
            return "open-source"

        @staticmethod
        def licensed_sources() -> list:
            return []

        @staticmethod
        def describe() -> str:
            return "open-source tier — no licensed sources configured."

        @staticmethod
        def reproducible_without_licence(result: dict) -> bool:
            return True

    tier = _OpenSourceTier()
from core.relevance import assess_relevance, load_profile
 
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)
 
# Global instances
llm = ChatAnthropic(
    model="claude-fable-5-1",
    api_key=ANTHROPIC_API_KEY,
)

# The summary call returns empty content without raising, seen once in four
# identical calls. Retried because the verdict surviving is not enough: a lost
# summary takes the DISSENT line with it, and that is the only channel for a
# compromised site no feed has caught yet.
SUMMARY_ATTEMPTS = 2
SUMMARY_BACKOFF = 1.5
 
# Loaded once at import. None when no profile exists, which disables the layer.
org_profile = load_profile()

executor = PivotExecutor()
scorer = ConfidenceScorer(org_profile=org_profile)
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
    deep: bool
    relevance_level: str
    # No source answered, so context_score is an absence rather than a low
    # reading. core.risk turns this into UNKNOWN.
    insufficient_data: bool
    # Per-type thresholds from the scorer, reapplied by core.risk.
    risk_thresholds: list
    # The LLM produced no summary. The scores stand; the assessment is missing.
    summary_failed: bool
    # The model's own output, before graph and temporal blending, with the
    # measured meaning of its band. Kept separate because band_precision was
    # measured on this number and not on the blended one, and because the
    # blending stages are otherwise invisible to anyone reading a result.
    model_score: float
    band_precision: float | None
    graph_score: float
    temporal_score: float
 
 
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
    records = list(passivedns.get("records", []))

    # DNSDB emits a passivedns-shaped records list, so it chains through the
    # same branches. Merged rather than substituted — the free tier sometimes
    # holds records DNSDB's limit truncated, and dedup below handles overlap.
    dnsdb = results.get("dnsdb", {})
    if isinstance(dnsdb, dict):
        records.extend(dnsdb.get("records", []) or [])
 
    if indicator_type == "domain":
        for record in records:
            ip = record.get("ip", "")
            record_type = record.get("record_type", "")
            if record_type == "a" and ip and is_ipv4(ip) and ip not in visited:
                new_indicators.append(ip)

        # Where the domain points now. Chained alongside passive DNS, not
        # instead of it: a domain with no history still resolves, and reading
        # only passive DNS stopped salviadivinorumseeds.net at one pivot while
        # its two live addresses sat unexamined in the same result.
        for ip in (results.get("dns", {}) or {}).get("a", []) or []:
            if is_ipv4(ip) and ip not in visited:
                new_indicators.append(ip)

        # crt.sh moved to its own key; older saved investigations still have
        # it under "censys".
        certs = results.get("crtsh") or results.get("censys") or {}
        for cert in certs.get("certificates", []):
            names = cert.get("names", "")
            for name in names.replace("\n", ",").split(","):
                name = name.strip().lstrip("*.")
                if name and is_domain(name) and name not in visited:
                    new_indicators.append(name)
 
    elif indicator_type == "url":
        # The host gets its own pivot, and any payload URLhaus recorded is a
        # sample worth following. Without this a URL seed stopped at one pivot.
        host = (results.get("url_parts") or {}).get("host") or ""
        if host and host not in visited:
            new_indicators.append(host)
        for payload in (results.get("urlhaus") or {}).get("payloads") or []:
            sha256 = payload.get("sha256", "")
            if sha256 and sha256 not in visited:
                new_indicators.append(sha256)

    elif indicator_type == "ipv4":
        for record in records:
            # Either key: passivedns.query_ip emits "domain", DNSDB emits both.
            # Reading only "ip" here meant an address never chained a single
            # co-tenant, and the pivot looked like passive DNS had nothing.
            value = record.get("domain") or record.get("ip") or ""
            if value and is_domain(value) and value not in visited:
                new_indicators.append(value)
 
    elif indicator_type == "hash":
        bazaar_related = results.get("malwarebazaar_related", {})
        samples = bazaar_related.get("samples", [])
        for sample in samples:
            sha256 = sample.get("sha256", "")
            if sha256 and sha256 != "unknown" and sha256 not in visited:
                new_indicators.append(sha256)

    elif indicator_type == "threat_group":
        # Sample hashes from the group's tooling, so the pivot continues into
        # live samples rather than dead-ending at ATT&CK.
        for bazaar_result in results.get("malwarebazaar_tooling", {}).values():
            if not isinstance(bazaar_result, dict):
                continue
            for sample in bazaar_result.get("samples", []):
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
 
    result = executor.run(current, deep=state["deep"])
 
    state["pivot_results"].append(result)
    state["pivot_count"] += 1
    state["visited"].append(current)
 
    new_indicators = extract_new_indicators(result, state["visited"])
    if new_indicators:
        logger.info(f"Discovered {len(new_indicators)} new indicators: {new_indicators}")
        state["pivot_queue"].extend(new_indicators)
 
    logger.info(f"Pivot {state['pivot_count']} complete. Queue depth: {len(state['pivot_queue'])}")
 
    return state
 
 
def extract_findings(result: dict) -> list[str]:
    """Builds the findings list for one pivot result from connector output."""
    findings: list[str] = []
    indicator = result.get("indicator", "")
    results = result.get("results", {})

    # VirusTotal — detection consensus and family label
    vt = results.get("virustotal", {})
    malicious = vt.get("malicious_votes", 0)
    harmless = vt.get("harmless_votes", 0)
    if malicious:
        findings.append(
            f"{indicator}: VirusTotal flagged malicious by {malicious} of "
            f"{malicious + harmless} engines."
        )
    if vt.get("malware_family"):
        findings.append(f"{indicator}: VirusTotal family label — {vt['malware_family']}.")

    # Live DNS — current state, and whether the zone answers for any label.
    live = results.get("dns", {})
    if isinstance(live, dict) and "error" not in live:
        if live.get("a") or live.get("aaaa"):
            addresses = ", ".join((live.get("a") or []) + (live.get("aaaa") or []))
            findings.append(f"{indicator}: currently resolves to {addresses}.")
        elif live.get("resolves") is False:
            findings.append(f"{indicator}: does not currently resolve.")
        if live.get("cname"):
            findings.append(f"{indicator}: CNAME to {', '.join(live['cname'])}.")

        # Reported as an observation, not a recommendation. A wildcard is cPanel's
        # default on shared hosting and also the signature of generated attacker
        # hostnames, so what it means depends on context the connector lacks.
        wildcard = live.get("wildcard") or {}
        if wildcard.get("is_wildcard"):
            findings.append(
                f"{indicator}: zone {wildcard.get('zone_apex')} resolves any label "
                f"(wildcard confirmed via probe {wildcard.get('probe')}), so arbitrary "
                f"hostnames under it resolve and a single hostname carries little weight "
                f"by itself. Common on both shared hosting and generated infrastructure."
            )
        if live.get("ptr"):
            findings.append(f"{indicator}: reverse DNS — {', '.join(live['ptr'])}.")

    # Shodan and Censys — exposed services and hosting
    shodan = results.get("shodan", {})
    censys = results.get("censys", {})
    ports = shodan.get("open_ports", []) or censys.get("open_ports", [])
    if ports:
        port_list = ", ".join(str(p) for p in ports[:8])
        findings.append(f"{indicator}: {len(ports)} open ports — {port_list}.")

    if shodan.get("organization"):
        findings.append(f"{indicator}: hosted by {shodan['organization']}.")

    # The port from a host:port seed. The pivot is on the host, so this is the
    # only place the reported service survives.
    #
    # Corroborated against the scan only when the scan actually returned ports.
    # An errored or empty Shodan saying nothing about a port is not the port
    # being closed, and writing it that way would retire a live C2 on silence.
    seed_port = results.get("seed_port") or {}
    if seed_port.get("port"):
        port = seed_port["port"]
        odd = " (non-standard)" if seed_port.get("non_standard_port") else ""
        if not ports:
            corroboration = (
                ", and no scan data came back to say whether it is open"
            )
        elif port in ports:
            corroboration = ", confirmed open by the scan above"
        else:
            corroboration = (
                f", which the scan above does not list among the {len(ports)} "
                f"open ports it saw"
            )
        findings.append(
            f"{indicator}: reported as a service on port {port}{odd}"
            f"{corroboration}."
        )

    country = censys.get("country", "")
    if country and country != "unknown":
        findings.append(f"{indicator}: geolocated to {country}.")

    # PassiveDNS — resolution history breadth
    record_count = results.get("passivedns", {}).get("record_count", 0)
    if record_count:
        findings.append(f"{indicator}: {record_count} historical DNS records.")

    # URLhaus — active delivery infrastructure
    urlhaus = results.get("urlhaus", {})
    if urlhaus.get("found"):
        online = sum(1 for u in urlhaus.get("urls", []) if u.get("status") == "online")
        findings.append(
            f"{indicator}: URLhaus lists {urlhaus.get('url_count', 0)} malicious URLs "
            f"({online} currently online)."
        )

    # Our own pulses are excluded from the count by the connector. Reported
    # separately so they stay visible without reading as independent
    # corroboration of our own earlier conclusions.
    otx = results.get("otx", {})
    if isinstance(otx, dict) and otx.get("own_pulse_count"):
        findings.append(
            f"{indicator}: {otx['own_pulse_count']} of the OTX pulses naming this "
            f"indicator are your own ({', '.join(otx.get('own_pulses') or [])}) and are "
            f"excluded from the corroboration count."
        )

    # OTX — community pulse reporting
    otx = results.get("otx", {})
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count:
        names = [p.get("name", "") for p in otx.get("pulses", [])[:3] if p.get("name")]
        detail = f" Including: {'; '.join(names)}." if names else ""
        findings.append(f"{indicator}: referenced in {pulse_count} OTX pulses.{detail}")

    # MalwareBazaar returns two shapes: one sample inline (hash lookups), or a
    # "samples" list (signature and filename lookups).
    bazaar = results.get("malwarebazaar", {})
    if bazaar.get("found") and "samples" in bazaar:
        samples = bazaar.get("samples", [])
        total = bazaar.get("sample_count", len(samples))
        qualifier = "+" if bazaar.get("count_at_api_ceiling") else ""
        findings.append(
            f"{indicator}: MalwareBazaar has {total}{qualifier} matching samples."
        )
        families = sorted({
            s.get("malware_family") for s in samples
            if s.get("malware_family") and s.get("malware_family") != "unknown"
        })
        if families:
            findings.append(f"{indicator}: sample families — {', '.join(families[:5])}.")
        sample_tags = sorted({t for s in samples for t in s.get("tags", []) or []})
        if sample_tags:
            findings.append(f"{indicator}: sample tags — {', '.join(sample_tags[:8])}.")
        seen = sorted(s.get("first_seen") for s in samples if s.get("first_seen"))
        if seen:
            findings.append(
                f"{indicator}: samples first seen between {seen[0]} and {seen[-1]}."
            )
    elif bazaar.get("found"):
        findings.append(
            f"{indicator}: MalwareBazaar sample — family "
            f"{bazaar.get('malware_family') or 'unclassified'}, type "
            f"{bazaar.get('file_type', 'unknown')}, first seen "
            f"{bazaar.get('first_seen', 'unknown')}."
        )
        tags = bazaar.get("tags", [])
        if tags:
            findings.append(f"{indicator}: MalwareBazaar tags — {', '.join(tags[:8])}.")

    related = results.get("malwarebazaar_related", {})
    if related.get("found"):
        findings.append(
            f"{indicator}: {related.get('sample_count', 0)} related samples share "
            "this malware family tag."
        )

    # Threat group tooling chained into MalwareBazaar by pivot_group
    tooling = results.get("malwarebazaar_tooling")
    if isinstance(tooling, dict) and tooling:
        with_samples = {
            name: r.get("sample_count", 0)
            for name, r in tooling.items()
            if isinstance(r, dict) and r.get("found")
        }
        if with_samples:
            detail = ", ".join(f"{n} ({c})" for n, c in sorted(with_samples.items()))
            findings.append(
                f"{indicator}: live MalwareBazaar samples for group tooling — {detail}."
            )
        else:
            findings.append(
                f"{indicator}: no live samples on MalwareBazaar for any chainable "
                f"tooling ({', '.join(sorted(tooling))})."
            )
    elif isinstance(tooling, dict) and results.get("mitre", {}).get("found"):
        # Nothing chainable means a living-off-the-land actor, which is itself
        # a finding rather than an absence of one.
        findings.append(
            f"{indicator}: no purpose-built malware attributed to this group — "
            "tooling is entirely living-off-the-land binaries."
        )

    # OTX community reporting on a name. For groups ATT&CK does not profile,
    # this is the only evidence the actor exists at all.
    #
    # Only threat_group pivots query it, so the key has to be present rather than
    # merely defaulting to {}. An absent lookup previously fell through to the
    # negative branch — {} is a dict with no "error" — and every IP, domain and
    # hash pivot asserted there was no community reporting on a name that was
    # never searched for.
    otx_search = results.get("otx_search")
    if isinstance(otx_search, dict):
        if otx_search.get("found"):
            findings.append(
                f"{indicator}: named in {otx_search.get('pulse_count', 0)} OTX community "
                f"pulses from {otx_search.get('distinct_authors', 0)} independent authors."
            )
            recent = [p.get("name", "") for p in otx_search.get("pulses", [])[:3] if p.get("name")]
            if recent:
                findings.append(f"{indicator}: community reporting — {'; '.join(recent)}.")
            if otx_search.get("malware_families"):
                findings.append(
                    f"{indicator}: tooling named in reporting — "
                    f"{', '.join(otx_search['malware_families'][:6])}."
                )
        elif "error" not in otx_search:
            findings.append(f"{indicator}: no OTX community reporting found for this name.")

    # Hacktivist read. Alignment and stated targeting are the whole picture for
    # these crews — there is usually no malware to report.
    hack = results.get("hacktivist", {})
    if isinstance(hack, dict) and hack.get("is_hacktivist"):
        basis = "on the known-crew roster" if hack.get("on_roster") else "from reporting"
        findings.append(
            f"{indicator}: assessed as a hacktivist crew ({basis}, "
            f"{hack.get('confidence', 'unknown')} confidence)."
        )
        if hack.get("alignments"):
            findings.append(
                f"{indicator}: reported alignment — {', '.join(hack['alignments'][:3])}."
            )
        if hack.get("activities"):
            findings.append(
                f"{indicator}: observed activity — {', '.join(hack['activities'])}."
            )
        targets = []
        if hack.get("target_sectors"):
            targets.append(f"sectors {', '.join(hack['target_sectors'][:4])}")
        if hack.get("target_countries"):
            targets.append(f"countries {', '.join(hack['target_countries'][:4])}")
        if targets:
            findings.append(f"{indicator}: stated targeting — {'; '.join(targets)}.")
        else:
            findings.append(
                f"{indicator}: no specific targeting named in available reporting."
            )

    # MITRE ATT&CK — technique coverage and attribution.
    mitre = results.get("mitre", {})
    if mitre.get("found"):
        if mitre.get("group_name"):
            aliases = mitre.get("aliases", [])
            alias_note = f" (aliases: {', '.join(aliases[:6])})" if aliases else ""
            findings.append(
                f"{indicator}: matches MITRE ATT&CK group "
                f"{mitre['group_name']}{alias_note}."
            )
        if mitre.get("software_name"):
            findings.append(
                f"{indicator}: matches MITRE ATT&CK software entry "
                f"{mitre['software_name']}."
            )

        # True totals, not len() of the truncated lists.
        techniques = mitre.get("techniques", [])
        if techniques:
            total = mitre.get("technique_count", len(techniques))
            ids = ", ".join(t.get("technique_id", "") for t in techniques[:5])
            findings.append(
                f"{indicator}: MITRE ATT&CK maps {total} techniques — {ids}"
                f"{' and others' if total > 5 else ''}."
            )
        groups = mitre.get("groups", [])
        if groups:
            total = mitre.get("group_count", len(groups))
            names = ", ".join(g.get("name", "") for g in groups[:5])
            findings.append(
                f"{indicator}: attributed to {total} threat groups — {names}"
                f"{' and others' if total > 5 else ''}."
            )
        software = mitre.get("software", [])
        if software:
            total = mitre.get("software_count", len(software))
            names = ", ".join(s.get("name", "") for s in software[:5])
            findings.append(
                f"{indicator}: {total} associated software entries — {names}"
                f"{' and others' if total > 5 else ''}."
            )

    # SpiderFoot — identity footprint
    spiderfoot = results.get("spiderfoot", {})
    if spiderfoot.get("finding_count"):
        findings.append(
            f"{indicator}: SpiderFoot returned "
            f"{spiderfoot['finding_count']} identity findings."
        )

    # Visibility gaps — name the sources that failed so summarize can cite them
    errored = sorted(
        name for name, payload in results.items()
        if isinstance(payload, dict) and "error" in payload
    )
    if errored:
        findings.append(f"{indicator}: no data returned from {', '.join(errored)}.")

    return findings
 
 
def analyze_results(state: AgentState) -> AgentState:
    """
    Records findings from the latest pivot and advances the queue.
    Deterministic — control flow comes from the queue and the depth cap.
    """
    logger.info("Recording findings and advancing queue...")

    latest = state["pivot_results"][-1]
    state["findings"].extend(extract_findings(latest))

    # NER — scan latest pivot result for threat actor mentions and queue them
    actors = ner_extractor.extract_threat_actors(latest, state["visited"])
    for actor in actors:
        if actor not in state["pivot_queue"] and actor not in state["visited"]:
            state["pivot_queue"].append(actor)
            logger.info(f"NER queued threat actor: {actor}")

    # Advance queue — take the first candidate we have not already pivoted on
    state["should_continue"] = False
    if state["pivot_count"] < config.MAX_PIVOT_DEPTH:
        while state["pivot_queue"]:
            candidate = state["pivot_queue"].pop(0)
            if candidate not in state["visited"]:
                state["current_seed"] = candidate
                state["should_continue"] = True
                logger.info(f"Advancing to next indicator: {candidate}")
                break

    if not state["should_continue"]:
        logger.info("No unvisited indicators remaining. Moving to summarize.")

    return state
 
 
# How much the strongest chained pivot can lift a non-infrastructure seed score.
#
# Infrastructure seeds already get chain awareness from graph_scorer, which runs
# across every pivot. Group, software and identity seeds skip it, so their score
# came from the seed pivot alone. Moonstone Sleet scored 0.2498 on ATT&CK
# coverage — 1 of 23 software entries — while four of its chained Qilin samples
# came back unanimously malicious on VirusTotal, and none of that counted.
#
# Indirect evidence, since it is the tooling that was measured and not the actor,
# so it lifts and never lowers.
CHAIN_EVIDENCE_WEIGHT = 0.65


def _apply_chain_evidence(seed_score: float, state: AgentState) -> tuple[float, dict]:
    """
    Lifts a seed score by the strongest score among the pivots chained off it.
    Returns the new score and the pivot responsible, or an empty dict if the
    chain found nothing.
    """
    best, source = 0.0, {}
    for pivot in state["pivot_results"][1:]:
        if pivot.get("error") or not pivot.get("results"):
            continue
        scored = scorer.score_any(pivot)
        if scored.get("risk_level") == "UNKNOWN":
            continue
        score = scored.get("confidence_score", 0.0)
        if score > best:
            best = score
            source = {"indicator": pivot.get("indicator", ""), "score": score}

    if not source:
        return seed_score, {}

    # Saturating lift, so it approaches 1.0 without ever exceeding it.
    lift = best * CHAIN_EVIDENCE_WEIGHT
    return seed_score + (1 - seed_score) * lift, source


def apply_context(state: AgentState) -> AgentState:
    """
    Runs the context layer on pivot results.
    Calculates ML score, graph score, temporal score, and context adjusted score.
    """
    logger.info("Applying context layer...")
 
    if not state["pivot_results"]:
        state["insufficient_data"] = True
        return state

    pivot_result = state["pivot_results"][0]
    indicator_type = pivot_result.get("type", "")

    raw = scorer.score_any(pivot_result)
    ml_score = raw.get("confidence_score", 0.0)

    state["model_score"] = ml_score
    state["band_precision"] = raw.get("band_precision")

    # The scorers say UNKNOWN when they had nothing, but only confidence_score
    # propagates from here, so that verdict was being dropped. Either way the
    # score below measures our visibility, not the indicator.
    # The thresholds are calibrated per indicator type. Carried through so
    # core.risk can reapply them to the context-adjusted score instead of
    # falling back to one global pair and contradicting the scorer.
    state["risk_thresholds"] = raw.get("thresholds") or list(DEFAULT_THRESHOLDS)

    state["insufficient_data"] = (
        raw.get("risk_level") == "UNKNOWN"
        or bool(pivot_result.get("error"))
        or not pivot_result.get("results")
    )

    if indicator_type in NON_INFRASTRUCTURE_TYPES:
        graph_score = 0.0
        temporal_score = 0.0
    else:
        graph_scores = graph_scorer.score_all(state["pivot_results"])
        graph_score = graph_scores.get(state["seed"], 0.0)

        temporal_result = temporal_scorer.score(pivot_result)
        temporal_score = temporal_result.get("temporal_score", 0.0)

    # Early warning is scanned across every pivot, not just the seed. The signal
    # comes from related-sample recency, which only exists on hash pivots — so a
    # threat group seed that chains into fresh samples would otherwise never
    # raise it, despite that being exactly the case worth flagging.
    early_warning_indicator = ""
    for pivot in state["pivot_results"]:
        if pivot.get("type") in NON_INFRASTRUCTURE_TYPES:
            continue
        if temporal_scorer.score(pivot).get("early_warning"):
            early_warning_indicator = pivot.get("indicator", "")
            break

    if indicator_type in NON_INFRASTRUCTURE_TYPES:
        blended_score, chain = _apply_chain_evidence(ml_score, state)
        if chain:
            state["findings"].append(
                f"CHAIN EVIDENCE: {chain['indicator']} scored {chain['score']} on its own "
                f"pivot, raising the {indicator_type} score from {ml_score} to "
                f"{round(blended_score, 4)}."
            )
            # Chained evidence is data, whatever the seed pivot managed on its own.
            state["insufficient_data"] = False
    else:
        blended_score = graph_scorer.blend_scores(ml_score, graph_score)
        blended_score = temporal_scorer.blend_with_ml(blended_score, temporal_score)

    state["graph_score"] = round(graph_score, 4)
    state["temporal_score"] = round(temporal_score, 4)

    context = detect_infrastructure_type(pivot_result)
    modifier = context.get("confidence_modifier", 0.0)
    context_score = max(0.0, min(1.0, blended_score + modifier))
 
    state["ml_score"] = blended_score
    state["context_score"] = round(context_score, 4)
    state["infrastructure_type"] = context.get("infrastructure_type", "unknown")
 
    if early_warning_indicator:
        state["findings"].append(
            f"EARLY WARNING: Related malware samples for {early_warning_indicator} "
            "detected within the last 7 days — active campaign signal."
        )

    # Organisational relevance — silent unless an org profile is configured.
    relevance = assess_relevance(state["pivot_results"], org_profile)
    state["relevance_level"] = relevance["level"]
    state["findings"].extend(relevance["findings"])
 
    logger.info(f"ML: {blended_score} | Graph: {graph_score} | Temporal: {temporal_score} | Context: {context_score}")
 
    return state
 
 
def summarize(state: AgentState) -> AgentState:
    """
    Uses Claude to produce a final analyst-facing
    investigation summary and context note.
    Runs NER on the generated summary to surface
    any threat actor mentions for analyst follow-up.

    The threat level is resolved here, before the model is called, and handed to
    it. The model narrates the verdict and may dissent from it in writing; it
    does not set it.
    """
    logger.info("Agent generating final summary...")

    findings_str = safe_json(state["findings"])
    results_str = safe_json(state["pivot_results"])

    # Deterministic, and computed from the same fields run_agent will use, so the
    # summary cannot state a level the result contradicts.
    verdict = resolve_risk_level(state)

    system_prompt = (
        "You are an expert cyber threat intelligence analyst reviewing OSINT pivot results.\n\n"
        "Produce a structured investigation summary using exactly this format:\n\n"
        f"THREAT LEVEL: {verdict} — [one sentence verdict]\n\n"
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
        "DISSENT: [none, or one of HIGH / MEDIUM / LOW / UNKNOWN — one sentence on why]\n\n"
        f"The threat level was decided before you were called and it is {verdict}. Reproduce it "
        "verbatim and write the rest consistently with it. You are not scoring this indicator. "
        "The score is deterministic so that two runs over the same data reach the same verdict, "
        "which is a property your judgement cannot offer: on identical data and a byte-identical "
        "score this step once returned LOW on one run and MEDIUM on the next.\n\n"
        "The DISSENT line is where your judgement belongs. Write 'none' when the evidence "
        "supports the level. Name a different level only when the findings genuinely point "
        "elsewhere, and say why in one sentence. The case it exists for is a legitimate site "
        "serving attacker content: the score reads infrastructure, and there the infrastructure "
        "is real while the maliciousness is in what is served. Dissent flags the indicator for "
        "an analyst and does not change the verdict, so raising it costs nothing and a bare "
        "restatement of the level costs a real signal.\n\n"
        "Write for a SOC analyst making a fast decision. Never fabricate data not in the results. "
        "If a source errored, acknowledge the gap. No markdown headers with # symbols. No bold with **.\n\n"
        "UNKNOWN means no source returned data, and it is already decided above when that is the "
        "case. LOW means checked and nothing elevated, never checked and safe.\n\n"
        "Report a failed source by what it returned, never by what you think caused it. Name "
        "the source, say which indicators it failed on, and quote the error text. Do not "
        "diagnose the cause: an SSL error is not evidence of an expired certificate, a 4xx is "
        "not evidence of a changed API, a timeout is not evidence of an outage, and an empty "
        "result is not evidence the source has nothing. Under VISIBILITY GAPS a stated cause "
        "reads as a verified finding, and an analyst will go and fix the wrong system.\n\n"
        "If the results carry a hacktivist assessment, judge the crew on its alignment, its "
        "activity, and who it says it targets. Having no malware is normal for these actors, "
        "not reassuring — DDoS, defacement and hack-and-leak need none. Absent tooling is only "
        "worth remarking on for an actor that would be expected to have some."
    )
 
    user_message = (
        "Write an investigation summary for:\n\n"
        f"Seed Indicator: {state['seed']}\n"
        f"Indicators investigated: {state['visited']}\n"
        f"Pivots run: {state['pivot_count']}\n"
        f"ML Score: {state['ml_score']}\n"
        f"Context Score: {state['context_score']}\n"
        f"Resolved threat level: {verdict}\n"
        f"Infrastructure Type: {state['infrastructure_type']}\n"
        # Stated outright rather than left to be inferred from the scores, which
        # read as low rather than absent.
        f"Sources returned usable data: {'no' if state['insufficient_data'] else 'yes'}\n"
        # So an unlicensed source is not written up as a visibility gap.
        f"Access tier: {tier.describe()}\n\n"
        f"Key findings:\n{findings_str}\n\n"
        f"Full results:\n{results_str}"
    )
 
    # A failure here used to surface as an empty summary on an otherwise normal
    # looking result: no error, findings present, and a score-derived risk level
    # that read as a confident verdict. The investigation is still usable — the
    # scoring layers ran — but the gap has to be visible rather than blank.
    # Empty content counts as a failure, not as a short answer. It arrives with
    # no exception, so retrying only on raise left the one observed failure mode
    # unhandled.
    content = ""
    for attempt in range(SUMMARY_ATTEMPTS):
        try:
            response = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_message)
            ])
            content = response.content
            if isinstance(content, list):
                # Anthropic returns content blocks, and a thinking block comes
                # first when the model is configured for it. Every text block is
                # joined rather than only the first, so a split response is not
                # silently truncated to its opening section.
                content = "".join(
                    b.get("text", "") for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                )
            if isinstance(content, str) and content.strip():
                break
            logger.warning(
                f"Summary attempt {attempt + 1} returned empty content."
            )
        except Exception as e:
            logger.error(
                f"Summary attempt {attempt + 1} failed: {str(e)[:150]}"
            )
        if attempt < SUMMARY_ATTEMPTS - 1:
            time.sleep(SUMMARY_BACKOFF)

    summary = content.strip() if isinstance(content, str) else ""
    state["summary_failed"] = not summary

    if not summary:
        logger.error("Summary generation returned nothing.")
        # The level is unaffected, since it never came from here. What is missing
        # is the writing, and the reader must not mistake the level's presence
        # for an assessment having been made. core.render says so too.
        summary = (
            "SUMMARY UNAVAILABLE — the analyst summary could not be generated for "
            "this investigation, so no written assessment was produced.\n\n"
            f"The pivot chain itself completed: {state['pivot_count']} pivot(s) and "
            f"{len(state['findings'])} finding(s) were collected, and the threat "
            "level below is the scored one, unchanged. Read the findings directly, "
            "and re-run to obtain a written assessment."
        )

    state["summary"] = enforce_verdict(summary, verdict)

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
 
 
def run_agent(seed: str, deep: bool = False) -> dict:
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
        "model_score": 0.0,
        "band_precision": None,
        "graph_score": 0.0,
        "temporal_score": 0.0,
        "infrastructure_type": "unknown",
        "context_note": "",
        "summary": "",
        "pivot_count": 0,
        "deep": deep,
        "relevance_level": "none",
        # Assumed until apply_context scores something. A run that never gets
        # that far has collected nothing by definition.
        "insufficient_data": True,
        "risk_thresholds": list(DEFAULT_THRESHOLDS),
        "summary_failed": False,
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

    result = {
        "summary": final_state["summary"],
        "findings": final_state["findings"],
        "pivot_count": final_state["pivot_count"],
        "ml_score": final_state["ml_score"],
        "context_score": final_state["context_score"],
        "model_score": final_state.get("model_score", 0.0),
        "band_precision": final_state.get("band_precision"),
        "graph_score": final_state.get("graph_score", 0.0),
        "temporal_score": final_state.get("temporal_score", 0.0),
        "infrastructure_type": final_state["infrastructure_type"],
        "indicator_type": final_state["indicator_type"],
        "relevance_level": final_state["relevance_level"],
        "context_note": final_state["context_note"],
        "insufficient_data": final_state["insufficient_data"],
        "risk_thresholds": final_state["risk_thresholds"],
        "summary_failed": final_state["summary_failed"],
        "full_results": final_state["pivot_results"],
        "visited": final_state["visited"],
        "indicator": seed,
    }

    # Resolved once here so every consumer agrees, and so a saved investigation
    # carries its own verdict. main.py computed this for display only, which left
    # the exported JSON without the one field a reader looks for first.
    result["risk_level"] = resolve_risk_level(result)
    # Recorded so a saved investigation says which tier produced it, and whether
    # anyone without the licences could reproduce it.
    result["tier"] = tier.active()
    result["licensed_sources"] = tier.licensed_sources()
    result["reproducible_without_licence"] = tier.reproducible_without_licence(result)

    # Logged here rather than in the front ends, so the CLI, TUI and MCP server
    # all record exactly one row per investigation.
    disagreement.record(result)

    return result
 