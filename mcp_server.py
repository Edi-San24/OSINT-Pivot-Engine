
# mcp_server.py
# MCP server exposing the OSINT Pivot Engine to MCP clients (Claude Code,
# Claude Desktop). Wraps the existing LangGraph agent behind an investigate()
# tool, plus helpers for type detection, raw drill-down, and STIX export.
#
# Transport is stdio, which means the MCP protocol owns sys.stdout. Anything
# the engine prints to stdout corrupts the JSON-RPC stream and drops the
# connection, so every call into engine code is wrapped in
# redirect_stdout(sys.stderr). Logging already goes to stderr and is fine.
#
# Run directly for a smoke test:  python mcp_server.py --selftest

import sys
import json
import contextlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from mcp.server import MCPServer

# config is cheap to import (no engine, no STIX bundle), so it is safe here.
# The heavy imports stay behind _engine().
from config import VERSION

mcp = MCPServer(
    name="osint-pivot-engine",
    version=VERSION,
    instructions=(
        "Autonomous OSINT threat intelligence enrichment. Give investigate() a "
        "seed indicator (IP, domain, file hash, email, username, threat group, "
        "or malware family) and it runs a multi-source pivot chain across "
        "VirusTotal, Shodan, Censys, PassiveDNS, WHOIS, URLhaus, OTX, "
        "MalwareBazaar, MITRE ATT&CK, and dark web indexes, chains into related "
        "indicators automatically, scores them, and returns an analyst summary.\n\n"
        "investigate() takes 15-40 seconds and consumes rate-limited API quota. "
        "Call it once per indicator and reuse the result rather than repeating it. "
        "It already follows the pivot chain on its own — do not manually "
        "re-investigate indicators it reports in indicators_investigated."
    ),
)

# Completed investigations keyed by seed, so raw drill-down and STIX export do
# not have to re-run a slow, rate-limited pivot chain.
_INVESTIGATIONS: dict[str, dict] = {}

# Engine modules are imported on first use, not at module import — see _engine().
_MODULES: dict = {}

MAX_RAW_CHARS = 20000


def _engine() -> dict:
    """
    Imports the engine on first tool call rather than at server startup.

    Constructing PivotExecutor loads the MITRE ATT&CK STIX bundle from disk and
    builds the NER lookup table, which takes several seconds. Doing that at
    import time would stall the MCP initialize handshake and make the server
    look hung to the client.
    """
    if not _MODULES:
        with contextlib.redirect_stdout(sys.stderr):
            import config
            from core.agent import run_agent
            from core.detector import detect_type
            from core.risk import resolve_risk_level
            from core.stix_exporter import STIXExporter

            _MODULES.update(
                config=config,
                run_agent=run_agent,
                detect_type=detect_type,
                resolve_risk_level=resolve_risk_level,
                STIXExporter=STIXExporter,
            )
    return _MODULES


def _source_status(pivot_results: list) -> dict:
    """
    Condenses per-source outcomes into one flat map so the caller can see
    coverage and visibility gaps without being handed the raw payloads.

    A source that succeeded on any pivot in the chain counts as "ok".
    """
    status: dict[str, str] = {}
    for pivot in pivot_results:
        for name, payload in pivot.get("results", {}).items():
            if name.startswith("_") or not isinstance(payload, dict):
                continue
            if "error" in payload:
                state = "error"
            elif payload.get("skipped"):
                state = "skipped"
            elif payload.get("found") is False:
                state = "no_match"
            else:
                state = "ok"
            if status.get(name) != "ok":
                status[name] = state
    return status


@mcp.tool()
def detect_indicator_type(indicator: str) -> dict:
    """
    Classify an indicator without querying any external source.

    Returns the detected type — ipv4, domain, md5, sha1, sha256, email,
    username, threat_group, or software — plus a confidence rating. Instant
    and free. Use it to confirm an ambiguous input will be routed the way you
    expect before spending an investigate() call on it. Note that "username"
    is the catch-all fallback and matches most short bare strings.
    """
    result = _engine()["detect_type"](indicator)
    if not result:
        return {
            "indicator": indicator,
            "type": "unknown",
            "confidence": "none",
            "note": "No pattern matched. investigate() will reject this input.",
        }
    return result


@mcp.tool()
def investigate(seed: str, depth: int = 3, deep: bool = False) -> dict:
    """
    Run a full OSINT investigation on one seed indicator.

    Queries every connector relevant to the indicator's type in parallel,
    automatically pivots into indicators it discovers (IPs from passive DNS,
    subdomains from certificate transparency, related samples from malware
    family clustering, threat actors named in the results), scores the result
    with an ML model plus graph, temporal, and infrastructure-context layers,
    and returns an analyst-facing summary.

    Takes 15-40 seconds and consumes rate-limited API quota, so call it once
    per indicator. Raw connector payloads are omitted from the response because
    they run to tens of thousands of tokens; use get_raw_pivot_data() when you
    need to inspect a specific source.

    Args:
        seed: The indicator to investigate. IP, domain, MD5/SHA1/SHA256 hash,
            email, username, threat group name, or malware family name.
        depth: Maximum indicators to pivot through, 1-10. Default 3. Each extra
            level of depth adds roughly 10-15 seconds and more API quota.
        deep: Enable SpiderFoot enrichment for email and username seeds. Has no
            effect on other indicator types and makes the call substantially
            slower.
    """
    engine = _engine()
    config = engine["config"]

    original_depth = config.MAX_PIVOT_DEPTH
    try:
        config.MAX_PIVOT_DEPTH = max(1, min(int(depth), 10))
        with contextlib.redirect_stdout(sys.stderr):
            result = engine["run_agent"](seed, deep=deep)
    except Exception as e:
        return {"seed": seed, "error": f"{type(e).__name__}: {e}"}
    finally:
        config.MAX_PIVOT_DEPTH = original_depth

    _INVESTIGATIONS[seed] = result

    return {
        "seed": seed,
        "indicator_type": result.get("indicator_type", "unknown"),
        "risk_level": engine["resolve_risk_level"](result),
        "ml_score": result.get("ml_score", 0.0),
        "context_score": result.get("context_score", 0.0),
        "infrastructure_type": result.get("infrastructure_type", "unknown"),
        "context_note": result.get("context_note", ""),
        "pivots_run": result.get("pivot_count", 0),
        "indicators_investigated": result.get("visited", []),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "source_status": _source_status(result.get("full_results", [])),
        "note": (
            "Raw connector payloads omitted. "
            "Call get_raw_pivot_data(seed, source) to inspect one source."
        ),
    }


@mcp.tool()
def get_raw_pivot_data(seed: str, source: str = "", indicator: str = "") -> dict:
    """
    Return raw connector output from an investigation already run in this session.

    Only for drilling into a detail the summary and findings did not cover —
    the payloads are large. Always narrow with the source argument. Does not
    make any network calls; if the seed has not been investigated yet this
    returns an error rather than running the chain.

    Args:
        seed: The seed passed to a previous investigate() call.
        source: Restrict to one connector — virustotal, shodan, censys, whois,
            passivedns, urlhaus, otx, mitre, malwarebazaar,
            malwarebazaar_related, ahmia, or spiderfoot. Strongly recommended.
        indicator: Restrict to one pivoted indicator instead of the whole chain.
    """
    result = _INVESTIGATIONS.get(seed)
    if result is None:
        return {
            "error": f"No investigation cached for '{seed}'.",
            "available": sorted(_INVESTIGATIONS.keys()),
            "hint": "Call investigate(seed) first.",
        }

    pivots = result.get("full_results", [])
    if indicator:
        pivots = [p for p in pivots if p.get("indicator") == indicator]
        if not pivots:
            return {
                "error": f"'{indicator}' was not pivoted in this investigation.",
                "available": result.get("visited", []),
            }

    if source:
        extracted = [
            {
                "indicator": p.get("indicator"),
                "type": p.get("type"),
                source: p.get("results", {}).get(source),
            }
            for p in pivots
            if source in p.get("results", {})
        ]
        if not extracted:
            return {
                "error": f"Source '{source}' did not run for this investigation.",
                "sources_present": sorted(
                    {k for p in pivots for k in p.get("results", {}) if not k.startswith("_")}
                ),
            }
        payload = extracted
    else:
        payload = pivots

    serialized = json.dumps(payload, indent=2, default=str)
    if len(serialized) > MAX_RAW_CHARS:
        return {
            "truncated": True,
            "original_chars": len(serialized),
            "data": serialized[:MAX_RAW_CHARS],
            "hint": "Narrow the request with the source or indicator argument.",
        }
    return {"truncated": False, "data": payload}


@mcp.tool()
def export_stix(seed: str, output_path: str = "") -> dict:
    """
    Export a completed investigation as a STIX 2.1 bundle for import into MISP,
    OpenCTI, Splunk, or any TAXII-compatible platform.

    Writes a file to disk. The investigation must already have been run by
    investigate() in this session.

    Args:
        seed: The seed passed to a previous investigate() call.
        output_path: Destination path. Relative paths resolve against the
            project root. Defaults to <seed>_stix.json.
    """
    engine = _engine()
    result = _INVESTIGATIONS.get(seed)
    if result is None:
        return {
            "error": f"No investigation cached for '{seed}'.",
            "available": sorted(_INVESTIGATIONS.keys()),
            "hint": "Call investigate(seed) first.",
        }

    safe_name = "".join(c if c.isalnum() or c in "-._" else "_" for c in seed)
    target = Path(output_path) if output_path else Path(f"{safe_name}_stix.json")
    if not target.is_absolute():
        target = PROJECT_ROOT / target

    with contextlib.redirect_stdout(sys.stderr):
        written = engine["STIXExporter"]().export(result, str(target))

    if not written:
        return {"error": "STIX export failed — exporter returned no path."}
    return {"exported": True, "path": str(written)}


async def _selftest() -> None:
    """Exercises the tool surface without starting the stdio transport."""
    print("Registered tools:")
    for tool in await mcp.list_tools():
        first_line = (tool.description or "").strip().split("\n")[0]
        print(f"  - {tool.name}: {first_line}")

    print("\ndetect_indicator_type checks:")
    for probe in ["185.220.101.45", "evil-domain.com", "Lazarus Group",
                  "db349b97c37d22f5ea1d1841e3c89eb4", "WannaCry"]:
        print(f"  {probe:38} -> {detect_indicator_type(probe)['type']}")

    print("\nUncached drill-down is handled cleanly:")
    print(f"  {get_raw_pivot_data('never-investigated.com')['error']}")
    print("\nSelftest OK — no network calls made.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        import asyncio
        asyncio.run(_selftest())
    else:
        mcp.run(transport="stdio")
