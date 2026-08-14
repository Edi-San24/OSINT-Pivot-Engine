# core/risk.py
# Shared risk-level derivation.
# Imported by both the CLI (main.py) and the MCP server (mcp_server.py) so the
# two front ends can never disagree about the same indicator.


# Types where the scorer's thresholds are authoritative and the agent's
# narrative verdict must not override them.
NON_INFRASTRUCTURE_TYPES = {
    "threat_group", "software", "email", "username", "filename"
}


def score_to_risk(score: float) -> str:
    """Maps a context score to HIGH / MEDIUM / LOW."""
    if score >= 0.7:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"


def extract_threat_level(summary: str) -> str | None:
    """
    Pulls the THREAT LEVEL verdict out of the agent's structured summary.
    Returns HIGH, MEDIUM, LOW, or None if the line is absent.
    """
    if not isinstance(summary, str):
        return None
    for line in summary.split("\n"):
        stripped = line.strip()
        if not stripped.startswith("THREAT LEVEL:"):
            continue
        # Read the token straight after the label, not the whole line — the
        # trailing verdict prose can contain other level words.
        verdict = stripped[len("THREAT LEVEL:"):].strip().upper()
        for level in ["HIGH", "MEDIUM", "LOW"]:
            if verdict.startswith(level):
                return level
        return None  # UNKNOWN or unparseable — fall back to the score
    return None


def resolve_risk_level(result: dict) -> str:
    """
    Final risk level for a completed investigation. Starts from the context
    score; the agent's verdict overrides it for infrastructure pivots only.
    """
    risk = score_to_risk(result.get("context_score", 0.0))
    if result.get("indicator_type", "") not in NON_INFRASTRUCTURE_TYPES:
        agent_level = extract_threat_level(result.get("summary", ""))
        if agent_level:
            risk = agent_level
    return risk
