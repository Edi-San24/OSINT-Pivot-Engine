# core/risk.py
# Shared risk-level derivation.
# Imported by both the CLI (main.py) and the MCP server (mcp_server.py) so the
# two front ends can never disagree about the same indicator.


# Types where the scorer's thresholds are authoritative and the agent's
# narrative verdict must not override them.
NON_INFRASTRUCTURE_TYPES = {
    "threat_group", "software", "email", "username", "filename"
}

# Types whose own scorer is authoritative, so the agent must not overrule it.
# Deliberately narrower than the set above.
#
# score_threat_group and score_software are calibrated against measured ATT&CK
# and MalwareBazaar distributions, so they mean something. score_identity is
# min(finding_count / 50, 1.0) — a measure of how much SpiderFoot returned, not
# of how dangerous the identity is. One finding scores 0.02 whether the handle
# belongs to nobody or to a ransomware group's spokesperson, which is exactly
# where the agent's judgement is worth more than the number.
SCORER_AUTHORITATIVE_TYPES = {"threat_group", "software"}


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
    Returns HIGH, MEDIUM, LOW, UNKNOWN, or None if the line is absent.

    UNKNOWN was discarded here as unparseable, which fell back to the score. A
    0.0 then rendered LOW, so "cannot tell" and "clean" looked identical.
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
        for level in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if verdict.startswith(level):
                return level
        return None  # Unparseable — fall back to the score
    return None


def has_evidence(result: dict) -> bool:
    """
    Whether the investigation collected anything to reason about.
    A 0.0 from a run that reached no source measures our visibility, not the
    indicator's safety, and must not show as LOW — analysts read LOW as clean.
    """
    if result.get("error"):
        return False
    if result.get("insufficient_data"):
        return False
    if result.get("pivot_count", 0) == 0:
        return False
    return True


def resolve_risk_level(result: dict) -> str:
    """
    Final risk level for a completed investigation. Starts from the context
    score; the agent's verdict overrides it unless that indicator's own scorer
    is authoritative. UNKNOWN comes ahead of both — neither means anything
    without inputs.
    """
    if not has_evidence(result):
        return "UNKNOWN"

    risk = score_to_risk(result.get("context_score", 0.0))
    if result.get("indicator_type", "") not in SCORER_AUTHORITATIVE_TYPES:
        agent_level = extract_threat_level(result.get("summary", ""))
        if agent_level:
            risk = agent_level
    return risk


def verdict_source(result: dict) -> str:
    """
    Which input decided the level: "no_data", "agent", or "scorer".
    Shared so the metrics table and the verdict log cannot drift apart.
    """
    if not has_evidence(result):
        return "no_data"
    if result.get("indicator_type", "") in SCORER_AUTHORITATIVE_TYPES:
        return "scorer"
    return "agent" if extract_threat_level(result.get("summary", "")) else "scorer"
