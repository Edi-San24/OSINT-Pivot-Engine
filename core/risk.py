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


# Used when a result carries no thresholds of its own: anything saved before the
# scorer started reporting them, and the ML path's own default.
DEFAULT_THRESHOLDS = (0.7, 0.4)

# What each band was measured to mean for the domain model, out-of-fold across
# eight resampled 5-fold splits of the published training set: HIGH 88.9% +/-
# 0.8, MEDIUM 42.9% +/- 5.9, LOW 20.1% +/- 1.0 actually malicious.
#
# LOW is the one to read carefully. One in five indicators scored LOW is
# malicious, and no threshold repairs that — even below 0.10 the rate is still
# 16%. The model can say an indicator looks like attacker infrastructure; it
# cannot clear one. LOW means "nothing elevated in the infrastructure", not
# "safe", and the label should never be read as an all-clear.
#
# Post-hoc calibration was tried and rejected. Platt scaling made expected
# calibration error worse (0.057 to 0.079) and isotonic bought 0.007 at the cost
# of AUC; at 383 rows both are fitting noise. Reporting the measured rate is
# honest where a transformed probability would not be.
#
# These rates are conditional on a near 50/50 training distribution. The base
# rate of domains an analyst actually investigates differs, so read them as the
# model's discrimination, not as a population probability.
DOMAIN_BAND_PRECISION = {"HIGH": 0.89, "MEDIUM": 0.43, "LOW": 0.20}


def score_to_risk(score: float, thresholds: tuple = DEFAULT_THRESHOLDS) -> str:
    """Maps a score to HIGH / MEDIUM / LOW against the given thresholds."""
    high, medium = thresholds
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    return "LOW"


def thresholds_for(result: dict) -> tuple:
    """
    The thresholds the scorer used for this indicator type.

    ConfidenceScorer calibrates these per type — (0.5, 0.25) for a community
    scored group, (0.65, 0.4) for one in ATT&CK, (0.5, 0.3) for an identity —
    and they used to be discarded here in favour of one global pair.
    """
    values = result.get("risk_thresholds")
    if isinstance(values, (list, tuple)) and len(values) == 2:
        return (values[0], values[1])
    return DEFAULT_THRESHOLDS


def score_level(result: dict) -> str:
    """The level implied by the context score alone, on the right thresholds."""
    return score_to_risk(result.get("context_score", 0.0), thresholds_for(result))


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

    risk = score_level(result)
    if result.get("indicator_type", "") not in SCORER_AUTHORITATIVE_TYPES:
        agent_level = extract_threat_level(result.get("summary", ""))
        if agent_level:
            risk = agent_level
    return risk


def verdict_source(result: dict) -> str:
    """
    Which input decided the level: "no_data", "agent", "scorer" or "concur".

    "agent" means the agent's verdict actually overrode the score. When the two
    reach the same level nothing was overridden, and labelling that an agent
    verdict overclaimed — 13 of 34 such rows in the verdict log were agreements
    presented as overrides.
    """
    if not has_evidence(result):
        return "no_data"
    if result.get("indicator_type", "") in SCORER_AUTHORITATIVE_TYPES:
        return "scorer"

    agent_level = extract_threat_level(result.get("summary", ""))
    if not agent_level:
        return "scorer"
    return "agent" if agent_level != score_level(result) else "concur"
