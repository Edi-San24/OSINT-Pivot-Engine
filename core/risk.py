# core/risk.py
# Shared risk-level derivation.
# Imported by both the CLI (main.py) and the MCP server (mcp_server.py) so the
# two front ends can never disagree about the same indicator.

import ipaddress
import time


# Types the graph and temporal layers do not apply to, so core.agent blends them
# by chained evidence instead.
NON_INFRASTRUCTURE_TYPES = {
    "threat_group", "software", "email", "username", "filename"
}

# The scorer is authoritative for every indicator type. resolve_risk_level reads
# no summary, so the verdict is reproducible; the agent's own read is recorded as
# dissent and displayed, never applied.
#
# Identities are the weak case. score_identity is min(finding_count / 50, 1.0),
# which measures how much SpiderFoot returned rather than how dangerous the
# identity is, so a thin result resolves LOW on a number that does not mean LOW.
# The scorer answers UNKNOWN at zero findings and there is no principled cut
# point above that.


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

# Retired with the IP model it described. Addresses are scored from evidence by
# ConfidenceScorer.score_ip, not by a model, so there is no band to measure.
#
# The measurement is kept in the commit history rather than here: HIGH 0.94,
# MEDIUM 0.71, LOW 0.29 against a 74.3% base rate, which is 1.26x lift on HIGH
# where the domain model reaches 1.77x. Those numbers were honest and the model
# behind them was not — its benign class was built by resolving domains, so it
# had learned to tell a mature multi-service host from a minimal one.

BASE_RATES = {"domain": 0.504}


# How recently a name must have resolved to an address to count as a current
# tenant of it. Passive DNS keeps names for years, so without a window the
# tenancy check answers "who was ever here" rather than "who is here now".
# Shared by the publisher and by PivotExecutor.screen.
TENANCY_WINDOW_DAYS = 45


def last_seen_within(record: dict, days: int = TENANCY_WINDOW_DAYS) -> bool:
    """
    Whether a passive DNS record was observed inside the window.

    Sources disagree on units, so an implausibly large stamp is rescaled from
    milliseconds. A record carrying no timestamp counts as current, since
    absence of a date is not evidence the neighbour has gone.
    """
    raw = record.get("last_seen") or record.get("time_last")
    if not raw:
        return True
    try:
        stamp = float(raw)
    except (TypeError, ValueError):
        return True
    if stamp > 1e11:          # milliseconds
        stamp /= 1000.0
    return (time.time() - stamp) <= days * 86400


# CDN edge ranges. A seed resolving only into one of these exposes no origin, so
# passive DNS, Shodan and the co-tenant chain have nothing to work with. An
# address in these ranges is also shared with most of the web, so it is never an
# indicator.
CDN_RANGES = tuple(ipaddress.ip_network(n) for n in (
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Akamai
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
))


def is_cdn_edge(value: str) -> bool:
    """Whether an address belongs to a shared CDN edge range."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(address in network for network in CDN_RANGES)


def is_routable_ip(value: str) -> bool:
    """
    Whether an address can actually host anything.

    False for reserved, private, multicast, loopback and documentation space,
    and for anything that is not an address at all. Applied wherever an address
    is about to cost work: selecting a pivot, and selecting an indicator to
    publish.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    # is_global alone admits multicast, since Python defines it as the
    # complement of private and 224.0.0.0/4 is in neither list.
    return address.is_global and not address.is_multicast and not address.is_reserved


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


LEVELS = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _line_value(summary: str, label: str) -> str | None:
    """
    The text following a labelled line in the agent's structured summary, or
    None when the line is absent. An empty string means the label was there and
    said nothing, which is not the same as never having been written.
    """
    if not isinstance(summary, str):
        return None
    for line in summary.split("\n"):
        stripped = line.strip()
        if stripped.startswith(label):
            return stripped[len(label):].strip()
    return None


def _level_on_line(summary: str, label: str) -> str | None:
    """
    Reads a risk level off a labelled line.
    Returns None when the line is absent or names no level.
    """
    stated = _line_value(summary, label)
    if stated is None:
        return None
    # Read the token straight after the label, not the whole line — the trailing
    # prose can contain other level words.
    stated = stated.upper()
    for level in LEVELS:
        if stated.startswith(level):
            return level
    return None


def extract_threat_level(summary: str) -> str | None:
    """
    Pulls the THREAT LEVEL line out of the agent's structured summary.
    Returns HIGH, MEDIUM, LOW, UNKNOWN, or None if the line is absent.

    core.agent now writes that line from the resolved level rather than letting
    the model choose it, so on a current investigation this reads back the
    engine's own verdict. It still parses saved investigations from when the
    model wrote it, and core.render uses it to show what a stored run said.
    """
    return _level_on_line(summary, "THREAT LEVEL:")


def extract_dissent(summary: str) -> str | None:
    """
    The level the agent's narrative would have given, when it differs from the
    verdict it was handed. None when the agent stated no dissent.

    This is the agent's whole remaining influence on the level, which is to say
    none: it is displayed and logged so an analyst can look, and a compromised
    site the feeds have not caught is the case it exists for. It is also anchored
    by construction, since the prompt is told the verdict before it answers, so
    read a dissent as a flag and never as an independent second opinion.
    """
    return _level_on_line(summary, "DISSENT:")


def enforce_verdict(summary: str, verdict: str) -> str:
    """
    Makes the THREAT LEVEL line carry the resolved verdict, inserting the line
    when the model left it out. Keeps whatever one-sentence verdict it wrote.

    The level is decided before the summary is, so this repairs prose rather
    than deciding anything. It exists because that line used to be the verdict:
    raspberryhillsshop.com emitted no THREAT LEVEL line at all on one run, and a
    reader cannot tell a level the engine stands behind from one the model
    improvised.
    """
    lines = summary.split("\n")
    for i, line in enumerate(lines):
        if not line.strip().startswith("THREAT LEVEL:"):
            continue
        stated = line.strip()[len("THREAT LEVEL:"):].strip()
        for level in LEVELS:
            if stated.upper().startswith(level):
                stated = stated[len(level):].lstrip(" -—:")
                break
        lines[i] = f"THREAT LEVEL: {verdict} — {stated}" if stated else f"THREAT LEVEL: {verdict}"
        return "\n".join(lines)
    return f"THREAT LEVEL: {verdict}\n\n{summary}"


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
    Final risk level for a completed investigation, and deterministic: the score
    decides, on that indicator type's own thresholds. UNKNOWN comes first,
    because a level means nothing without inputs.

    The agent used to overrule this and the result was not reproducible. On a
    byte-identical 0.157 dizaynholding.com drew LOW on one run and MEDIUM on the
    next; raspberryhillsshop.com drew HIGH on one run and emitted no THREAT LEVEL
    line at all on the next, which dropped a ThreatFox confidence-100 ClearFake
    domain to LOW. Nothing in the engine measured that. Reading no summary is
    what makes two runs over the same data agree.
    """
    if not has_evidence(result):
        return "UNKNOWN"
    return score_level(result)


def verdict_source(result: dict) -> str:
    """
    How the level was reached: "no_data", "scorer", "concur" or "dissent".

    The scorer decides in every case now, so this reports whether anything
    argued with it: "concur" when the agent read the same level, "dissent" when
    it read a different one and was not allowed to act on it, "scorer" when it
    stated no read. The old "agent" value meant the agent had overridden the
    score and can no longer occur.
    """
    if not has_evidence(result):
        return "no_data"

    summary = result.get("summary", "")
    # Absent line and a line reading "none" are different answers. A current run
    # always writes one, so an absent line means a saved investigation from
    # before this format or a run whose summary failed, and neither stated a
    # read to agree or disagree with.
    if _line_value(summary, "DISSENT:") is None:
        return "scorer"

    dissent = extract_dissent(summary)
    if dissent and dissent != score_level(result):
        return "dissent"
    return "concur"
