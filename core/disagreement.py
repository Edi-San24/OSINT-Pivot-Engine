# core/disagreement.py
# Logs the agent verdict against the score on every run, as an eval trail.

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

from config import DATA_DIR
from core.risk import (
    extract_dissent,
    resolve_risk_level,
    score_level as level_from_score,
    verdict_source,
)

logger = logging.getLogger(__name__)

LOG_PATH = os.path.join(DATA_DIR, "verdicts.jsonl")

# The LLM no longer writes the verdict, so what this log measures changed with
# it. It used to record which of two deciders won. It now records where the
# written assessment reads the evidence differently from the score that decided,
# which is where the bugs turn up: Moonstone Sleet scored LOW on ATT&CK coverage
# while the agent read HIGH off four unanimous VirusTotal verdicts, and the agent
# was right. Those rows are still the cheapest place to find a scoring blind
# spot, and they no longer come at the cost of a reproducible verdict.
#
# Rows written before that change carry decided_by "agent", meaning the agent's
# level was the one applied. They are kept as history and counted as splits.


# Where a ground-truth label came from, because that decides what it is worth.
#
# A label copied from a feed the engine already queries measures agreement with
# that feed, not correctness. The labels that carry information are the ones the
# feeds did not supply: briansclub.cm was a carding marketplace with zero
# VirusTotal detections, thekinsmenservers.com a legitimate host the model
# flagged, eversxcellence.co.za compromised rather than attacker-owned. Those
# took analyst judgement, which is exactly why they are worth recording.
TRUTH_SOURCES = {"analyst", "feed", "published"}


def _row(result: dict, truth: str | None = None, truth_source: str = "analyst") -> dict:
    """One record per investigation, enough to re-derive the decision."""
    context_score = result.get("context_score", 0.0)
    score_level = level_from_score(result)
    resolved = resolve_risk_level(result)
    decided_by = verdict_source(result)

    # The level the written assessment read, which is no longer the level that
    # was applied. On a dissent it named a different one; on a concur it agreed
    # with the score. "scorer" means it stated no read at all, so there is
    # nothing to compare.
    if decided_by == "dissent":
        agent_level = extract_dissent(result.get("summary", ""))
    elif decided_by == "concur":
        agent_level = score_level
    else:
        agent_level = None

    # Comparable only when both sides actually made a claim. A no-data run has a
    # 0.0 that means nothing, and an agent that stated no read said nothing —
    # scoring either as a disagreement would inflate the rate with noise.
    comparable = agent_level is not None and decided_by != "no_data"

    return {
        "when": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": result.get("indicator", ""),
        "indicator_type": result.get("indicator_type", "unknown"),
        "pivot_count": result.get("pivot_count", 0),
        "finding_count": len(result.get("findings") or []),
        "ml_score": result.get("ml_score", 0.0),
        "context_score": context_score,
        "score_level": score_level,
        "agent_level": agent_level,
        "resolved_level": resolved,
        "decided_by": decided_by,
        "insufficient_data": bool(result.get("insufficient_data")),
        "agreed": (agent_level == score_level) if comparable else None,
        # What the answer should have been, when known. Absent on most rows and
        # that is expected: accuracy is measured over the labelled subset, while
        # agreement is measured over everything.
        "truth": truth,
        "truth_source": truth_source if truth else None,
        "correct": _is_correct(resolved, truth) if truth else None,
    }


def _is_correct(resolved: str, truth: str | None) -> bool | None:
    """
    Whether the resolved level matched the label.

    HIGH and MEDIUM both count as flagged, because an analyst looks at either.
    Reading MEDIUM as a miss would punish the engine for being uncertain when it
    is uncertain, which is the behaviour the band measurements asked for.
    """
    if truth == "malicious":
        return resolved in {"HIGH", "MEDIUM"}
    if truth == "benign":
        return resolved in {"LOW", "UNKNOWN"}
    if truth == "unknown":
        return resolved == "UNKNOWN"
    return None


def record(result: dict, path: str = LOG_PATH, truth: str | None = None,
           truth_source: str = "analyst") -> dict | None:
    """
    Appends one row and returns it, or None if logging failed.
    Never raises: an audit trail must not be able to break an investigation.

    truth is optional and one of "malicious", "benign" or "unknown". Supplying it
    turns the row into an accuracy datapoint rather than only an agreement one.
    """
    try:
        row = _row(result, truth=truth, truth_source=truth_source)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(row) + "\n")

        if row["agreed"] is False:
            logger.info(
                f"Verdict split on {row['seed'][:40]}: score said "
                f"{row['score_level']}, agent said {row['agent_level']}, "
                f"{row['decided_by']} decided."
            )
        return row
    except Exception as e:
        logger.error(f"Could not write verdict log: {str(e)[:100]}")
        return None


def _wilson(hits: int, total: int, z: float = 1.96) -> list:
    """
    95% confidence interval on a rate, so a small sample cannot be read as a
    measurement.

    Added because a 7-of-10 run was reported as 70% against a historical 32%,
    and the intervals overlapped at [40, 89] and [20, 47]. The two rates were
    indistinguishable, and the point estimate alone concealed that.
    """
    if total == 0:
        return [0.0, 0.0]
    p = hits / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / d
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def summarize(path: str = LOG_PATH) -> dict:
    """
    Agreement and, over the labelled subset, accuracy.

    The two are different questions and only one of them matters on its own.
    Agreement says the score and the agent reached the same level; both can
    concur and both be wrong. Accuracy needs a label, which is why record()
    takes one.
    """
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        return {"total": 0, "note": f"No verdict log at {path} yet."}
    except Exception as e:
        return {"total": 0, "note": f"Could not read {path}: {str(e)[:80]}"}

    # Rows where either side made no claim cannot agree or disagree, so they are
    # counted separately rather than diluting the rate.
    comparable = [r for r in rows if r.get("agreed") is not None]
    splits = [r for r in comparable if r["agreed"] is False]

    by_type = defaultdict(lambda: {"compared": 0, "split": 0})
    for r in comparable:
        entry = by_type[r.get("indicator_type", "unknown")]
        entry["compared"] += 1
        entry["split"] += 1 if r["agreed"] is False else 0

    labelled = [r for r in rows if r.get("correct") is not None]
    correct = [r for r in labelled if r["correct"]]
    by_truth = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in labelled:
        entry = by_truth[r.get("truth", "unknown")]
        entry["n"] += 1
        entry["correct"] += 1 if r["correct"] else 0

    return {
        "total": len(rows),
        "comparable": len(comparable),
        "not_comparable": len(rows) - len(comparable),
        "disagreements": len(splits),
        "disagreement_rate": round(len(splits) / len(comparable), 4) if comparable else 0.0,
        "by_indicator_type": {
            k: {**v, "rate": round(v["split"] / v["compared"], 4)}
            for k, v in sorted(by_type.items())
        },
        "disagreement_ci": _wilson(len(splits), len(comparable)),
        # Accuracy over rows carrying a ground-truth label. Absent until labels
        # are supplied, and reported with an interval because the labelled
        # subset is small and a bare rate invites over-reading.
        "labelled": len(labelled),
        "accuracy": round(len(correct) / len(labelled), 4) if labelled else None,
        "accuracy_ci": _wilson(len(correct), len(labelled)) if labelled else None,
        "accuracy_by_truth": {
            k: {**v, "rate": round(v["correct"] / v["n"], 4)}
            for k, v in sorted(by_truth.items())
        },
        # The interesting ones: the written assessment read the evidence
        # differently from the score that decided. "agent" is the historical
        # spelling, from when that read was applied instead of recorded.
        "agent_dissents": [
            {"seed": r["seed"], "type": r["indicator_type"],
             "score": r["context_score"], "score_level": r["score_level"],
             "agent_level": r["agent_level"]}
            for r in splits if r.get("decided_by") in {"dissent", "agent"}
        ][-10:],
    }


if __name__ == "__main__":
    print(json.dumps(summarize(), indent=2))
