# core/disagreement.py
# Logs the agent verdict against the score on every run, as an eval trail.

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

from config import DATA_DIR
from core.risk import (
    extract_threat_level,
    resolve_risk_level,
    score_to_risk,
    verdict_source,
)

logger = logging.getLogger(__name__)

LOG_PATH = os.path.join(DATA_DIR, "verdicts.jsonl")

# The ML models are tracked in MLflow; the LLM that writes the actual verdict is
# measured by nothing. Where it disagrees with the score is where the bugs turn
# up — Moonstone Sleet scored LOW on ATT&CK coverage while the agent read HIGH
# off four unanimous VirusTotal verdicts, and the agent was right. Logging the
# split builds a self-labelling set to check calibration against.


def _row(result: dict) -> dict:
    """One record per investigation, enough to re-derive the decision."""
    context_score = result.get("context_score", 0.0)
    agent_level = extract_threat_level(result.get("summary", ""))
    score_level = score_to_risk(context_score)
    resolved = resolve_risk_level(result)
    decided_by = verdict_source(result)

    # Comparable only when both sides actually made a claim. A no-data run has a
    # 0.0 that means nothing, and an agent that stated no verdict said nothing —
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
    }


def record(result: dict, path: str = LOG_PATH) -> dict | None:
    """
    Appends one row and returns it, or None if logging failed.
    Never raises: an audit trail must not be able to break an investigation.
    """
    try:
        row = _row(result)
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


def summarize(path: str = LOG_PATH) -> dict:
    """Disagreement rates overall and per indicator type."""
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
        # The interesting ones: the scorer overruled a stated agent verdict.
        "scorer_overrode_agent": [
            {"seed": r["seed"], "type": r["indicator_type"],
             "score": r["context_score"], "score_level": r["score_level"],
             "agent_level": r["agent_level"]}
            for r in splits if r.get("decided_by") == "scorer"
        ][-10:],
    }


if __name__ == "__main__":
    print(json.dumps(summarize(), indent=2))
