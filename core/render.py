# core/render.py
# Shared result rendering for the CLI and the TUI.
#
# Both front ends display the same investigation, so the table and summary
# formatting live here rather than in either one. Imports stay light on
# purpose: nothing here pulls in the agent, so a front end can render a cached
# result without paying for the engine to load.

from rich import box
from rich.table import Table
from rich.text import Text

from core.risk import (
    extract_dissent,
    extract_threat_level,
    resolve_risk_level,
    score_level,
    score_to_risk,
    verdict_source,
)

# Section labels the agent writes, and the colour each gets on screen.
SUMMARY_SECTIONS = {
    "THREAT LEVEL:": "bold white",
    "ASSESSMENT:": "bold cyan",
    "KEY INDICATORS:": "bold cyan",
    "VISIBILITY GAPS:": "bold yellow",
    "RECOMMENDED ACTIONS:": "bold cyan",
    "DISSENT:": "bold magenta",
}

# Org relevance findings, ordered by urgency. An indicator that turns out to
# be your own host outranks everything else on screen.
RELEVANCE_STYLES = [
    ("OWN ASSET", "bold red", "red"),
    ("BRAND ABUSE", "bold yellow", "yellow"),
    ("ORG RELEVANCE", "bold cyan", "cyan"),
    ("COVERAGE GAP", "dim", "dim"),
]


def get_risk_color(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "bold red"
    if risk_level == "MEDIUM":
        return "bold yellow"
    # Not green — green means a clean result, and the point of UNKNOWN is that
    # we do not have one.
    if risk_level == "UNKNOWN":
        return "bold cyan"
    return "bold green"


def format_summary(summary) -> Text:
    """Colours the section labels in the agent's structured summary."""
    if not isinstance(summary, str):
        summary = ""

    text = Text()
    for line in summary.strip().split("\n"):
        stripped = line.strip()
        for label, color in SUMMARY_SECTIONS.items():
            if stripped.startswith(label):
                text.append(label + " ", style=color)
                text.append(stripped[len(label):].strip() + "\n")
                break
        else:
            text.append(line + "\n")
    return text


def build_metrics_table(result: dict, verbose: bool = False) -> Table:
    """Builds the metrics table shown above the investigation summary."""
    risk_level = resolve_risk_level(result)
    risk_color = get_risk_color(risk_level)

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Field", style="dim")
    table.add_column("Value")

    table.add_row("Pivots run", str(result.get("pivot_count", 0)))
    table.add_row("Findings", str(len(result.get("findings", []))))

    # One score: the context-adjusted one, since that is what feeds the risk
    # level. When the context layer moved it, the reason goes inline rather
    # than into a second row the reader has to reconcile.
    infrastructure = result.get("infrastructure_type", "unknown")
    ml_score = result.get("ml_score", 0.0)
    context_score = result.get("context_score", 0.0)

    if round(context_score, 4) != round(ml_score, 4):
        direction = "lowered" if context_score < ml_score else "raised"
        table.add_row("Score", f"{context_score}  [dim]({direction})[/dim]")
    else:
        table.add_row("Score", str(context_score))

    if infrastructure and infrastructure != "unknown":
        table.add_row("Infrastructure", infrastructure)

    # The score always decides the level now, so what this says is whether
    # anything argued with it. A dissent is the only thing the agent can still
    # raise, and it has to be visible: it is the channel for a compromised
    # legitimate site, which the model cannot see by construction.
    dissent = extract_dissent(result.get("summary", ""))
    decided_by = verdict_source(result)

    if decided_by == "no_data":
        label = "[No data collected]"
    elif result.get("summary_failed"):
        # The scores are real but no assessment was written. Without this the
        # level reads as a considered verdict when nothing considered it.
        label = "[Score-derived; summary unavailable]"
    elif decided_by == "dissent":
        label = f"[Score-derived; agent dissents, reads {dissent}]"
    elif decided_by == "concur":
        label = "[Score-derived; agent concurs]"
    else:
        # No dissent line, so a saved investigation from before this format. Its
        # THREAT LEVEL line was the verdict when it was written and is re-derived
        # now, so say when the two differ rather than printing a bare LOW beside
        # a summary whose first line reads HIGH.
        stated = extract_threat_level(result.get("summary", ""))
        label = (f"[Score-derived; summary states {stated}]"
                 if stated and stated != risk_level else "[Score-derived]")

    suffix = f"  [dim]{label}[/dim]" if label else ""
    table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]{suffix}")

    # Spelled out rather than left as a dim suffix. The verdict stands, and an
    # analyst who reads past it is exactly who this is for.
    if decided_by == "dissent":
        table.add_row("", "")
        table.add_row(
            "[bold magenta]Agent dissent[/bold magenta]",
            f"[magenta]The written assessment reads this as {dissent}, against the scored "
            f"{risk_level}.[/magenta]\nIt does not change the verdict. Worth a look where the "
            "score cannot see served content.",
        )

    # A LOW here means the model found nothing elevated, which is not the same
    # as finding the indicator safe. One in five domains scoring LOW was
    # malicious in validation, and no threshold repairs that, so the label is
    # spelled out rather than left to be read as an all-clear.
    if risk_level == "LOW" and result.get("band_precision") is not None:
        table.add_row("", "")
        table.add_row(
            "[yellow]Note[/yellow]",
            f"[yellow]LOW is not an all-clear.[/yellow] In validation "
            f"{result['band_precision']:.0%} of indicators scoring LOW were malicious.\n"
            "This model flags attacker infrastructure; it cannot clear an indicator.",
        )

    if verbose:
        table.add_row("", "")

        # The whole chain, because four different numbers reach four different
        # conclusions and only the last two were ever shown. band_precision
        # belongs on the model's own score, which is what it was measured on —
        # not on the blended figure the table reports as "Score".
        model_score = result.get("model_score")
        if model_score is not None:
            band = result.get("band_precision")
            base = result.get("band_base_rate")
            # Lift against the base rate, because a band precision alone is not
            # readable. The two models were measured on sets with different
            # priors, so 94% on the IP model is weaker evidence than 89% on the
            # domain one, and only the multiple shows it.
            lift = f", {band / base:.2f}x base rate" if band and base else ""
            measured = (
                f"  [dim]{score_to_risk(model_score)} band: {band:.0%} malicious{lift}[/dim]"
                if band else ""
            )
            table.add_row("[dim]Model score[/dim]", f"[dim]{model_score}[/dim]{measured}")

            # Shown as inputs rather than as a running total. The intermediate
            # value would mean importing the blenders here, and this module
            # stays free of them so a front end can render a cached result
            # without loading the engine. Both can only raise the model score.
            table.add_row("[dim]Graph score[/dim]", f"[dim]{result.get('graph_score', 0.0)}[/dim]")
            table.add_row("[dim]Temporal score[/dim]", f"[dim]{result.get('temporal_score', 0.0)}[/dim]")
            table.add_row("[dim]Blended[/dim]", f"[dim]{ml_score}[/dim]")
        else:
            table.add_row("[dim]Base score[/dim]", f"[dim]{ml_score}[/dim]")

        delta = round(context_score - ml_score, 4)
        table.add_row("[dim]Context modifier[/dim]", f"[dim]{delta:+} ({infrastructure})[/dim]")
        table.add_row("[dim]Score-derived[/dim]", f"[dim]{score_level(result)}[/dim]")
        # What the summary says, and what it would have said. The first is the
        # engine's own verdict written back into the prose, not a second opinion.
        table.add_row(
            "[dim]Summary states[/dim]",
            f"[dim]{extract_threat_level(result.get('summary', '')) or 'no line'}[/dim]",
        )
        table.add_row("[dim]Agent dissent[/dim]", f"[dim]{dissent or 'none'}[/dim]")

    findings = result.get("findings", [])

    relevance_hits = [
        (prefix, label_style, value_style, finding)
        for prefix, label_style, value_style in RELEVANCE_STYLES
        for finding in findings if finding.startswith(prefix)
    ]
    if relevance_hits:
        table.add_row("", "")
        for prefix, label_style, value_style, finding in relevance_hits[:5]:
            table.add_row(
                f"[{label_style}]{prefix}[/{label_style}]",
                f"[{value_style}]{finding[len(prefix) + 2:]}[/{value_style}]",
            )

    early_warnings = [f for f in findings if "EARLY WARNING" in f]
    if early_warnings:
        table.add_row("", "")
        table.add_row("[bold red]EARLY WARNING[/bold red]", f"[red]{early_warnings[0]}[/red]")

    ner_notes = [f for f in findings if "Threat actors mentioned" in f]
    if ner_notes:
        table.add_row("[bold yellow]NER[/bold yellow]", f"[yellow]{ner_notes[0]}[/yellow]")

    return table
