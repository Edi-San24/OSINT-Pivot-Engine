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
    extract_threat_level,
    resolve_risk_level,
    score_level,
    verdict_source,
)

# Section labels the agent writes, and the colour each gets on screen.
SUMMARY_SECTIONS = {
    "THREAT LEVEL:": "bold white",
    "ASSESSMENT:": "bold cyan",
    "KEY INDICATORS:": "bold cyan",
    "VISIBILITY GAPS:": "bold yellow",
    "RECOMMENDED ACTIONS:": "bold cyan",
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

    # Always say which source the level came from. Nothing was collected, the
    # agent's verdict won, or the scorer overruled it — and that last case used
    # to print a bare LOW next to a summary reading HIGH with no explanation.
    agent_level = extract_threat_level(result.get("summary", ""))
    decided_by = verdict_source(result)

    if decided_by == "no_data":
        label = "[No data collected]"
    elif result.get("summary_failed"):
        # The scores are real but no assessment was written. Without this the
        # level reads as a considered verdict when nothing considered it.
        label = "[Score-derived; summary unavailable]"
    elif decided_by == "agent":
        label = "[Agent's Verdict]"
    elif agent_level and agent_level != risk_level:
        label = f"[Score-derived; agent said {agent_level}]"
    else:
        label = ""

    suffix = f"  [dim]{label}[/dim]" if label else ""
    table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]{suffix}")

    if verbose:
        table.add_row("", "")
        table.add_row("[dim]Base score[/dim]", f"[dim]{ml_score}[/dim]")
        delta = round(context_score - ml_score, 4)
        table.add_row("[dim]Context modifier[/dim]", f"[dim]{delta:+} ({infrastructure})[/dim]")
        table.add_row("[dim]Score-derived[/dim]", f"[dim]{score_level(result)}[/dim]")
        table.add_row(
            "[dim]Agent verdict[/dim]",
            f"[dim]{extract_threat_level(result.get('summary', '')) or 'none stated'}[/dim]",
        )

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
