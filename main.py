# main.py
# CLI entry point for project


import click
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box
from core.agent import run_agent
from core.stix_exporter import STIXExporter
from config import VERSION
from core.risk import (
    resolve_risk_level,
    score_to_risk,
    extract_threat_level,
    NON_INFRASTRUCTURE_TYPES,
)
 
console = Console()
 
 
def get_risk_color(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "bold red"
    elif risk_level == "MEDIUM":
        return "bold yellow"
    else:
        return "bold green"
 
 
def format_summary(summary) -> Text:
    """
    Formats the structured investigation summary for Rich terminal display.
    Colors each section label for readability.
    """
    if not isinstance(summary, str):
        summary = ""
 
    text = Text()
    lines = summary.strip().split("\n")
 
    section_colors = {
        "THREAT LEVEL:": "bold white",
        "ASSESSMENT:": "bold cyan",
        "KEY INDICATORS:": "bold cyan",
        "VISIBILITY GAPS:": "bold yellow",
        "RECOMMENDED ACTIONS:": "bold cyan",
    }
 
    for line in lines:
        stripped = line.strip()
        matched = False
        for label, color in section_colors.items():
            if stripped.startswith(label):
                text.append(label + " ", style=color)
                text.append(stripped[len(label):].strip() + "\n")
                matched = True
                break
        if not matched:
            text.append(line + "\n")
 
    return text
 
 
HELP_BANNER = f"""\
   OSINT PIVOT ENGINE  v{VERSION}
   ─────────────────────────────────────────────
     seed ─┬─▶ ip ─────▶ domain ──▶ certificates
           ├─▶ hash ───▶ samples ─▶ family
           └─▶ group ──▶ tooling ─▶ live samples
   ─────────────────────────────────────────────
"""


class BannerCommand(click.Command):
    """Prints the pivot diagram above the usage line on --help."""

    def format_help(self, ctx, formatter):
        formatter.write(HELP_BANNER + "\n")
        super().format_help(ctx, formatter)


EXAMPLES = """
\b
Examples:
  Investigate an IP address
    main.py -s 185.220.101.45

\b
  Profile a threat group, chaining into live malware samples
    main.py -s "Lazarus Group"

\b
  Save the full result and export a bundle for your TIP
    main.py -s db349b97c37d22f5ea1d1841e3c89eb4 -o case.json --export-stix case-stix.json

\b
  Show how the score and risk level were reached
    main.py -s 185.220.101.45 --verbose

\b
  Follow the chain further than the default three pivots
    main.py -s suspicious-domain.com --depth 5
"""


@click.command(
    cls=BannerCommand,
    epilog=EXAMPLES,
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 96},
)
# Investigation
@click.option("--seed", "-s", required=True, metavar="INDICATOR",
              help="The indicator to investigate. See supported types above.")
@click.option("--depth", default=None, type=int, metavar="N",
              help="Maximum indicators to pivot through. Default 3.")
@click.option("--deep", is_flag=True, default=False,
              help="Add SpiderFoot enrichment. Email and username seeds only, and slow.")
# Output
@click.option("--output", "-o", default=None, metavar="PATH",
              help="Write the full result, including raw connector output, to JSON.")
@click.option("--export-stix", default=None, metavar="PATH",
              help="Write a STIX 2.1 bundle for MISP, OpenCTI, or any TAXII platform.")
# Display
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show how the score and risk level were derived.")
def run(seed, depth, deep, output, export_stix, verbose):
    """
    Autonomous threat intelligence enrichment.

    Give it one indicator. It queries every relevant OSINT source in parallel,
    follows the indicators it discovers, scores what it finds, and writes an
    analyst summary.

    \b
    Supported indicators:
      IPv4              185.220.101.45
      Domain            paypal-login-secure.com
      File hash         MD5, SHA1, or SHA256
      Threat group      Lazarus Group
      Malware family    WannaCry
      Email             analyst@example.com
      Username          threat_actor_handle
    """

    if depth:
        import config
        config.MAX_PIVOT_DEPTH = depth
 
    banner = (
        "[cyan]══════════════════════════════════════[/cyan]\n"
        "[bold white]OSINT PIVOT ENGINE[/bold white]\n"
        f"[cyan]── Autonomous Threat Intelligence · v{VERSION}[/cyan]\n"
        "[cyan]══════════════════════════════════════[/cyan]\n"
        f"[dim]Seed: {seed}[/dim]"
    )
    console.print(banner)
 
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running pivot chain...", total=None)
        result = run_agent(seed, deep=deep)
        progress.update(task, description="Investigation complete.")
 
    risk_level = resolve_risk_level(result)
    risk_color = get_risk_color(risk_level)
 
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Field", style="dim")
    table.add_column("Value")
 
    table.add_row("Pivots run", str(result['pivot_count']))
    table.add_row("Findings", str(len(result['findings'])))

    # One score: the context-adjusted one, since that is what feeds the risk
    # level. When the context layer moved it, the reason goes inline rather
    # than into a second row the reader has to reconcile.
    infrastructure = result['infrastructure_type']
    adjusted = round(result['context_score'], 4) != round(result['ml_score'], 4)

    if adjusted:
        direction = "lowered" if result['context_score'] < result['ml_score'] else "raised"
        table.add_row("Score", f"{result['context_score']}  [dim]({direction})[/dim]")
    else:
        table.add_row("Score", str(result['context_score']))

    if infrastructure and infrastructure != "unknown":
        table.add_row("Infrastructure", infrastructure)

    # The agent's written verdict outranks the score on infrastructure pivots.
    # Label it whenever the agent is the source, not only when it disagrees —
    # a label that appears intermittently is its own kind of confusing.
    agent_sourced = (
        result.get('indicator_type', '') not in NON_INFRASTRUCTURE_TYPES
        and extract_threat_level(result['summary']) is not None
    )
    if agent_sourced:
        table.add_row(
            "Risk Level",
            f"[{risk_color}]{risk_level}[/{risk_color}]  [dim][Agent's Verdict][/dim]"
        )
    else:
        table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]")

    if verbose:
        table.add_row("", "")
        table.add_row("[dim]Base score[/dim]", f"[dim]{result['ml_score']}[/dim]")
        delta = round(result['context_score'] - result['ml_score'], 4)
        table.add_row(
            "[dim]Context modifier[/dim]",
            f"[dim]{delta:+} ({infrastructure})[/dim]"
        )
        table.add_row("[dim]Score-derived[/dim]", f"[dim]{score_to_risk(result['context_score'])}[/dim]")
        agent_verdict = extract_threat_level(result['summary']) or "none stated"
        table.add_row("[dim]Agent verdict[/dim]", f"[dim]{agent_verdict}[/dim]")

    # Org relevance — absent entirely unless an org profile is configured.
    # Ordered by urgency: an indicator that is your own host outranks
    # everything else in this table.
    relevance_styles = [
        ("OWN ASSET", "bold red", "red"),
        ("BRAND ABUSE", "bold yellow", "yellow"),
        ("ORG RELEVANCE", "bold cyan", "cyan"),
        ("COVERAGE GAP", "dim", "dim"),
    ]
    relevance_hits = [
        (prefix, label_style, value_style, finding)
        for prefix, label_style, value_style in relevance_styles
        for finding in result['findings'] if finding.startswith(prefix)
    ]
    if relevance_hits:
        table.add_row("", "")
        for prefix, label_style, value_style, finding in relevance_hits[:5]:
            table.add_row(
                f"[{label_style}]{prefix}[/{label_style}]",
                f"[{value_style}]{finding[len(prefix) + 2:]}[/{value_style}]"
            )

    # Early warning
    early_warnings = [f for f in result['findings'] if "EARLY WARNING" in f]
    if early_warnings:
        table.add_row("", "")
        table.add_row("[bold red]EARLY WARNING[/bold red]", f"[red]{early_warnings[0]}[/red]")
 
    # NER actor recommendations
    ner_notes = [f for f in result['findings'] if "Threat actors mentioned" in f]
    if ner_notes:
        table.add_row("[bold yellow]NER[/bold yellow]", f"[yellow]{ner_notes[0]}[/yellow]")
 
    console.print(table)
 
    console.print(Panel(
        format_summary(result['summary']),
        title="[bold]Investigation Summary[/bold]",
        border_style=risk_color.replace("bold ", ""),
        padding=(1, 2)
    ))
 
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to {output}[/green]")
 
    if export_stix:
        exporter = STIXExporter()
        path = exporter.export(result, export_stix)
        if path:
            console.print(f"\n[green]STIX 2.1 bundle exported to {path}[/green]")
        else:
            console.print("\n[red]STIX export failed — no results to export.[/red]")
 
 
if __name__ == "__main__":
    run()
 