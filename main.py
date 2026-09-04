# main.py
# CLI entry point for project


import sys

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
from core.risk import resolve_risk_level
from core.render import build_metrics_table, format_summary, get_risk_color
 
console = Console()
 
 
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

\b
  Decide which candidates are worth a pivot, spending no VirusTotal quota
    main.py --screen -s candidates.txt
    main.py --screen -s 1.2.3.4,evil.example
"""

VERDICT_COLOURS = {"GO": "bold green", "WEAK": "bold yellow", "SKIP": "dim"}


def _screen_seeds(seed: str) -> None:
    """
    Screens candidates and prints the verdict with the reasoning behind it.

    The reasons matter more than the verdict. A SKIP an analyst disagrees with
    is one they can overrule, and the point is to show what the screen saw
    rather than to gate anything.
    """
    from pathlib import Path
    from core.executor import PivotExecutor

    path = Path(seed)
    if path.is_file():
        candidates = [ln.strip() for ln in path.read_text().splitlines()
                      if ln.strip() and not ln.startswith("#")]
    else:
        candidates = [s.strip() for s in seed.split(",") if s.strip()]

    console.print(
        f"[cyan]Screening {len(candidates)} candidate(s). "
        f"No VirusTotal quota is spent.[/cyan]\n"
    )
    executor = PivotExecutor()
    tally = {}
    for candidate in candidates:
        verdict = executor.screen(candidate)
        mark = verdict["verdict"]
        tally[mark] = tally.get(mark, 0) + 1
        colour = VERDICT_COLOURS.get(mark, "white")
        console.print(
            f"[{colour}]{mark:<5}[/{colour}] {verdict['indicator'][:44]}"
        )
        for reason in verdict.get("reasons", []):
            console.print(f"      [dim]{reason}[/dim]")
    console.print(
        "\n  " + "  ".join(f"{k} {v}" for k, v in sorted(tally.items()))
    )


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
@click.option("--screen", is_flag=True, default=False,
              help="Judge whether seeds are worth a pivot, without spending one. "
                   "--seed takes a comma-separated list or a path to a file of "
                   "one indicator per line. Costs no VirusTotal quota.")
# Display
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show how the score and risk level were derived.")
def run(seed, depth, deep, output, export_stix, screen, verbose):
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

    if screen:
        _screen_seeds(seed)
        return

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
 
    table = build_metrics_table(result, verbose=verbose)
 
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
    # No arguments means interactive use, so launch the TUI. Any flag at all
    # keeps the Click CLI, which is what scripts and the MCP server rely on.
    if len(sys.argv) == 1:
        from tui import launch
        launch()
    else:
        run()
 