# main.py
# CLI entry point for project 

import click
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from core.agent import run_agent
from core.stix_exporter import STIXExporter


console = Console()

def get_risk_color(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "bold red"
    elif risk_level == "MEDIUM":
        return "bold yellow"
    else:
        return "bold green"

def get_context_score_risk(score: float) -> str:
    if score >= 0.7:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"

@click.command()
@click.option("--seed", required=True, help="The indicator to investigate (IP, domain, hash, email, or username)")
@click.option("--output", default=None, help="Save full results to a JSON file")
@click.option("--depth", default=None, type=int, help="Override max pivot depth")
@click.option("--export-stix", default=None, help="Export investigation as STIX 2.1 bundle to given path")
def run(seed, output, depth, export_stix):
    """OSINT Pivot Engine — autonomous threat intelligence enrichment tool."""

    if depth:
        import config
        config.MAX_PIVOT_DEPTH = depth

    banner = (
        "[cyan]══════════════════════════════════════[/cyan]\n"
        "[bold white]OSINT PIVOT ENGINE[/bold white]\n"
        "[cyan]── Autonomous Threat Intelligence · v1.0[/cyan]\n"
        "[cyan]══════════════════════════════════════[/cyan]\n"
        f"[dim]Seed: {seed}[/dim]"
    )
    console.print(banner)

    with console.status("[bold cyan]Launching AI agent...[/bold cyan]", spinner="dots"):
        result = run_agent(seed)

    risk_level = get_context_score_risk(result['context_score'])
    risk_color = get_risk_color(risk_level)

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Field", style="dim")
    table.add_column("Value")

    table.add_row("Pivots run", str(result['pivot_count']))
    table.add_row("Findings", str(len(result['findings'])))
    table.add_row("ML Score", f"{result['ml_score']}  [dim](raw feature pattern match)[/dim]")
    table.add_row("Context Score", f"{result['context_score']}  [dim](adjusted for infrastructure type)[/dim]")
    table.add_row("Infrastructure", result['infrastructure_type'])
    table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]")

    if result['context_note']:
        table.add_row("Note", f"[dim]{result['context_note']}[/dim]")

    console.print(table)

    console.print(Panel(
        result['summary'],
        title="[bold]Investigation Summary[/bold]",
        border_style=risk_color.replace("bold ", "")
    ))

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to {output}[/green]")
    else:
        console.print("\n[dim]Full results:[/dim]")
        console.print_json(json.dumps(result['full_results'], default=str))

    if export_stix:
        exporter = STIXExporter()
        path = exporter.export(result, export_stix)
        if path:
            console.print(f"\n[green]STIX 2.1 bundle exported to {path}[/green]")
        else:
            console.print("\n[red]STIX export failed — no results to export.[/red]")

if __name__ == "__main__":
    run()