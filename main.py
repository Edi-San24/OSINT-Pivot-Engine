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
from core.risk import resolve_risk_level
 
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
 
 
@click.command()
@click.option("--seed", required=True, help="The indicator to investigate (IP, domain, hash, email, or username)")
@click.option("--output", default=None, help="Save full results to a JSON file")
@click.option("--depth", default=None, type=int, help="Override max pivot depth")
@click.option("--export-stix", default=None, help="Export investigation as STIX 2.1 bundle to given path")
@click.option("--deep", is_flag=True, default=False, help="Enable SpiderFoot for email and username pivots")
def run(seed, output, depth, export_stix, deep):
    """OSINT Pivot Engine — autonomous threat intelligence enrichment tool."""
 
    if depth:
        import config
        config.MAX_PIVOT_DEPTH = depth
 
    banner = (
        "[cyan]══════════════════════════════════════[/cyan]\n"
        "[bold white]OSINT PIVOT ENGINE[/bold white]\n"
        "[cyan]── Autonomous Threat Intelligence · v1.2.0[/cyan]\n"
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
    table.add_row("ML Score", f"{result['ml_score']}  [dim](raw feature pattern match)[/dim]")
    table.add_row("Context Score", f"{result['context_score']}  [dim](adjusted for infrastructure type)[/dim]")
    table.add_row("Infrastructure", result['infrastructure_type'])
    table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]")
 
    if result['context_note']:
        table.add_row("Note", f"[dim]{result['context_note']}[/dim]")
 
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
 