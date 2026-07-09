# main.py
# CLI entry point for project 

# CLI entry point for the OSINT Pivot Engine.
# Accepts a seed indicator and routes it through the pivot chain.

import click
import json
from core.executor import PivotExecutor

@click.command()
@click.option("--seed", required=True, help="The indicator to investigate (IP, domain, hash, email, or username)")
def run(seed):
    """OSINT Pivot Engine — autonomous threat intelligence enrichment tool."""

    click.echo(f"\n[*] Seed received: {seed}")
    click.echo("[*] Initializing pivot chain...\n")

    executor = PivotExecutor()
    result = executor.run(seed)

    click.echo(f"[+] Pivot complete. Results below:\n")
    click.echo(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    run()