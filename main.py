# main.py
# CLI entry point for project 

# CLI entry point for the OSINT Pivot Engine.
# Accepts a seed indicator and routes it through the pivot chain.

import click
from core.detector import detect_type

@click.command()
@click.option("--seed", required = True, help = "The inidcator to investigate (IP, domain, hash, email, or username)")
def run(seed):
    """
    OSINT Pivot Engine: Auto threat intelligence enrichment tool.
    """
    click.echo(f"\n[*] Seed received: {seed}")

    result = detect_type(seed)
    click.echo(f"[+] Detected type: {result['type'].upper()}")
    click.echo(f"[+] Confidence:  {result['confidence']}")
    click.echo(f"\n[>] Ready to route {result['indicator']} through pivot chain! \n")

if __name__ == "__main__":
    run()
    