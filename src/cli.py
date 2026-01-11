"""CLI interface for API Security Checker."""

import asyncio
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from src.core import Target
from src.scanners import (
    AuthScanner,
    BOLAScanner,
    InjectionScanner,
    GraphQLScanner,
    KnownFilesScanner,
    EndpointsScanner,
    HeadersScanner,
)
from src.reporters import ConsoleReporter, JSONReporter

app = typer.Typer(
    name="apisec",
    help="API Security Checker - Scan REST and GraphQL APIs for vulnerabilities",
    add_completion=False,
)
console = Console()


def get_all_scanners(client: httpx.Client) -> list:
    """Get all available scanners."""
    return [
        AuthScanner(client),
        BOLAScanner(client),
        InjectionScanner(client),
        GraphQLScanner(client),
        KnownFilesScanner(client),
        EndpointsScanner(client),
        HeadersScanner(client),
    ]


def get_scanners_by_type(client: httpx.Client, scan_type: str) -> list:
    """Get scanners by type."""
    scanners = {
        "api": [AuthScanner, BOLAScanner, InjectionScanner, GraphQLScanner],
        "recon": [KnownFilesScanner, EndpointsScanner, HeadersScanner],
        "auth": [AuthScanner, BOLAScanner],
        "injection": [InjectionScanner],
        "graphql": [GraphQLScanner],
        "headers": [HeadersScanner],
        "files": [KnownFilesScanner],
        "endpoints": [EndpointsScanner],
    }
    return [cls(client) for cls in scanners.get(scan_type, [])]


async def run_scan(target: Target, scanners: list) -> list:
    """Run all scanners against target."""
    results = []
    for scanner in scanners:
        console.print(f"  [dim]Running {scanner.name}...[/dim]")
        try:
            result = await scanner.scan(target)
            results.append(result)
        except Exception as e:
            console.print(f"  [red]Error in {scanner.name}: {e}[/red]")
    return results


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL (e.g., http://localhost:8000)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Target config YAML file"),
    scan_type: str = typer.Option("all", "--type", "-t", help="Scan type: all, api, recon, auth, injection, graphql, headers, files, endpoints"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Username for authentication testing"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password for authentication testing"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="JSON output file"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
):
    """
    Scan an API for security vulnerabilities.

    Examples:

        apisec scan http://localhost:8000

        apisec scan http://localhost:8000 -u john -p password123

        apisec scan http://localhost:8000 --type graphql

        apisec scan http://localhost:8000 -c config/vulnapi.yaml -o report.json
    """
    # Load target configuration
    if config and config.exists():
        target = Target.from_yaml(str(config))
        target.base_url = url  # Override with CLI arg
    else:
        target = Target(
            base_url=url.rstrip("/"),
            valid_username=username,
            valid_password=password,
        )

    # Override credentials if provided
    if username:
        target.valid_username = username
    if password:
        target.valid_password = password

    console.print(f"\n[bold blue]API Security Checker[/bold blue]")
    console.print(f"Target: {target.base_url}")
    console.print(f"Scan type: {scan_type}\n")

    # Create HTTP client
    with httpx.Client(timeout=timeout, verify=False) as client:
        # Get scanners
        if scan_type == "all":
            scanners = get_all_scanners(client)
        else:
            scanners = get_scanners_by_type(client, scan_type)

        if not scanners:
            console.print(f"[red]Unknown scan type: {scan_type}[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Running {len(scanners)} scanners...[/dim]\n")

        # Run scans
        results = asyncio.run(run_scan(target, scanners))

    # Generate reports
    console_reporter = ConsoleReporter()
    console_reporter.report(results, target.base_url)

    if output:
        json_reporter = JSONReporter()
        json_reporter.report(results, target.base_url, str(output))
        console.print(f"\n[green]Report saved to {output}[/green]")

    # Exit code based on findings
    total_findings = sum(len(r.findings) for r in results)
    critical_high = sum(
        1 for r in results for f in r.findings
        if f.severity.value in ["critical", "high"]
    )

    if critical_high > 0:
        raise typer.Exit(2)
    elif total_findings > 0:
        raise typer.Exit(1)


@app.command()
def vulnapi(
    port: int = typer.Option(8000, "--port", "-p", help="VulnAPI port"),
    backend: str = typer.Option("fastapi", "--backend", "-b", help="Backend: fastapi, express, go, php, java"),
):
    """
    Quick scan against VulnAPI with preset configuration.

    Examples:

        apisec vulnapi

        apisec vulnapi --port 3001 --backend express
    """
    ports = {
        "fastapi": 8000,
        "express": 3001,
        "go": 3002,
        "php": 3003,
        "java": 3004,
    }

    if backend in ports:
        port = ports[backend]

    url = f"http://localhost:{port}"

    console.print(f"\n[bold blue]Scanning VulnAPI ({backend})[/bold blue]\n")

    # Use VulnAPI preset
    target = Target(
        base_url=url,
        name=f"VulnAPI-{backend}",
        valid_username="john",
        valid_password="password123",
        login_endpoint="/api/login",
        graphql_endpoint="/graphql",
    )

    with httpx.Client(timeout=10, verify=False) as client:
        scanners = get_all_scanners(client)
        console.print(f"[dim]Running {len(scanners)} scanners...[/dim]\n")
        results = asyncio.run(run_scan(target, scanners))

    console_reporter = ConsoleReporter()
    console_reporter.report(results, target.base_url)


@app.command()
def list_scanners():
    """List all available scanners."""
    console.print("\n[bold]Available Scanners:[/bold]\n")

    scanners_info = [
        ("AuthScanner", "auth", "Authentication vulnerabilities (V02, V04)"),
        ("BOLAScanner", "auth", "Broken Object Level Authorization (V01)"),
        ("InjectionScanner", "injection", "SQL and Command injection (V06, V07)"),
        ("GraphQLScanner", "graphql", "GraphQL vulnerabilities (G01-G05)"),
        ("KnownFilesScanner", "files", "Exposed sensitive files"),
        ("EndpointsScanner", "endpoints", "Common exposed endpoints"),
        ("HeadersScanner", "headers", "Security headers analysis (V08)"),
    ]

    for name, type_, desc in scanners_info:
        console.print(f"  [cyan]{name}[/cyan] [{type_}]")
        console.print(f"    {desc}\n")


if __name__ == "__main__":
    app()
