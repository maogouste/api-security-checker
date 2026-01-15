"""CLI interface for API Security Checker."""

import asyncio
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TaskID

from src.core import Target, setup_logging, get_logger
from src.core.scanner import Scanner, ScanResult
from src.scanners import (
    AuthScanner,
    BOLAScanner,
    DataExposureScanner,
    MassAssignmentScanner,
    InjectionScanner,
    LegacyAPIScanner,
    LoggingScanner,
    GraphQLScanner,
    KnownFilesScanner,
    EndpointsScanner,
    HeadersScanner,
    FuzzerScanner,
)
from src.reporters import ConsoleReporter, JSONReporter, HTMLReporter, SARIFReporter

app = typer.Typer(
    name="apisec",
    help="API Security Checker - Scan REST and GraphQL APIs for vulnerabilities",
    add_completion=False,
)
console = Console()


def get_all_scanners(client: httpx.Client) -> list[Scanner]:
    """Get all available scanners."""
    return [
        # V01-V10 Scanners
        BOLAScanner(client),           # V01
        AuthScanner(client),           # V02, V04
        DataExposureScanner(client),   # V03
        MassAssignmentScanner(client), # V05
        InjectionScanner(client),      # V06, V07
        HeadersScanner(client),        # V08
        LegacyAPIScanner(client),      # V09
        LoggingScanner(client),        # V10
        # GraphQL G01-G05
        GraphQLScanner(client),
        # Recon
        KnownFilesScanner(client),
        EndpointsScanner(client),
    ]


def get_scanners_by_type(client: httpx.Client, scan_type: str) -> list[Scanner]:
    """Get scanners by type."""
    scanners = {
        "api": [BOLAScanner, AuthScanner, DataExposureScanner, MassAssignmentScanner,
                InjectionScanner, LegacyAPIScanner, LoggingScanner, GraphQLScanner],
        "rest": [BOLAScanner, AuthScanner, DataExposureScanner, MassAssignmentScanner,
                 InjectionScanner, HeadersScanner, LegacyAPIScanner, LoggingScanner],
        "recon": [KnownFilesScanner, EndpointsScanner, HeadersScanner, FuzzerScanner],
        "auth": [AuthScanner, BOLAScanner, MassAssignmentScanner],
        "injection": [InjectionScanner],
        "graphql": [GraphQLScanner],
        "headers": [HeadersScanner],
        "files": [KnownFilesScanner],
        "endpoints": [EndpointsScanner],
        "exposure": [DataExposureScanner, LegacyAPIScanner],
        "logging": [LoggingScanner],
        "fuzz": [FuzzerScanner, EndpointsScanner],
    }
    return [cls(client) for cls in scanners.get(scan_type, [])]


async def run_scan_sequential(target: Target, scanners: list[Scanner]) -> list[ScanResult]:
    """Run all scanners sequentially against target."""
    logger = get_logger("cli")
    results: list[ScanResult] = []
    for scanner in scanners:
        console.print(f"  [dim]Running {scanner.name}...[/dim]")
        try:
            result = await scanner.scan(target)
            results.append(result)
        except Exception as e:
            console.print(f"  [red]Error in {scanner.name}: {e}[/red]")
            logger.error(f"Scanner {scanner.name} failed: {e}")
    return results


async def run_scan_parallel(
    target: Target,
    scanners: list[Scanner],
    max_concurrent: int = 5,
    rate_limit: float = 0.1,
) -> list[ScanResult]:
    """
    Run scanners in parallel with concurrency limit and rate limiting.

    Args:
        target: Target configuration
        scanners: List of scanner instances
        max_concurrent: Maximum concurrent scanners
        rate_limit: Minimum seconds between scanner starts
    """
    logger = get_logger("cli")
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[ScanResult] = []
    errors: list[str] = []
    lock = asyncio.Lock()

    async def run_scanner(scanner: Scanner, progress: Progress, task_id: TaskID) -> None:
        async with semaphore:
            # Rate limiting - wait before starting
            await asyncio.sleep(rate_limit)

            progress.update(task_id, description=f"[cyan]{scanner.name}[/cyan]")
            try:
                result = await scanner.scan(target)
                async with lock:
                    results.append(result)
            except Exception as e:
                logger.error(f"Scanner {scanner.name} failed: {e}")
                async with lock:
                    errors.append(f"{scanner.name}: {e}")
            finally:
                progress.advance(task_id)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        console=console,
    ) as progress:
        task_id = progress.add_task("Starting...", total=len(scanners))

        # Create all tasks
        tasks = [run_scanner(scanner, progress, task_id) for scanner in scanners]

        # Run all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

    # Report errors
    for error in errors:
        console.print(f"  [red]Error: {error}[/red]")

    return results


async def run_scan(
    target: Target,
    scanners: list[Scanner],
    parallel: int = 1,
    rate_limit: float = 0.1,
) -> list[ScanResult]:
    """Run all scanners against target."""
    if parallel > 1:
        return await run_scan_parallel(target, scanners, parallel, rate_limit)
    else:
        return await run_scan_sequential(target, scanners)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL (e.g., http://localhost:8000)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Target config YAML file"),
    scan_type: str = typer.Option("all", "--type", "-t", help="Scan type: all, api, recon, auth, injection, graphql, headers, files, endpoints"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Username for authentication testing"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password for authentication testing"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="JSON output file"),
    html_output: Optional[Path] = typer.Option(None, "--html", help="HTML report output file"),
    sarif_output: Optional[Path] = typer.Option(None, "--sarif", help="SARIF output file (for CI/CD integration)"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL certificate verification (use with caution)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Write logs to file"),
    parallel: int = typer.Option(1, "--parallel", "-P", help="Number of concurrent scanners (1-10)", min=1, max=10),
    rate_limit: float = typer.Option(0.1, "--rate-limit", "-r", help="Seconds between requests (rate limiting)"),
):
    """
    Scan an API for security vulnerabilities.

    Examples:

        apisec scan http://localhost:8000

        apisec scan http://localhost:8000 -u john -p password123

        apisec scan http://localhost:8000 --type graphql

        apisec scan http://localhost:8000 -c config/vulnapi.yaml -o report.json
    """
    # Setup logging
    logger = setup_logging(
        verbose=verbose,
        log_file=str(log_file) if log_file else None,
    )
    logger.info(f"Starting scan of {url}")

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

    # Handle SSL verification
    verify_ssl = not insecure
    target.verify_ssl = verify_ssl

    console.print(f"\n[bold blue]API Security Checker[/bold blue]")
    console.print(f"Target: {target.base_url}")
    console.print(f"Scan type: {scan_type}")

    if insecure:
        console.print("[yellow]Warning: SSL certificate verification is disabled[/yellow]")
        logger.warning("SSL certificate verification disabled - vulnerable to MITM attacks")

    console.print()

    # Create HTTP client with proper SSL verification
    with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
        # Get scanners
        if scan_type == "all":
            scanners = get_all_scanners(client)
        else:
            scanners = get_scanners_by_type(client, scan_type)

        if not scanners:
            console.print(f"[red]Unknown scan type: {scan_type}[/red]")
            raise typer.Exit(1)

        if parallel > 1:
            console.print(f"[dim]Running {len(scanners)} scanners in parallel (max {parallel} concurrent)...[/dim]\n")
        else:
            console.print(f"[dim]Running {len(scanners)} scanners...[/dim]\n")

        # Run scans
        results = asyncio.run(run_scan(target, scanners, parallel, rate_limit))

    # Generate reports
    console_reporter = ConsoleReporter()
    console_reporter.report(results, target.base_url)

    if output:
        json_reporter = JSONReporter()
        json_reporter.report(results, target.base_url, str(output))
        console.print(f"\n[green]JSON report saved to {output}[/green]")

    if html_output:
        html_reporter = HTMLReporter()
        html_reporter.report(results, target.base_url, str(html_output))
        console.print(f"[green]HTML report saved to {html_output}[/green]")

    if sarif_output:
        sarif_reporter = SARIFReporter()
        sarif_reporter.report(results, target.base_url, str(sarif_output))
        console.print(f"[green]SARIF report saved to {sarif_output}[/green]")

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
    port: int = typer.Option(8000, "--port", help="VulnAPI port"),
    backend: str = typer.Option("fastapi", "--backend", "-b", help="Backend: fastapi, express, go, php, java"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL certificate verification"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    parallel: int = typer.Option(5, "--parallel", "-P", help="Number of concurrent scanners (1-10)", min=1, max=10),
):
    """
    Quick scan against VulnAPI with preset configuration.

    Examples:

        apisec vulnapi

        apisec vulnapi --port 3001 --backend express
    """
    # Setup logging
    logger = setup_logging(verbose=verbose)

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

    console.print(f"\n[bold blue]Scanning VulnAPI ({backend})[/bold blue]")

    if insecure:
        console.print("[yellow]Warning: SSL certificate verification is disabled[/yellow]")
        logger.warning("SSL certificate verification disabled")

    console.print()

    # Use VulnAPI preset
    verify_ssl = not insecure
    target = Target(
        base_url=url,
        name=f"VulnAPI-{backend}",
        valid_username="john",
        valid_password="password123",
        login_endpoint="/api/login",
        graphql_endpoint="/graphql",
        verify_ssl=verify_ssl,
    )

    with httpx.Client(timeout=10, verify=verify_ssl) as client:
        scanners = get_all_scanners(client)
        console.print(f"[dim]Running {len(scanners)} scanners in parallel...[/dim]\n")
        results = asyncio.run(run_scan(target, scanners, parallel=parallel))

    console_reporter = ConsoleReporter()
    console_reporter.report(results, target.base_url)


@app.command()
def list_scanners():
    """List all available scanners."""
    console.print("\n[bold]Available Scanners:[/bold]\n")

    console.print("[bold cyan]REST API Vulnerabilities (V01-V10):[/bold cyan]")
    rest_scanners = [
        ("BOLAScanner", "V01", "Broken Object Level Authorization"),
        ("AuthScanner", "V02,V04", "Broken Authentication & Rate Limiting"),
        ("DataExposureScanner", "V03", "Excessive Data Exposure"),
        ("MassAssignmentScanner", "V05", "Mass Assignment"),
        ("InjectionScanner", "V06,V07", "SQL & Command Injection"),
        ("HeadersScanner", "V08", "Security Misconfiguration"),
        ("LegacyAPIScanner", "V09", "Improper Assets Management"),
        ("LoggingScanner", "V10", "Insufficient Logging"),
    ]
    for name, vulns, desc in rest_scanners:
        console.print(f"  [cyan]{name}[/cyan] [{vulns}]")
        console.print(f"    {desc}\n")

    console.print("[bold cyan]GraphQL Vulnerabilities (G01-G05):[/bold cyan]")
    console.print(f"  [cyan]GraphQLScanner[/cyan] [G01-G05]")
    console.print(f"    Introspection, Depth, Batching, Suggestions, Auth Bypass\n")

    console.print("[bold cyan]Reconnaissance:[/bold cyan]")
    recon_scanners = [
        ("KnownFilesScanner", "Exposed sensitive files (.env, .git, etc)"),
        ("EndpointsScanner", "Common exposed endpoints (admin, debug)"),
    ]
    for name, desc in recon_scanners:
        console.print(f"  [cyan]{name}[/cyan]")
        console.print(f"    {desc}\n")


@app.command()
def train(
    target: str = typer.Option("http://localhost:8000", "--target", "-t", help="VulnAPI target URL"),
    challenge: Optional[str] = typer.Option(None, "--challenge", "-c", help="Specific challenge ID (e.g., V01, V06, G01)"),
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Learning path ID (beginner, intermediate, graphql)"),
    all_challenges: bool = typer.Option(False, "--all", "-a", help="Run all challenges"),
    list_items: bool = typer.Option(False, "--list", "-l", help="List available challenges and paths"),
):
    """
    Interactive training mode with VulnAPI challenges.

    Examples:

        apisec train --list

        apisec train --challenge V01

        apisec train --path beginner

        apisec train --all

        apisec train -t http://localhost:8000 -c V06
    """
    from src.modes import TrainingMode

    training = TrainingMode(target_url=target)

    if list_items:
        training.list_challenges()
        console.print()
        training.list_paths()
        return

    if challenge:
        asyncio.run(training.run_challenge(challenge))
    elif path:
        asyncio.run(training.run_path(path))
    elif all_challenges:
        asyncio.run(training.run_all())
    else:
        # Default: show list
        console.print("[yellow]No challenge specified. Use --list to see options.[/yellow]\n")
        training.list_challenges()
        console.print()
        console.print("[dim]Use --challenge V01 or --path beginner to start[/dim]")


if __name__ == "__main__":
    app()
