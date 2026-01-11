"""Console reporter with rich formatting."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from src.core import ScanResult, Severity


class ConsoleReporter:
    """Rich console output for scan results."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "[!]",
        Severity.HIGH: "[!]",
        Severity.MEDIUM: "[*]",
        Severity.LOW: "[-]",
        Severity.INFO: "[i]",
    }

    def __init__(self):
        self.console = Console()

    def report(self, results: list[ScanResult], target_url: str):
        """Generate console report."""
        self.console.print()
        self.console.print(Panel(
            f"[bold]API Security Scan Results[/bold]\n[dim]{target_url}[/dim]",
            style="blue",
        ))

        # Collect all findings
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        if not all_findings:
            self.console.print("\n[green]No vulnerabilities found![/green]\n")
            return

        # Summary
        self._print_summary(all_findings)

        # Findings table
        self._print_findings(all_findings)

        # Errors
        errors = []
        for result in results:
            errors.extend(result.errors)
        if errors:
            self._print_errors(errors)

    def _print_summary(self, findings: list):
        """Print summary statistics."""
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        table = Table(title="Summary", show_header=False, box=None)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if counts[severity] > 0:
                color = self.SEVERITY_COLORS[severity]
                table.add_row(
                    Text(severity.value.upper(), style=color),
                    Text(str(counts[severity]), style=color),
                )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def _print_findings(self, findings: list):
        """Print findings table."""
        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("ID", width=15)
        table.add_column("Name", width=35)
        table.add_column("Endpoint", width=25)

        # Sort by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

        for finding in sorted_findings:
            color = self.SEVERITY_COLORS[finding.severity]
            table.add_row(
                Text(finding.severity.value.upper(), style=color),
                finding.id,
                finding.name,
                finding.endpoint,
            )

        self.console.print(table)

        # Detailed findings
        self.console.print("\n[bold]Details:[/bold]\n")
        for finding in sorted_findings:
            color = self.SEVERITY_COLORS[finding.severity]
            icon = self.SEVERITY_ICONS[finding.severity]

            self.console.print(f"[{color}]{icon} {finding.id}: {finding.name}[/{color}]")
            self.console.print(f"    Endpoint: {finding.endpoint}")
            self.console.print(f"    {finding.description}")
            if finding.evidence:
                self.console.print(f"    [dim]Evidence: {finding.evidence[:100]}...[/dim]" if len(finding.evidence) > 100 else f"    [dim]Evidence: {finding.evidence}[/dim]")
            self.console.print()

    def _print_errors(self, errors: list[str]):
        """Print scan errors."""
        self.console.print("\n[yellow]Warnings/Errors:[/yellow]")
        for error in errors:
            self.console.print(f"  [dim]- {error}[/dim]")
