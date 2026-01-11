"""JSON reporter."""

import json
from datetime import datetime
from pathlib import Path
from src.core import ScanResult


class JSONReporter:
    """JSON output for scan results."""

    def report(self, results: list[ScanResult], target_url: str, output_path: str | None = None) -> dict:
        """Generate JSON report."""
        report = {
            "scan_info": {
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "tool": "api-security-checker",
                "version": "0.1.0",
            },
            "summary": self._generate_summary(results),
            "findings": [],
            "errors": [],
        }

        for result in results:
            for finding in result.findings:
                report["findings"].append(finding.to_dict())
            report["errors"].extend(result.errors)

        if output_path:
            Path(output_path).write_text(json.dumps(report, indent=2))

        return report

    def _generate_summary(self, results: list[ScanResult]) -> dict:
        """Generate summary statistics."""
        summary = {
            "total_findings": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "scanners_run": [],
        }

        for result in results:
            summary["scanners_run"].append(result.scanner_name)
            for finding in result.findings:
                summary["total_findings"] += 1
                summary["by_severity"][finding.severity.value] += 1

        return summary
