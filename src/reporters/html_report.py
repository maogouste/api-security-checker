"""HTML reporter - generates standalone HTML reports."""

from datetime import datetime
from html import escape
from pathlib import Path
from typing import List
from src.core import ScanResult, Severity


class HTMLReporter:
    """Generate standalone HTML security reports."""

    def report(
        self,
        results: List[ScanResult],
        target_url: str,
        output_path: str | None = None,
    ) -> str:
        """Generate HTML report."""
        summary = self._generate_summary(results)
        findings_html = self._generate_findings_html(results)

        html = self._render_template(
            target_url=target_url,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            summary=summary,
            findings_html=findings_html,
            total=summary["total_findings"],
        )

        if output_path:
            Path(output_path).write_text(html)

        return html

    def _generate_summary(self, results: List[ScanResult]) -> dict:
        """Generate summary statistics."""
        summary = {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "scanners_run": [],
        }

        for result in results:
            summary["scanners_run"].append(result.scanner_name)
            for finding in result.findings:
                summary["total_findings"] += 1
                summary[finding.severity.value] += 1

        return summary

    def _generate_findings_html(self, results: List[ScanResult]) -> str:
        """Generate HTML for all findings."""
        findings = []
        for result in results:
            findings.extend(result.findings)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        html_parts = []
        for finding in findings:
            severity_class = finding.severity.value
            html_parts.append(f'''
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="severity-badge {severity_class}">{escape(finding.severity.value.upper())}</span>
                    <span class="finding-id">{escape(finding.id)}</span>
                    <h3>{escape(finding.name)}</h3>
                </div>
                <div class="finding-body">
                    <p class="description">{escape(finding.description)}</p>
                    <div class="finding-details">
                        <div class="detail">
                            <strong>Endpoint:</strong>
                            <code>{escape(finding.endpoint)}</code>
                        </div>
                        <div class="detail">
                            <strong>Evidence:</strong>
                            <pre>{escape(finding.evidence)}</pre>
                        </div>
                        <div class="detail">
                            <strong>Remediation:</strong>
                            <p>{escape(finding.remediation)}</p>
                        </div>
                        {self._render_references(finding.references)}
                    </div>
                </div>
            </div>
            ''')

        return "\n".join(html_parts)

    def _render_references(self, references: List[str]) -> str:
        """Render references as links."""
        if not references:
            return ""
        links = " ".join(f'<a href="{escape(ref)}" target="_blank">{escape(ref[:50])}...</a>' for ref in references)
        return f'<div class="detail"><strong>References:</strong> {links}</div>'

    def _render_template(
        self,
        target_url: str,
        timestamp: str,
        summary: dict,
        findings_html: str,
        total: int,
    ) -> str:
        """Render the full HTML template."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Report - {escape(target_url)}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --border: #e2e8f0;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 12px;
        }}
        header h1 {{ font-size: 1.75rem; margin-bottom: 0.5rem; }}
        header .meta {{ opacity: 0.8; font-size: 0.9rem; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat {{
            background: var(--card);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat .count {{
            font-size: 2.5rem;
            font-weight: bold;
            display: block;
        }}
        .stat.critical .count {{ color: var(--critical); }}
        .stat.high .count {{ color: var(--high); }}
        .stat.medium .count {{ color: var(--medium); }}
        .stat.low .count {{ color: var(--low); }}
        .stat.info .count {{ color: var(--info); }}
        .stat .label {{ color: #64748b; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        .findings {{ display: flex; flex-direction: column; gap: 1rem; }}
        .finding {{
            background: var(--card);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid var(--info);
        }}
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding-header {{
            padding: 1rem 1.5rem;
            background: #f8fafc;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        .finding-header h3 {{ font-size: 1rem; flex-grow: 1; }}
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
            background: var(--info);
        }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); }}
        .severity-badge.low {{ background: var(--low); }}
        .finding-id {{ color: #64748b; font-size: 0.875rem; font-family: monospace; }}
        .finding-body {{ padding: 1.5rem; }}
        .description {{ margin-bottom: 1rem; }}
        .finding-details {{ display: flex; flex-direction: column; gap: 0.75rem; }}
        .detail strong {{ color: #475569; }}
        .detail code {{
            background: #f1f5f9;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        .detail pre {{
            background: #f1f5f9;
            padding: 0.75rem;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.875rem;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .detail a {{ color: #2563eb; text-decoration: none; }}
        .detail a:hover {{ text-decoration: underline; }}
        footer {{
            margin-top: 2rem;
            padding: 1rem;
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
        }}
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: none; padding: 0; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>API Security Scan Report</h1>
            <div class="meta">
                <div>Target: <strong>{escape(target_url)}</strong></div>
                <div>Generated: {timestamp}</div>
                <div>Scanners: {len(summary["scanners_run"])} | Findings: {total}</div>
            </div>
        </header>

        <section class="summary">
            <div class="stat critical">
                <span class="count">{summary["critical"]}</span>
                <span class="label">Critical</span>
            </div>
            <div class="stat high">
                <span class="count">{summary["high"]}</span>
                <span class="label">High</span>
            </div>
            <div class="stat medium">
                <span class="count">{summary["medium"]}</span>
                <span class="label">Medium</span>
            </div>
            <div class="stat low">
                <span class="count">{summary["low"]}</span>
                <span class="label">Low</span>
            </div>
            <div class="stat info">
                <span class="count">{summary["info"]}</span>
                <span class="label">Info</span>
            </div>
        </section>

        <section class="findings">
            <h2 style="margin-bottom: 1rem; color: #475569;">Findings</h2>
            {findings_html if findings_html else '<p style="color: #64748b;">No vulnerabilities found.</p>'}
        </section>

        <footer>
            Generated by <strong>API Security Checker</strong> |
            <a href="https://owasp.org/API-Security/" target="_blank">OWASP API Security</a>
        </footer>
    </div>
</body>
</html>'''
