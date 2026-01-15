"""SARIF reporter - generates SARIF format for CI/CD integration."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from src.core import ScanResult, Severity


class SARIFReporter:
    """Generate SARIF (Static Analysis Results Interchange Format) reports.

    SARIF is supported by:
    - GitHub Code Scanning
    - Azure DevOps
    - GitLab SAST
    - Many other CI/CD platforms
    """

    TOOL_NAME = "api-security-checker"
    TOOL_VERSION = "0.1.0"
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Severity mapping to SARIF levels
    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    # Security severity for GitHub Code Scanning
    SECURITY_SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
    }

    def report(
        self,
        results: List[ScanResult],
        target_url: str,
        output_path: str | None = None,
    ) -> Dict[str, Any]:
        """Generate SARIF report."""
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": self._generate_tool_info(),
                    "results": self._generate_results(results, target_url),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        }
                    ],
                }
            ],
        }

        if output_path:
            Path(output_path).write_text(json.dumps(sarif, indent=2))

        return sarif

    def _generate_tool_info(self) -> Dict[str, Any]:
        """Generate tool descriptor."""
        return {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.TOOL_VERSION,
                "informationUri": "https://github.com/vulnapi/api-security-checker",
                "rules": self._generate_rules(),
            }
        }

    def _generate_rules(self) -> List[Dict[str, Any]]:
        """Generate rule descriptors for all vulnerability types."""
        rules = [
            {
                "id": "V01-BOLA",
                "name": "BrokenObjectLevelAuthorization",
                "shortDescription": {"text": "Broken Object Level Authorization"},
                "fullDescription": {"text": "API endpoint allows access to objects belonging to other users"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V02-AUTH",
                "name": "BrokenAuthentication",
                "shortDescription": {"text": "Broken Authentication"},
                "fullDescription": {"text": "Authentication mechanism is flawed or missing"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V03-EXPOSURE",
                "name": "ExcessiveDataExposure",
                "shortDescription": {"text": "Excessive Data Exposure"},
                "fullDescription": {"text": "API returns more data than necessary"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V05-MASS",
                "name": "MassAssignment",
                "shortDescription": {"text": "Mass Assignment"},
                "fullDescription": {"text": "API allows modification of object properties that should be protected"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V06-SQLI",
                "name": "SQLInjection",
                "shortDescription": {"text": "SQL Injection"},
                "fullDescription": {"text": "API endpoint is vulnerable to SQL injection attacks"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "properties": {"tags": ["security", "api", "injection"]},
            },
            {
                "id": "V07-CMDI",
                "name": "CommandInjection",
                "shortDescription": {"text": "Command Injection"},
                "fullDescription": {"text": "API endpoint is vulnerable to OS command injection"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "properties": {"tags": ["security", "api", "injection"]},
            },
            {
                "id": "V08-HEADERS",
                "name": "SecurityMisconfiguration",
                "shortDescription": {"text": "Security Misconfiguration"},
                "fullDescription": {"text": "Security headers are missing or misconfigured"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V09-LEGACY",
                "name": "ImproperAssetsManagement",
                "shortDescription": {"text": "Improper Assets Management"},
                "fullDescription": {"text": "Legacy API versions are exposed"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "V10-LOGGING",
                "name": "InsufficientLogging",
                "shortDescription": {"text": "Insufficient Logging & Monitoring"},
                "fullDescription": {"text": "API lacks proper logging and monitoring"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                "properties": {"tags": ["security", "api", "owasp-api-top10"]},
            },
            {
                "id": "G01-INTROSPECTION",
                "name": "GraphQLIntrospectionEnabled",
                "shortDescription": {"text": "GraphQL Introspection Enabled"},
                "fullDescription": {"text": "GraphQL introspection is enabled in production"},
                "helpUri": "https://owasp.org/www-project-web-security-testing-guide/",
                "properties": {"tags": ["security", "graphql"]},
            },
        ]
        return rules

    def _generate_results(self, results: List[ScanResult], target_url: str) -> List[Dict[str, Any]]:
        """Generate SARIF results from scan findings."""
        sarif_results = []

        for result in results:
            for finding in result.findings:
                sarif_result = {
                    "ruleId": self._normalize_rule_id(finding.id),
                    "level": self.SEVERITY_MAP.get(finding.severity.value, "note"),
                    "message": {
                        "text": f"{finding.name}: {finding.description}",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": target_url + finding.endpoint,
                                    "uriBaseId": "APIROOT",
                                }
                            }
                        }
                    ],
                    "properties": {
                        "security-severity": self._get_security_severity(finding.severity.value),
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                    },
                }

                # Add fingerprint for deduplication
                sarif_result["fingerprints"] = {
                    "primary": f"{finding.id}:{finding.endpoint}",
                }

                sarif_results.append(sarif_result)

        return sarif_results

    def _normalize_rule_id(self, finding_id: str) -> str:
        """Normalize finding ID to rule ID."""
        # Extract base rule ID (e.g., V06-SQLI from V06-SQLI-BLIND)
        parts = finding_id.split("-")
        if len(parts) >= 2:
            return f"{parts[0]}-{parts[1]}"
        return finding_id

    def _get_security_severity(self, severity: str) -> str:
        """Get numeric security severity for GitHub Code Scanning."""
        # GitHub uses a scale of 0.0-10.0
        severity_scores = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "4.0",
            "low": "2.0",
            "info": "1.0",
        }
        return severity_scores.get(severity, "1.0")
