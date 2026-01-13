"""Legacy/Deprecated API scanner (V09)."""

from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.legacy")


class LegacyAPIScanner(Scanner):
    """Scan for Improper Assets Management (V09).

    Detects exposed legacy/deprecated API versions that may have
    different security controls or expose sensitive data.
    """

    name = "LegacyAPIScanner"
    description = "Detects exposed legacy API versions (V09)"

    # API version patterns to test
    VERSION_PATTERNS = [
        "/api/v1",
        "/api/v2",
        "/api/v0",
        "/v1/api",
        "/v2/api",
        "/api/1.0",
        "/api/2.0",
        "/api-v1",
        "/api-v2",
        "/old/api",
        "/legacy/api",
        "/deprecated/api",
        "/internal/api",
        "/beta/api",
        "/alpha/api",
        "/staging/api",
        "/dev/api",
    ]

    # Common endpoints to check in legacy APIs
    TEST_ENDPOINTS = [
        "/users",
        "/users/1",
        "/products",
        "/orders",
        "/admin",
        "/config",
        "/settings",
    ]

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Detect current API version
        current_version = await self._detect_current_version(target)

        # Test for legacy versions
        await self._check_legacy_versions(target, current_version, result)

        return result

    async def _detect_current_version(self, target: Target) -> str | None:
        """Detect the current API version from root endpoint."""
        try:
            resp = self.client.get(f"{target.base_url}/")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("version") or data.get("api_version")
        except Exception:
            pass
        return None

    async def _check_legacy_versions(self, target: Target, current_version: str | None, result: ScanResult):
        """Check for accessible legacy API versions."""
        found_versions = []

        for version_path in self.VERSION_PATTERNS:
            for endpoint in self.TEST_ENDPOINTS[:3]:  # Test first 3 endpoints
                full_path = f"{version_path}{endpoint}"

                try:
                    resp = self.client.get(f"{target.base_url}{full_path}")

                    if resp.status_code == 200:
                        data = resp.json()

                        # Check if this is a different version or has more data
                        is_legacy = self._check_if_legacy(data, endpoint)

                        if version_path not in found_versions:
                            found_versions.append(version_path)

                            severity = Severity.HIGH if is_legacy else Severity.MEDIUM

                            evidence = f"Endpoint accessible: {full_path}"
                            if is_legacy:
                                evidence += " (exposes additional sensitive data)"

                            result.add_finding(Finding(
                                id="V09-LEGACY-API",
                                name=f"Legacy API Exposed: {version_path}",
                                severity=severity,
                                description=f"Legacy API version at {version_path} is accessible",
                                endpoint=full_path,
                                evidence=evidence,
                                remediation="Disable or restrict access to deprecated API versions. If needed, apply same security controls as current version.",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                            ))

                        # Check for password hash exposure specifically
                        if isinstance(data, list):
                            for item in data[:1]:
                                if isinstance(item, dict) and item.get("password_hash"):
                                    result.add_finding(Finding(
                                        id="V09-LEGACY-PWHASH",
                                        name="Legacy API Exposes Password Hashes",
                                        severity=Severity.CRITICAL,
                                        description=f"Legacy API {version_path} exposes password hashes",
                                        endpoint=full_path,
                                        evidence="password_hash field present in legacy API response",
                                        remediation="Immediately disable legacy API or remove sensitive fields from responses",
                                        references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                                    ))
                        elif isinstance(data, dict) and data.get("password_hash"):
                            result.add_finding(Finding(
                                id="V09-LEGACY-PWHASH",
                                name="Legacy API Exposes Password Hashes",
                                severity=Severity.CRITICAL,
                                description=f"Legacy API {version_path} exposes password hashes",
                                endpoint=full_path,
                                evidence="password_hash field present in legacy API response",
                                remediation="Immediately disable legacy API or remove sensitive fields from responses",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                            ))

                        break  # Found this version, move to next

                except Exception as e:
                    logger.debug(f"Legacy check failed for {full_path}: {e}")

    def _check_if_legacy(self, data: dict | list, endpoint: str) -> bool:
        """Check if response contains more data than expected (legacy behavior)."""
        # Legacy APIs often expose more fields
        dangerous_fields = [
            "password_hash", "passwordHash", "hashed_password",
            "secret", "api_key", "apiKey",
            "internal_id", "internal_notes",
        ]

        def check_obj(obj):
            if isinstance(obj, dict):
                for field in dangerous_fields:
                    if field in obj and obj[field]:
                        return True
            return False

        if isinstance(data, list):
            return any(check_obj(item) for item in data[:3])
        return check_obj(data)
