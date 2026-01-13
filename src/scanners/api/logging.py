"""Insufficient Logging scanner (V10)."""

import time
from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.logging")


class LoggingScanner(Scanner):
    """Scan for Insufficient Logging and Monitoring (V10).

    Tests if the API properly handles and potentially blocks suspicious
    activity patterns that should trigger security alerts.
    """

    name = "LoggingScanner"
    description = "Detects insufficient logging and monitoring (V10)"

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Test 1: Multiple failed login attempts (should trigger rate limit or lockout)
        await self._test_brute_force_detection(target, result)

        # Test 2: SQL injection patterns (should be blocked/logged)
        await self._test_attack_detection(target, result)

        # Test 3: Rapid enumeration (should be rate limited)
        await self._test_enumeration_detection(target, result)

        return result

    async def _test_brute_force_detection(self, target: Target, result: ScanResult):
        """Test if multiple failed logins trigger any security response."""
        # Send 15 failed login attempts rapidly
        blocked = False
        attempts = 0

        for i in range(15):
            try:
                resp = self.client.post(
                    f"{target.base_url}{target.login_endpoint}",
                    json={"username": "admin", "password": f"wrongpass{i}"},
                )
                attempts += 1

                # Check for blocking responses
                if resp.status_code == 429:  # Too Many Requests
                    blocked = True
                    break
                elif resp.status_code == 403:  # Forbidden (account locked)
                    blocked = True
                    break
                elif "locked" in resp.text.lower() or "blocked" in resp.text.lower():
                    blocked = True
                    break

            except Exception as e:
                logger.debug(f"Brute force test request failed: {e}")

        if not blocked:
            result.add_finding(Finding(
                id="V10-NO-BRUTEFORCE-PROTECTION",
                name="No Brute Force Protection",
                severity=Severity.HIGH,
                description=f"API accepted {attempts} failed login attempts without blocking",
                endpoint=target.login_endpoint,
                evidence=f"{attempts} consecutive failed logins accepted without rate limiting or account lockout",
                remediation="Implement rate limiting and/or account lockout after multiple failed attempts",
                references=["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
            ))

    async def _test_attack_detection(self, target: Target, result: ScanResult):
        """Test if obvious attack patterns are detected/blocked."""
        attack_payloads = [
            ("' OR '1'='1", "SQL injection"),
            ("'; DROP TABLE users; --", "SQL injection"),
            ("; cat /etc/passwd", "Command injection"),
            ("| ls -la", "Command injection"),
            ("<script>alert('xss')</script>", "XSS"),
            ("../../../etc/passwd", "Path traversal"),
        ]

        attacks_allowed = 0

        for payload, attack_type in attack_payloads:
            try:
                resp = self.client.get(
                    f"{target.base_url}/api/products",
                    params={"search": payload},
                )

                # Check if attack was blocked
                if resp.status_code not in [400, 403, 429]:
                    attacks_allowed += 1

            except Exception as e:
                logger.debug(f"Attack detection test failed: {e}")

        if attacks_allowed >= 3:
            result.add_finding(Finding(
                id="V10-NO-ATTACK-DETECTION",
                name="No Attack Pattern Detection",
                severity=Severity.MEDIUM,
                description="API does not block or detect obvious attack patterns",
                endpoint="/api/products?search=...",
                evidence=f"{attacks_allowed}/{len(attack_payloads)} attack payloads were accepted without blocking",
                remediation="Implement WAF or input validation to detect and block common attack patterns",
                references=["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
            ))

    async def _test_enumeration_detection(self, target: Target, result: ScanResult):
        """Test if rapid resource enumeration is detected."""
        # Rapidly request multiple user IDs
        requests_sent = 0
        blocked = False

        for user_id in range(1, 21):
            try:
                resp = self.client.get(f"{target.base_url}/api/users/{user_id}")
                requests_sent += 1

                if resp.status_code == 429:
                    blocked = True
                    break

            except Exception as e:
                logger.debug(f"Enumeration test request failed: {e}")

        if not blocked and requests_sent >= 15:
            result.add_finding(Finding(
                id="V10-NO-ENUM-PROTECTION",
                name="No Enumeration Protection",
                severity=Severity.LOW,
                description="API allows rapid resource enumeration without rate limiting",
                endpoint="/api/users/{id}",
                evidence=f"Successfully enumerated {requests_sent} user IDs without rate limiting",
                remediation="Implement rate limiting to prevent resource enumeration attacks",
                references=["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
            ))
