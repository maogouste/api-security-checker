"""Injection vulnerability scanner."""

from src.core import (
    Scanner, ScanResult, Finding, Severity, Target,
    get_logger, get_payloads,
    detect_sql_error, detect_cmd_output,
)

logger = get_logger("scanners.injection")


class InjectionScanner(Scanner):
    """Scan for injection vulnerabilities (V06, V07)."""

    name = "InjectionScanner"
    description = "Detects SQL injection and command injection (V06, V07)"

    @property
    def sql_payloads(self) -> list[str]:
        """Get SQL injection payloads from config."""
        payloads = get_payloads("sql_injection")
        if not payloads:
            # Fallback to defaults
            return [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "1' ORDER BY 1--",
            ]
        return payloads

    @property
    def cmd_payloads(self) -> list[str]:
        """Get command injection payloads from config."""
        payloads = get_payloads("command_injection")
        if not payloads:
            # Fallback to defaults
            return [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "127.0.0.1; whoami",
            ]
        return payloads

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Get token if credentials available
        token = None
        if target.valid_username and target.valid_password:
            token = await self._get_token(target)

        headers = {"Authorization": f"Bearer {token}"} if token else {}

        # Test SQL injection on search endpoints
        await self._check_sqli(target, headers, result)

        # Test command injection on tool endpoints
        await self._check_cmdi(target, headers, result)

        return result

    async def _get_token(self, target: Target) -> str | None:
        try:
            resp = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                json={"username": target.valid_username, "password": target.valid_password},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception as e:
            logger.debug(f"Failed to get token: {e}")
        return None

    async def _check_sqli(self, target: Target, headers: dict[str, str], result: ScanResult) -> None:
        """Check for SQL injection using robust pattern detection."""
        search_endpoints = [
            "/api/products?search=",
            "/api/users?search=",
            "/api/products?name=",
            "/api/products?category=",
            "/api/orders?id=",
        ]

        for endpoint in search_endpoints:
            for payload in self.sql_payloads:
                try:
                    url = f"{target.base_url}{endpoint}{payload}"
                    resp = self.client.get(url, headers=headers)

                    is_vulnerable = False
                    evidence = ""
                    confidence = 0.0

                    # Use robust pattern detection for SQL errors
                    sql_detection = detect_sql_error(resp.text)
                    if sql_detection.matched:
                        is_vulnerable = True
                        evidence = f"SQL error detected ({sql_detection.pattern_name}): {sql_detection.match_text}"
                        confidence = sql_detection.confidence

                    # Check for UNION-based injection
                    if not is_vulnerable and resp.status_code == 200 and "UNION" in payload.upper():
                        try:
                            data = resp.json()
                            if isinstance(data, list) and len(data) > 5:
                                is_vulnerable = True
                                evidence = f"UNION injection returned {len(data)} records"
                                confidence = 0.85
                        except Exception:
                            pass

                    # Check for boolean-based SQLi
                    if not is_vulnerable and "OR" in payload.upper() and resp.status_code == 200:
                        try:
                            normal_resp = self.client.get(
                                f"{target.base_url}{endpoint}test",
                                headers=headers,
                            )
                            payload_count = len(resp.json()) if isinstance(resp.json(), list) else 0
                            normal_count = len(normal_resp.json()) if isinstance(normal_resp.json(), list) else 0
                            if payload_count > normal_count:
                                is_vulnerable = True
                                evidence = f"Boolean SQLi: payload returned more results ({payload_count} vs {normal_count})"
                                confidence = 0.9
                        except Exception:
                            pass

                    # Check for time-based blind SQLi (if SLEEP/WAITFOR in payload)
                    if not is_vulnerable and any(t in payload.upper() for t in ["SLEEP", "WAITFOR", "PG_SLEEP"]):
                        import asyncio
                        loop = asyncio.get_event_loop()
                        start = loop.time()
                        try:
                            self.client.get(url, headers=headers, timeout=10)
                        except Exception:
                            pass
                        elapsed = loop.time() - start
                        if elapsed >= 4.5:  # Payload usually has SLEEP(5)
                            is_vulnerable = True
                            evidence = f"Time-based blind SQLi: response delayed {elapsed:.1f}s"
                            confidence = 0.95

                    if is_vulnerable:
                        result.add_finding(Finding(
                            id="V06-SQLI",
                            name="SQL Injection",
                            severity=Severity.CRITICAL,
                            description=f"Endpoint is vulnerable to SQL injection (confidence: {confidence:.0%})",
                            endpoint=endpoint.split("?")[0],
                            evidence=f"Payload: {payload}\n{evidence}",
                            remediation="Use parameterized queries or ORM. Never concatenate user input in SQL.",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                        ))
                        return  # One finding per endpoint type is enough

                except Exception as e:
                    logger.debug(f"SQLi test failed for {endpoint}: {e}")

    async def _check_cmdi(self, target: Target, headers: dict[str, str], result: ScanResult) -> None:
        """Check for command injection using robust pattern detection."""
        cmd_endpoints = [
            ("/api/tools/ping", "host"),
            ("/api/tools/dns", "domain"),
            ("/api/tools/lookup", "target"),
            ("/api/tools/nslookup", "hostname"),
        ]

        for endpoint, param in cmd_endpoints:
            for payload in self.cmd_payloads:
                try:
                    resp = self.client.post(
                        f"{target.base_url}{endpoint}",
                        json={param: payload},
                        headers=headers,
                    )

                    if resp.status_code in [200, 500]:
                        # Use robust pattern detection
                        cmd_detection = detect_cmd_output(resp.text)
                        if cmd_detection.matched:
                            result.add_finding(Finding(
                                id="V07-CMDI",
                                name="Command Injection",
                                severity=Severity.CRITICAL,
                                description=f"Endpoint is vulnerable to OS command injection (confidence: {cmd_detection.confidence:.0%})",
                                endpoint=endpoint,
                                evidence=f"Payload: {payload}\nDetected: {cmd_detection.pattern_name}\nMatch: {cmd_detection.match_text}",
                                remediation="Never pass user input to shell commands. Use safe APIs or subprocess with shell=False.",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                            ))
                            return

                    # Check for blind command injection via timing
                    if any(t in payload for t in ["sleep", "ping -c"]):
                        import asyncio
                        loop = asyncio.get_event_loop()
                        start = loop.time()
                        try:
                            self.client.post(
                                f"{target.base_url}{endpoint}",
                                json={param: payload},
                                headers=headers,
                                timeout=10,
                            )
                        except Exception:
                            pass
                        elapsed = loop.time() - start
                        if elapsed >= 4.5:
                            result.add_finding(Finding(
                                id="V07-CMDI-BLIND",
                                name="Blind Command Injection",
                                severity=Severity.CRITICAL,
                                description="Endpoint is vulnerable to blind command injection",
                                endpoint=endpoint,
                                evidence=f"Payload: {payload}\nResponse delayed {elapsed:.1f}s",
                                remediation="Never pass user input to shell commands. Use safe APIs.",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                            ))
                            return

                except Exception as e:
                    logger.debug(f"CMDi test failed for {endpoint}: {e}")
