"""Injection vulnerability scanner."""

from src.core import Scanner, ScanResult, Finding, Severity, Target


class InjectionScanner(Scanner):
    """Scan for injection vulnerabilities (V06, V07)."""

    name = "InjectionScanner"
    description = "Detects SQL injection and command injection (V06, V07)"

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
    ]

    CMD_PAYLOADS = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "127.0.0.1; whoami",
    ]

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
        except Exception:
            pass
        return None

    async def _check_sqli(self, target: Target, headers: dict, result: ScanResult):
        """Check for SQL injection."""
        search_endpoints = [
            "/api/products?search=",
            "/api/users?search=",
            "/api/products?name=",
            "/api/products?category=",
        ]

        for endpoint in search_endpoints:
            for payload in self.SQL_PAYLOADS:
                try:
                    url = f"{target.base_url}{endpoint}{payload}"
                    resp = self.client.get(url, headers=headers)

                    # Signs of SQLi
                    is_vulnerable = False
                    evidence = ""

                    # Check for SQL errors in response
                    text = resp.text.lower()
                    sql_errors = ["sql", "syntax", "sqlite", "mysql", "postgresql", "oracle"]
                    if any(err in text for err in sql_errors):
                        is_vulnerable = True
                        evidence = "SQL error in response"

                    # Check for unexpected data return (UNION success)
                    if resp.status_code == 200 and "UNION" in payload:
                        try:
                            data = resp.json()
                            if isinstance(data, list) and len(data) > 5:
                                is_vulnerable = True
                                evidence = f"UNION injection returned {len(data)} records"
                        except Exception:
                            pass

                    # Check for boolean-based (OR 1=1 returns more results)
                    if "OR" in payload and resp.status_code == 200:
                        try:
                            # Compare with normal request
                            normal_resp = self.client.get(
                                f"{target.base_url}{endpoint}test",
                                headers=headers,
                            )
                            if len(resp.json()) > len(normal_resp.json()):
                                is_vulnerable = True
                                evidence = f"Boolean SQLi: payload returned more results ({len(resp.json())} vs {len(normal_resp.json())})"
                        except Exception:
                            pass

                    if is_vulnerable:
                        result.add_finding(Finding(
                            id="V06-SQLI",
                            name="SQL Injection",
                            severity=Severity.CRITICAL,
                            description="Endpoint is vulnerable to SQL injection",
                            endpoint=endpoint.split("?")[0],
                            evidence=f"Payload: {payload}\n{evidence}",
                            remediation="Use parameterized queries or ORM",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                        ))
                        return  # One finding per endpoint type is enough

                except Exception as e:
                    pass  # Continue testing

    async def _check_cmdi(self, target: Target, headers: dict, result: ScanResult):
        """Check for command injection."""
        cmd_endpoints = [
            ("/api/tools/ping", "host"),
            ("/api/tools/dns", "domain"),
        ]

        for endpoint, param in cmd_endpoints:
            for payload in self.CMD_PAYLOADS:
                try:
                    resp = self.client.post(
                        f"{target.base_url}{endpoint}",
                        json={param: payload},
                        headers=headers,
                    )

                    if resp.status_code in [200, 500]:
                        text = resp.text.lower()
                        # Check for command execution signs
                        cmd_signs = ["uid=", "root:", "bin/", "/home/", "whoami", "www-data"]
                        if any(sign in text for sign in cmd_signs):
                            result.add_finding(Finding(
                                id="V07-CMDI",
                                name="Command Injection",
                                severity=Severity.CRITICAL,
                                description="Endpoint is vulnerable to OS command injection",
                                endpoint=endpoint,
                                evidence=f"Payload: {payload}\nResponse contains command output",
                                remediation="Never pass user input to shell commands. Use safe APIs.",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                            ))
                            return

                except Exception:
                    pass
