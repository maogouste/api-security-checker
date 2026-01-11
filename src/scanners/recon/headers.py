"""Security headers scanner."""

from src.core import Scanner, ScanResult, Finding, Severity, Target


class HeadersScanner(Scanner):
    """Scan for missing security headers."""

    name = "HeadersScanner"
    description = "Checks for missing or misconfigured security headers (V08)"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": (
            "HSTS not set",
            "Enforces HTTPS connections",
            Severity.MEDIUM,
        ),
        "X-Content-Type-Options": (
            "X-Content-Type-Options not set",
            "Prevents MIME type sniffing",
            Severity.LOW,
        ),
        "X-Frame-Options": (
            "X-Frame-Options not set",
            "Prevents clickjacking attacks",
            Severity.MEDIUM,
        ),
        "Content-Security-Policy": (
            "CSP not set",
            "Prevents XSS and injection attacks",
            Severity.MEDIUM,
        ),
        "X-XSS-Protection": (
            "X-XSS-Protection not set",
            "Legacy XSS filter (deprecated but still useful)",
            Severity.LOW,
        ),
        "Referrer-Policy": (
            "Referrer-Policy not set",
            "Controls referrer information",
            Severity.LOW,
        ),
        "Permissions-Policy": (
            "Permissions-Policy not set",
            "Controls browser features",
            Severity.LOW,
        ),
    }

    DANGEROUS_HEADERS = {
        "Server": ("Server header exposed", "Reveals server software", Severity.LOW),
        "X-Powered-By": ("X-Powered-By exposed", "Reveals technology stack", Severity.LOW),
        "X-AspNet-Version": ("ASP.NET version exposed", "Reveals framework version", Severity.MEDIUM),
        "X-AspNetMvc-Version": ("ASP.NET MVC version exposed", "Reveals framework version", Severity.MEDIUM),
    }

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        try:
            resp = self.client.get(f"{target.base_url}/")

            # Check missing security headers
            for header, (name, desc, severity) in self.SECURITY_HEADERS.items():
                if header.lower() not in [h.lower() for h in resp.headers.keys()]:
                    result.add_finding(Finding(
                        id=f"V08-HDR-{header.upper().replace('-', '')}",
                        name=name,
                        severity=severity,
                        description=desc,
                        endpoint="/",
                        evidence=f"Header '{header}' is not present",
                        remediation=f"Add '{header}' header to responses",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    ))

            # Check dangerous headers
            for header, (name, desc, severity) in self.DANGEROUS_HEADERS.items():
                value = resp.headers.get(header)
                if value:
                    result.add_finding(Finding(
                        id=f"V08-HDR-{header.upper().replace('-', '')}",
                        name=name,
                        severity=severity,
                        description=desc,
                        endpoint="/",
                        evidence=f"{header}: {value}",
                        remediation=f"Remove or obfuscate '{header}' header",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    ))

            # Check CORS configuration
            await self._check_cors(target, result)

        except Exception as e:
            result.add_error(f"Headers check failed: {e}")

        return result

    async def _check_cors(self, target: Target, result: ScanResult):
        """Check for permissive CORS configuration."""
        try:
            resp = self.client.options(
                f"{target.base_url}/api/products",
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET",
                },
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Check for wildcard with credentials
            if acao == "*" and acac.lower() == "true":
                result.add_finding(Finding(
                    id="V08-CORS-WILDCARD",
                    name="Permissive CORS with Credentials",
                    severity=Severity.HIGH,
                    description="CORS allows all origins with credentials",
                    endpoint="/api/products",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    remediation="Restrict CORS to specific trusted origins",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))
            elif acao == "*":
                result.add_finding(Finding(
                    id="V08-CORS-WILDCARD",
                    name="Permissive CORS",
                    severity=Severity.MEDIUM,
                    description="CORS allows all origins",
                    endpoint="/api/products",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict CORS to specific trusted origins",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))
            elif acao == "https://evil.com":
                result.add_finding(Finding(
                    id="V08-CORS-REFLECT",
                    name="CORS Origin Reflection",
                    severity=Severity.HIGH,
                    description="CORS reflects arbitrary origins",
                    endpoint="/api/products",
                    evidence=f"Reflected origin: {acao}",
                    remediation="Validate origins against a whitelist",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))

        except Exception:
            pass
