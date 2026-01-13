"""Endpoints scanner - discovers common API endpoints."""

from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.endpoints")


class EndpointsScanner(Scanner):
    """Scan for common exposed endpoints."""

    name = "EndpointsScanner"
    description = "Discovers common API endpoints (admin, debug, metrics)"

    ENDPOINTS = {
        # Admin endpoints
        "/admin": ("Admin panel", Severity.HIGH),
        "/admin/": ("Admin panel", Severity.HIGH),
        "/administrator": ("Admin panel", Severity.HIGH),
        "/dashboard": ("Dashboard", Severity.MEDIUM),
        "/console": ("Console", Severity.HIGH),
        "/manage": ("Management interface", Severity.MEDIUM),
        "/management": ("Management interface", Severity.MEDIUM),

        # Debug/Development
        "/debug": ("Debug endpoint", Severity.HIGH),
        "/debug/": ("Debug endpoint", Severity.HIGH),
        "/dev": ("Development endpoint", Severity.MEDIUM),
        "/test": ("Test endpoint", Severity.LOW),
        "/phpinfo": ("PHP info", Severity.MEDIUM),
        "/_debug": ("Debug endpoint", Severity.HIGH),
        "/__debug__": ("Debug endpoint", Severity.HIGH),

        # Monitoring/Metrics
        "/metrics": ("Metrics endpoint", Severity.MEDIUM),
        "/prometheus": ("Prometheus metrics", Severity.MEDIUM),
        "/health": ("Health check", Severity.INFO),
        "/healthz": ("Health check", Severity.INFO),
        "/status": ("Status endpoint", Severity.LOW),
        "/ping": ("Ping endpoint", Severity.INFO),
        "/ready": ("Readiness probe", Severity.INFO),
        "/live": ("Liveness probe", Severity.INFO),

        # API versions (info disclosure)
        "/api": ("API root", Severity.INFO),
        "/api/": ("API root", Severity.INFO),
        "/api/v1": ("API v1", Severity.INFO),
        "/api/v2": ("API v2", Severity.INFO),
        "/api/v1/": ("API v1", Severity.INFO),
        "/v1": ("API v1", Severity.INFO),
        "/v2": ("API v2", Severity.INFO),

        # Documentation
        "/docs": ("API documentation", Severity.LOW),
        "/swagger": ("Swagger UI", Severity.LOW),
        "/swagger-ui": ("Swagger UI", Severity.LOW),
        "/swagger-ui.html": ("Swagger UI", Severity.LOW),
        "/api-docs": ("API documentation", Severity.LOW),
        "/redoc": ("ReDoc documentation", Severity.LOW),
        "/graphql": ("GraphQL endpoint", Severity.INFO),
        "/graphiql": ("GraphiQL interface", Severity.MEDIUM),
        "/playground": ("GraphQL Playground", Severity.MEDIUM),

        # Database interfaces
        "/phpmyadmin": ("phpMyAdmin", Severity.CRITICAL),
        "/pma": ("phpMyAdmin", Severity.CRITICAL),
        "/adminer": ("Adminer", Severity.CRITICAL),
        "/mysql": ("MySQL interface", Severity.CRITICAL),

        # Common frameworks
        "/actuator": ("Spring Actuator", Severity.HIGH),
        "/actuator/env": ("Spring Actuator env", Severity.CRITICAL),
        "/actuator/health": ("Spring Actuator health", Severity.LOW),
        "/actuator/beans": ("Spring Actuator beans", Severity.MEDIUM),
        "/actuator/mappings": ("Spring Actuator mappings", Severity.MEDIUM),
        "/rails/info": ("Rails info", Severity.MEDIUM),
        "/elmah.axd": ("ELMAH error log", Severity.HIGH),
        "/trace.axd": (".NET trace", Severity.HIGH),

        # Backup/Old versions
        "/backup": ("Backup directory", Severity.HIGH),
        "/old": ("Old version", Severity.MEDIUM),
        "/temp": ("Temp directory", Severity.MEDIUM),
        "/tmp": ("Temp directory", Severity.MEDIUM),

        # User management
        "/users": ("Users endpoint", Severity.MEDIUM),
        "/api/users": ("Users API", Severity.MEDIUM),
        "/accounts": ("Accounts endpoint", Severity.MEDIUM),
        "/register": ("Registration", Severity.INFO),
        "/signup": ("Signup", Severity.INFO),
        "/login": ("Login", Severity.INFO),

        # Config endpoints
        "/config": ("Configuration", Severity.HIGH),
        "/settings": ("Settings", Severity.MEDIUM),
        "/env": ("Environment", Severity.CRITICAL),
        "/environment": ("Environment", Severity.CRITICAL),
    }

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        for endpoint, (description, severity) in self.ENDPOINTS.items():
            await self._check_endpoint(target, endpoint, description, severity, result)

        return result

    async def _check_endpoint(
        self,
        target: Target,
        endpoint: str,
        description: str,
        severity: Severity,
        result: ScanResult,
    ):
        """Check if an endpoint is accessible."""
        try:
            url = f"{target.base_url}{endpoint}"
            resp = self.client.get(url, follow_redirects=False)

            # Accessible if 200, 301, 302, or 401 (exists but protected)
            if resp.status_code in [200, 301, 302]:
                status_info = "accessible" if resp.status_code == 200 else f"redirects ({resp.status_code})"

                # Only report if severity is MEDIUM or higher
                # or if it returns interesting content
                if severity.value in ["critical", "high", "medium"]:
                    result.add_finding(Finding(
                        id=f"RECON-ENDPOINT-{endpoint.replace('/', '-').strip('-').upper()}",
                        name=f"Endpoint Found: {endpoint}",
                        severity=severity,
                        description=f"{description} ({status_info})",
                        endpoint=endpoint,
                        evidence=f"HTTP {resp.status_code}",
                        remediation="Restrict access to sensitive endpoints",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))
            elif resp.status_code == 401:
                # Exists but requires auth - lower severity
                if severity.value in ["critical", "high"]:
                    result.add_finding(Finding(
                        id=f"RECON-ENDPOINT-{endpoint.replace('/', '-').strip('-').upper()}",
                        name=f"Protected Endpoint: {endpoint}",
                        severity=Severity.INFO,
                        description=f"{description} (requires authentication)",
                        endpoint=endpoint,
                        evidence="HTTP 401 - endpoint exists but is protected",
                        remediation="Ensure strong authentication is in place",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))

        except Exception as e:
            logger.debug(f"Failed to check endpoint {endpoint}: {e}")
