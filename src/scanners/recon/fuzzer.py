"""Endpoint fuzzer - discovers hidden API endpoints."""

import json
from typing import List, Dict, Set, Tuple
from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.fuzzer")


class FuzzerScanner(Scanner):
    """Scan for hidden/undocumented API endpoints.

    Features:
    - Parses OpenAPI/Swagger specs to discover documented endpoints
    - Fuzzes REST resource patterns (CRUD operations)
    - Discovers hidden HTTP methods
    - Tests parameter variations
    """

    name = "FuzzerScanner"
    description = "Discovers hidden API endpoints via fuzzing"

    # Common REST resources to fuzz
    RESOURCES = [
        "users", "user", "accounts", "account",
        "products", "product", "items", "item",
        "orders", "order", "invoices", "invoice",
        "customers", "customer", "clients", "client",
        "posts", "post", "articles", "article",
        "comments", "comment", "reviews", "review",
        "files", "file", "uploads", "upload",
        "images", "image", "documents", "document",
        "settings", "config", "configs", "configuration",
        "admin", "admins", "administrators",
        "roles", "role", "permissions", "permission",
        "tokens", "token", "sessions", "session",
        "logs", "log", "events", "event",
        "notifications", "notification",
        "messages", "message", "emails", "email",
        "payments", "payment", "transactions", "transaction",
        "reports", "report", "analytics", "stats",
        "search", "query", "lookup",
        "export", "import", "backup", "restore",
        "sync", "refresh", "reset", "verify",
    ]

    # HTTP methods to test
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    # Common ID patterns
    ID_PATTERNS = ["1", "0", "-1", "admin", "me", "current", "self", "test", "null"]

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Try to discover endpoints from OpenAPI spec
        openapi_endpoints = await self._parse_openapi(target)

        # Fuzz REST endpoints
        await self._fuzz_rest_endpoints(target, result)

        # Test undocumented methods on discovered endpoints
        await self._fuzz_methods(target, openapi_endpoints, result)

        # Discover admin/internal variations
        await self._fuzz_internal_endpoints(target, result)

        return result

    async def _parse_openapi(self, target: Target) -> Set[str]:
        """Parse OpenAPI/Swagger spec to discover endpoints."""
        endpoints = set()
        spec_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api-docs",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/api/openapi.json",
            "/docs/openapi.json",
        ]

        for spec_path in spec_paths:
            try:
                resp = self.client.get(f"{target.base_url}{spec_path}")
                if resp.status_code == 200:
                    try:
                        spec = resp.json()
                        if "paths" in spec:
                            for path in spec["paths"].keys():
                                endpoints.add(path)
                            logger.info(f"Found {len(spec['paths'])} endpoints in {spec_path}")
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.debug(f"Failed to fetch {spec_path}: {e}")

        return endpoints

    async def _fuzz_rest_endpoints(self, target: Target, result: ScanResult):
        """Fuzz common REST endpoint patterns."""
        discovered = []
        api_prefixes = ["/api", "/api/v1", "/api/v2", "/v1", "/v2", ""]

        for prefix in api_prefixes:
            for resource in self.RESOURCES[:20]:  # Limit to avoid too many requests
                # Test collection endpoint
                endpoint = f"{prefix}/{resource}"
                status = await self._check_endpoint(target, endpoint)
                if status in [200, 401, 403]:
                    discovered.append((endpoint, status))

                # Test single resource endpoint
                endpoint_with_id = f"{prefix}/{resource}/1"
                status = await self._check_endpoint(target, endpoint_with_id)
                if status in [200, 401, 403]:
                    discovered.append((endpoint_with_id, status))

        # Report interesting discoveries
        for endpoint, status in discovered:
            if status == 200:
                severity = Severity.MEDIUM
                desc = "Accessible endpoint"
            elif status == 401:
                severity = Severity.LOW
                desc = "Protected endpoint exists"
            else:  # 403
                severity = Severity.LOW
                desc = "Forbidden endpoint exists"

            # Only report non-trivial findings
            if status == 200 and not self._is_common_endpoint(endpoint):
                result.add_finding(Finding(
                    id=f"FUZZ-ENDPOINT-{endpoint.replace('/', '-').strip('-').upper()[:30]}",
                    name=f"Discovered Endpoint: {endpoint}",
                    severity=severity,
                    description=desc,
                    endpoint=endpoint,
                    evidence=f"HTTP {status}",
                    remediation="Review if this endpoint should be exposed",
                    references=["https://owasp.org/www-project-api-security/"],
                ))

    async def _fuzz_methods(self, target: Target, known_endpoints: Set[str], result: ScanResult):
        """Test undocumented HTTP methods on endpoints."""
        # Test a few key endpoints
        test_endpoints = list(known_endpoints)[:10] if known_endpoints else [
            "/api/users",
            "/api/products",
            "/api/orders",
        ]

        for endpoint in test_endpoints:
            methods_allowed = []
            for method in self.HTTP_METHODS:
                try:
                    resp = self.client.request(method, f"{target.base_url}{endpoint}")
                    if resp.status_code not in [404, 405]:
                        methods_allowed.append(method)
                except Exception:
                    pass

            # Check for dangerous methods
            dangerous = set(methods_allowed) & {"DELETE", "PUT", "PATCH"}
            if dangerous and len(methods_allowed) > 2:
                result.add_finding(Finding(
                    id=f"FUZZ-METHODS-{endpoint.replace('/', '-').strip('-').upper()[:20]}",
                    name=f"Multiple HTTP Methods: {endpoint}",
                    severity=Severity.INFO,
                    description=f"Endpoint accepts multiple HTTP methods",
                    endpoint=endpoint,
                    evidence=f"Allowed methods: {', '.join(methods_allowed)}",
                    remediation="Ensure all allowed methods are intentional and secured",
                    references=["https://owasp.org/www-project-api-security/"],
                ))

    async def _fuzz_internal_endpoints(self, target: Target, result: ScanResult):
        """Fuzz for internal/admin endpoint variations."""
        internal_prefixes = [
            "/internal",
            "/private",
            "/_",
            "/__",
            "/hidden",
            "/secret",
            "/admin/api",
            "/api/admin",
            "/api/internal",
            "/management",
            "/system",
        ]

        internal_endpoints = [
            "/config", "/settings", "/env", "/debug",
            "/users", "/logs", "/metrics", "/status",
        ]

        discovered = []
        for prefix in internal_prefixes:
            for endpoint in internal_endpoints:
                full_path = f"{prefix}{endpoint}"
                status = await self._check_endpoint(target, full_path)
                if status in [200, 401, 403]:
                    discovered.append((full_path, status))

        for endpoint, status in discovered:
            severity = Severity.HIGH if status == 200 else Severity.MEDIUM
            result.add_finding(Finding(
                id=f"FUZZ-INTERNAL-{endpoint.replace('/', '-').strip('-').upper()[:20]}",
                name=f"Internal Endpoint: {endpoint}",
                severity=severity,
                description="Internal/admin endpoint discovered",
                endpoint=endpoint,
                evidence=f"HTTP {status}",
                remediation="Restrict access to internal endpoints",
                references=["https://owasp.org/www-project-api-security/"],
            ))

    async def _check_endpoint(self, target: Target, endpoint: str) -> int:
        """Check if endpoint exists and return status code."""
        try:
            resp = self.client.get(
                f"{target.base_url}{endpoint}",
                follow_redirects=False,
                timeout=5,
            )
            return resp.status_code
        except Exception:
            return 0

    def _is_common_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is a common/expected one."""
        common = [
            "/api/users", "/api/products", "/api/orders",
            "/users", "/products", "/orders",
            "/api/v1/users", "/api/v1/products",
            "/health", "/status", "/docs",
        ]
        return endpoint in common
