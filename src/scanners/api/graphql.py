"""GraphQL vulnerability scanner."""

import json
from src.core import Scanner, ScanResult, Finding, Severity, Target


class GraphQLScanner(Scanner):
    """Scan for GraphQL vulnerabilities (G01-G05)."""

    name = "GraphQLScanner"
    description = "Detects GraphQL-specific vulnerabilities (G01-G05)"

    INTROSPECTION_QUERY = """
    query {
        __schema {
            types {
                name
                fields {
                    name
                    type { name }
                }
            }
        }
    }
    """

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        graphql_url = target.graphql_endpoint or "/graphql"
        full_url = f"{target.base_url}{graphql_url}"

        # G01: Introspection enabled
        await self._check_introspection(full_url, result)

        # G02: No query depth limit
        await self._check_depth_limit(full_url, result)

        # G03: Batching allowed
        await self._check_batching(full_url, result)

        # G04: Field suggestions
        await self._check_field_suggestions(full_url, result)

        # G05: Authorization bypass
        await self._check_auth_bypass(full_url, result)

        return result

    async def _check_introspection(self, url: str, result: ScanResult):
        """Check if introspection is enabled."""
        try:
            resp = self.client.post(
                url,
                json={"query": self.INTROSPECTION_QUERY},
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("data", {}).get("__schema"):
                    types = data["data"]["__schema"]["types"]
                    type_names = [t["name"] for t in types if not t["name"].startswith("__")]

                    result.add_finding(Finding(
                        id="G01-INTRO",
                        name="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        description="GraphQL introspection is enabled, exposing the entire schema",
                        endpoint=url,
                        evidence=f"Exposed types: {', '.join(type_names[:10])}{'...' if len(type_names) > 10 else ''}",
                        remediation="Disable introspection in production",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                    ))

        except Exception as e:
            result.add_error(f"Introspection check failed: {e}")

    async def _check_depth_limit(self, url: str, result: ScanResult):
        """Check for query depth limits."""
        # Deep nested query
        deep_query = """
        query {
            users {
                orders {
                    user {
                        orders {
                            user {
                                username
                            }
                        }
                    }
                }
            }
        }
        """

        try:
            resp = self.client.post(url, json={"query": deep_query})

            if resp.status_code == 200:
                data = resp.json()
                if not data.get("errors"):
                    result.add_finding(Finding(
                        id="G02-DEPTH",
                        name="No Query Depth Limit",
                        severity=Severity.HIGH,
                        description="GraphQL allows deeply nested queries without limits",
                        endpoint=url,
                        evidence="5-level nested query was accepted",
                        remediation="Implement query depth limiting (max 3-5 levels)",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                    ))

        except Exception as e:
            result.add_error(f"Depth limit check failed: {e}")

    async def _check_batching(self, url: str, result: ScanResult):
        """Check if query batching is allowed."""
        batch_query = [
            {"query": "{ products { id } }"},
            {"query": "{ products { id } }"},
            {"query": "{ products { id } }"},
            {"query": "{ products { id } }"},
            {"query": "{ products { id } }"},
        ]

        try:
            resp = self.client.post(url, json=batch_query)

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == 5:
                    result.add_finding(Finding(
                        id="G03-BATCH",
                        name="GraphQL Batching Allowed",
                        severity=Severity.MEDIUM,
                        description="GraphQL allows batching multiple operations in one request",
                        endpoint=url,
                        evidence="5 batched queries were accepted",
                        remediation="Limit batch size or disable batching",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                    ))

        except Exception as e:
            result.add_error(f"Batching check failed: {e}")

    async def _check_field_suggestions(self, url: str, result: ScanResult):
        """Check if field suggestions are enabled."""
        query = "{ users { userna } }"  # Typo in 'username'

        try:
            resp = self.client.post(url, json={"query": query})

            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                for error in errors:
                    msg = error.get("message", "").lower()
                    if "did you mean" in msg or "suggestion" in msg:
                        result.add_finding(Finding(
                            id="G04-SUGGEST",
                            name="GraphQL Field Suggestions",
                            severity=Severity.LOW,
                            description="GraphQL suggests field names in error messages",
                            endpoint=url,
                            evidence=error.get("message"),
                            remediation="Disable field suggestions in production",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        ))
                        break

        except Exception as e:
            result.add_error(f"Field suggestions check failed: {e}")

    async def _check_auth_bypass(self, url: str, result: ScanResult):
        """Check for authorization bypass on sensitive queries."""
        sensitive_query = """
        query {
            users {
                id
                username
                ssn
                creditCard
            }
        }
        """

        try:
            # Query WITHOUT authentication
            resp = self.client.post(url, json={"query": sensitive_query})

            if resp.status_code == 200:
                data = resp.json()
                users = data.get("data", {}).get("users", [])
                if users:
                    # Check if sensitive data is exposed
                    sensitive_exposed = any(
                        u.get("ssn") or u.get("creditCard")
                        for u in users
                    )
                    if sensitive_exposed:
                        result.add_finding(Finding(
                            id="G05-AUTH",
                            name="GraphQL Authorization Bypass",
                            severity=Severity.CRITICAL,
                            description="Sensitive data accessible without authentication via GraphQL",
                            endpoint=url,
                            evidence=f"Retrieved {len(users)} users with SSN/credit card without auth",
                            remediation="Implement authentication and authorization in resolvers",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        ))

        except Exception as e:
            result.add_error(f"Auth bypass check failed: {e}")
