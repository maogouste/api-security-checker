"""Tests for GraphQLScanner."""

import pytest
import httpx
import respx

from src.core import Severity
from src.scanners import GraphQLScanner


class TestGraphQLScanner:
    """Tests for GraphQL vulnerability scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = GraphQLScanner(client)
        assert scanner.name == "GraphQLScanner"
        assert "G01" in scanner.description

    def test_introspection_query_defined(self, mock_client):
        """Introspection query is defined."""
        client, _ = mock_client
        scanner = GraphQLScanner(client)
        assert "__schema" in scanner.INTROSPECTION_QUERY


class TestGraphQLIntrospection:
    """Tests for G01 - Introspection detection."""

    @respx.mock
    async def test_detects_introspection_enabled(
        self, base_url, target, graphql_introspection_response
    ):
        """Detects enabled introspection."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(200, json=graphql_introspection_response)
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        intro_findings = [f for f in result.findings if "INTRO" in f.id]
        assert len(intro_findings) == 1
        assert intro_findings[0].severity == Severity.MEDIUM
        assert "Query" in intro_findings[0].evidence or "User" in intro_findings[0].evidence

    @respx.mock
    async def test_no_finding_introspection_disabled(self, base_url, target):
        """No finding when introspection is disabled."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={"errors": [{"message": "Introspection is disabled"}]}
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        intro_findings = [f for f in result.findings if "INTRO" in f.id]
        assert len(intro_findings) == 0


class TestGraphQLDepthLimit:
    """Tests for G02 - Query depth limit."""

    @respx.mock
    async def test_detects_no_depth_limit(self, base_url, target):
        """Detects missing query depth limit."""
        # Deep query succeeds
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(200, json={"data": {"users": []}})
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        depth_findings = [f for f in result.findings if "DEPTH" in f.id]
        assert len(depth_findings) == 1
        assert depth_findings[0].severity == Severity.HIGH

    @respx.mock
    async def test_depth_limit_enforced(self, base_url, target):
        """No finding when depth limit is enforced."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={"errors": [{"message": "Query depth exceeded maximum"}]}
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        depth_findings = [f for f in result.findings if "DEPTH" in f.id]
        assert len(depth_findings) == 0


class TestGraphQLBatching:
    """Tests for G03 - Batching attacks."""

    @respx.mock
    async def test_detects_batching_allowed(self, base_url, target):
        """Detects when batching is allowed."""
        # Returns array of 5 results
        batch_response = [{"data": {"products": []}} for _ in range(5)]
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(200, json=batch_response)
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        batch_findings = [f for f in result.findings if "BATCH" in f.id]
        assert len(batch_findings) == 1
        assert batch_findings[0].severity == Severity.MEDIUM

    @respx.mock
    async def test_batching_disabled(self, base_url, target):
        """No finding when batching is disabled."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                400,
                json={"errors": [{"message": "Batching is not supported"}]}
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        batch_findings = [f for f in result.findings if "BATCH" in f.id]
        assert len(batch_findings) == 0


class TestGraphQLFieldSuggestions:
    """Tests for G04 - Field suggestions."""

    @respx.mock
    async def test_detects_field_suggestions(self, base_url, target):
        """Detects field suggestions in errors."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "errors": [{
                        "message": "Cannot query field 'userna' on type 'User'. Did you mean 'username'?"
                    }]
                }
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        suggest_findings = [f for f in result.findings if "SUGGEST" in f.id]
        assert len(suggest_findings) == 1
        assert suggest_findings[0].severity == Severity.LOW

    @respx.mock
    async def test_no_field_suggestions(self, base_url, target):
        """No finding when suggestions are disabled."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={"errors": [{"message": "Unknown field"}]}
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        suggest_findings = [f for f in result.findings if "SUGGEST" in f.id]
        assert len(suggest_findings) == 0


class TestGraphQLAuthBypass:
    """Tests for G05 - Authorization bypass."""

    @respx.mock
    async def test_detects_auth_bypass(self, base_url, target, graphql_users_response):
        """Detects sensitive data accessible without auth."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(200, json=graphql_users_response)
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        auth_findings = [f for f in result.findings if "AUTH" in f.id]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_no_bypass_auth_required(self, base_url, target):
        """No finding when auth is required."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={"errors": [{"message": "Authentication required"}]}
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        auth_findings = [f for f in result.findings if "AUTH" in f.id]
        assert len(auth_findings) == 0

    @respx.mock
    async def test_no_bypass_no_sensitive_data(self, base_url, target):
        """No finding when data doesn't contain sensitive fields."""
        respx.post(f"{base_url}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "users": [
                            {"id": 1, "username": "admin"},
                            {"id": 2, "username": "user"},
                        ]
                    }
                }
            )
        )

        with httpx.Client() as client:
            scanner = GraphQLScanner(client)
            result = await scanner.scan(target)

        auth_findings = [f for f in result.findings if "AUTH" in f.id]
        assert len(auth_findings) == 0
