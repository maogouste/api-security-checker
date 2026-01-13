"""Tests for PayloadManager."""

import pytest
from pathlib import Path

from src.core.payloads import PayloadManager, get_payloads


class TestPayloadManager:
    """Tests for PayloadManager singleton."""

    def test_singleton_pattern(self):
        """PayloadManager uses singleton pattern."""
        pm1 = PayloadManager()
        pm2 = PayloadManager()
        assert pm1 is pm2

    def test_categories_available(self):
        """PayloadManager has expected categories."""
        pm = PayloadManager()
        categories = pm.categories()

        assert "sql_injection" in categories
        assert "command_injection" in categories
        assert "graphql" in categories

    def test_get_sql_injection_payloads(self):
        """Can retrieve SQL injection payloads."""
        pm = PayloadManager()
        payloads = pm.get("sql_injection")

        assert len(payloads) > 0
        # Check some payloads are present
        payloads_str = " ".join(str(p) for p in payloads)
        assert "OR" in payloads_str or "UNION" in payloads_str

    def test_get_subcategory(self):
        """Can retrieve specific subcategory."""
        pm = PayloadManager()
        error_based = pm.get("sql_injection", "error_based")

        assert len(error_based) > 0
        assert "'" in error_based  # Simple quote is common error-based payload

    def test_get_nonexistent_category(self):
        """Returns empty list for nonexistent category."""
        pm = PayloadManager()
        payloads = pm.get("nonexistent_category")

        assert payloads == []

    def test_get_nonexistent_subcategory(self):
        """Returns empty list for nonexistent subcategory."""
        pm = PayloadManager()
        payloads = pm.get("sql_injection", "nonexistent_subcategory")

        assert payloads == []

    def test_get_all_subcategories(self):
        """Can retrieve all subcategories for a category."""
        pm = PayloadManager()
        all_sqli = pm.get_all("sql_injection")

        assert "error_based" in all_sqli
        assert "union_based" in all_sqli
        assert "time_based" in all_sqli

    def test_command_injection_payloads(self):
        """Command injection payloads are available."""
        pm = PayloadManager()
        payloads = pm.get("command_injection", "basic")

        assert len(payloads) > 0
        assert any("; id" in str(p) or "| id" in str(p) for p in payloads)

    def test_graphql_payloads(self):
        """GraphQL payloads include introspection queries."""
        pm = PayloadManager()
        introspection = pm.get("graphql", "introspection")

        assert len(introspection) > 0
        assert any("__schema" in str(p) for p in introspection)

    def test_headers_security_required(self):
        """Security headers list is available."""
        pm = PayloadManager()
        headers = pm.get("headers", "security_required")

        assert len(headers) > 0
        assert "Strict-Transport-Security" in headers

    def test_files_sensitive(self):
        """Sensitive files list is available."""
        pm = PayloadManager()
        files = pm.get("files", "sensitive")

        assert len(files) > 0
        assert ".env" in files or any(".env" in str(f) for f in files)


class TestGetPayloadsFunction:
    """Tests for convenience get_payloads function."""

    def test_get_payloads_category(self):
        """get_payloads returns payloads for category."""
        payloads = get_payloads("sql_injection")
        assert len(payloads) > 0

    def test_get_payloads_subcategory(self):
        """get_payloads returns payloads for subcategory."""
        payloads = get_payloads("command_injection", "basic")
        assert len(payloads) > 0

    def test_get_payloads_empty(self):
        """get_payloads returns empty list for unknown category."""
        payloads = get_payloads("unknown")
        assert payloads == []
