"""Tests for reconnaissance scanners (Endpoints and KnownFiles)."""

import pytest
import httpx
import respx

from src.core import Severity
from src.scanners import EndpointsScanner, KnownFilesScanner


class TestEndpointsScanner:
    """Tests for endpoint discovery scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = EndpointsScanner(client)
        assert scanner.name == "EndpointsScanner"

    def test_endpoints_defined(self, mock_client):
        """Endpoints to check are defined."""
        client, _ = mock_client
        scanner = EndpointsScanner(client)
        assert "/admin" in scanner.ENDPOINTS
        assert "/debug" in scanner.ENDPOINTS
        assert "/actuator" in scanner.ENDPOINTS

    @respx.mock
    async def test_detects_admin_panel(self, base_url, target):
        """Detects exposed admin panel."""
        # Admin endpoint accessible
        respx.get(f"{base_url}/admin").mock(
            return_value=httpx.Response(200, text="Admin Panel")
        )
        # Other endpoints return 404
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = EndpointsScanner(client)
            result = await scanner.scan(target)

        admin_findings = [f for f in result.findings if "admin" in f.endpoint.lower()]
        assert len(admin_findings) >= 1
        assert admin_findings[0].severity == Severity.HIGH

    @respx.mock
    async def test_detects_debug_endpoint(self, base_url, target):
        """Detects exposed debug endpoint."""
        respx.get(f"{base_url}/debug").mock(
            return_value=httpx.Response(200, text="Debug Info")
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = EndpointsScanner(client)
            result = await scanner.scan(target)

        debug_findings = [f for f in result.findings if "debug" in f.endpoint.lower()]
        assert len(debug_findings) >= 1

    @respx.mock
    async def test_detects_protected_endpoint(self, base_url, target):
        """Detects endpoints that exist but require auth."""
        respx.get(f"{base_url}/admin").mock(
            return_value=httpx.Response(401, json={"detail": "Unauthorized"})
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = EndpointsScanner(client)
            result = await scanner.scan(target)

        # Should find protected endpoint with INFO severity
        protected = [f for f in result.findings if "Protected" in f.name]
        assert len(protected) >= 1
        assert protected[0].severity == Severity.INFO

    @respx.mock
    async def test_detects_database_interface(self, base_url, target):
        """Detects exposed database interfaces."""
        respx.get(f"{base_url}/phpmyadmin").mock(
            return_value=httpx.Response(200, text="phpMyAdmin")
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = EndpointsScanner(client)
            result = await scanner.scan(target)

        db_findings = [f for f in result.findings if "phpmyadmin" in f.endpoint.lower()]
        assert len(db_findings) >= 1
        assert db_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_no_findings_all_404(self, base_url, target):
        """No findings when all endpoints return 404."""
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = EndpointsScanner(client)
            result = await scanner.scan(target)

        assert len(result.findings) == 0


class TestKnownFilesScanner:
    """Tests for known files scanner."""

    def test_scanner_name(self, mock_client):
        """Scanner has correct name."""
        client, _ = mock_client
        scanner = KnownFilesScanner(client)
        assert scanner.name == "KnownFilesScanner"

    def test_known_files_defined(self, mock_client):
        """Known files to check are defined."""
        client, _ = mock_client
        scanner = KnownFilesScanner(client)
        assert ".env" in scanner.KNOWN_FILES
        assert ".git/HEAD" in scanner.KNOWN_FILES
        assert "backup.sql" in scanner.KNOWN_FILES

    @respx.mock
    async def test_detects_env_file(self, base_url, target):
        """Detects exposed .env file."""
        respx.get(f"{base_url}/.env").mock(
            return_value=httpx.Response(
                200,
                text="DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=mysecret",
                headers={"Content-Type": "text/plain"},
            )
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        env_findings = [f for f in result.findings if ".env" in f.endpoint]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_detects_git_directory(self, base_url, target):
        """Detects exposed .git directory."""
        # Content must be > 50 bytes to not be filtered as too small
        git_content = "ref: refs/heads/main\n" + "x" * 50
        respx.get(f"{base_url}/.git/HEAD").mock(
            return_value=httpx.Response(
                200,
                text=git_content,
                headers={"Content-Type": "text/plain"},
            )
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        git_findings = [f for f in result.findings if ".git" in f.endpoint]
        assert len(git_findings) >= 1
        assert git_findings[0].severity == Severity.HIGH

    @respx.mock
    async def test_detects_sql_backup(self, base_url, target):
        """Detects exposed SQL backup."""
        # Content must be > 50 bytes
        sql_content = "-- MySQL dump\nCREATE TABLE users (id INT, username VARCHAR(255));\n" + "x" * 50
        respx.get(f"{base_url}/backup.sql").mock(
            return_value=httpx.Response(
                200,
                text=sql_content,
                headers={"Content-Type": "application/sql"},
            )
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        backup_findings = [f for f in result.findings if "backup" in f.endpoint]
        assert len(backup_findings) >= 1
        assert backup_findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_ignores_error_pages(self, base_url, target):
        """Ignores HTML error pages that return 200."""
        respx.get(f"{base_url}/.env").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>404 Not Found</body></html>",
                headers={"Content-Type": "text/html"},
            )
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        env_findings = [f for f in result.findings if ".env" in f.endpoint]
        assert len(env_findings) == 0

    @respx.mock
    async def test_ignores_small_files(self, base_url, target):
        """Ignores very small responses (likely empty/error)."""
        respx.get(f"{base_url}/.env").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        env_findings = [f for f in result.findings if ".env" in f.endpoint]
        assert len(env_findings) == 0

    @respx.mock
    async def test_no_findings_all_404(self, base_url, target):
        """No findings when all files return 404."""
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        with httpx.Client() as client:
            scanner = KnownFilesScanner(client)
            result = await scanner.scan(target)

        assert len(result.findings) == 0
