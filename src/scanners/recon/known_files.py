"""Known files scanner - checks for exposed sensitive files."""

from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.files")


class KnownFilesScanner(Scanner):
    """Scan for exposed sensitive files."""

    name = "KnownFilesScanner"
    description = "Detects exposed sensitive files (.env, .git, backups, etc.)"

    KNOWN_FILES = {
        # Environment files
        ".env": ("Environment variables", Severity.CRITICAL),
        ".env.local": ("Local environment variables", Severity.CRITICAL),
        ".env.production": ("Production environment", Severity.CRITICAL),
        ".env.development": ("Development environment", Severity.HIGH),
        ".env.backup": ("Environment backup", Severity.CRITICAL),

        # Version control
        ".git/HEAD": ("Git repository exposed", Severity.HIGH),
        ".git/config": ("Git configuration", Severity.HIGH),
        ".svn/entries": ("SVN repository exposed", Severity.HIGH),
        ".hg/store": ("Mercurial repository exposed", Severity.HIGH),

        # Config files
        "config.json": ("Configuration file", Severity.HIGH),
        "config.yaml": ("Configuration file", Severity.HIGH),
        "config.yml": ("Configuration file", Severity.HIGH),
        "settings.py": ("Python settings", Severity.HIGH),
        "settings.json": ("Settings file", Severity.HIGH),
        "database.yml": ("Database configuration", Severity.CRITICAL),
        "secrets.json": ("Secrets file", Severity.CRITICAL),
        "credentials.json": ("Credentials file", Severity.CRITICAL),

        # Backups
        "backup.sql": ("SQL backup", Severity.CRITICAL),
        "dump.sql": ("SQL dump", Severity.CRITICAL),
        "database.sql": ("Database export", Severity.CRITICAL),
        "db.sqlite": ("SQLite database", Severity.CRITICAL),
        "data.db": ("Database file", Severity.CRITICAL),

        # Logs
        "debug.log": ("Debug log", Severity.MEDIUM),
        "error.log": ("Error log", Severity.MEDIUM),
        "access.log": ("Access log", Severity.LOW),
        "app.log": ("Application log", Severity.MEDIUM),

        # API documentation (info disclosure)
        "swagger.json": ("Swagger documentation", Severity.LOW),
        "swagger.yaml": ("Swagger documentation", Severity.LOW),
        "openapi.json": ("OpenAPI specification", Severity.LOW),
        "openapi.yaml": ("OpenAPI specification", Severity.LOW),
        "api-docs.json": ("API documentation", Severity.LOW),

        # Package files (can reveal dependencies/versions)
        "package.json": ("Node.js dependencies", Severity.INFO),
        "composer.json": ("PHP dependencies", Severity.INFO),
        "requirements.txt": ("Python dependencies", Severity.INFO),
        "Gemfile": ("Ruby dependencies", Severity.INFO),
        "pom.xml": ("Java/Maven dependencies", Severity.INFO),

        # IDE/Editor files
        ".idea/workspace.xml": ("IntelliJ project", Severity.LOW),
        ".vscode/settings.json": ("VS Code settings", Severity.LOW),

        # Docker
        "docker-compose.yml": ("Docker configuration", Severity.MEDIUM),
        "Dockerfile": ("Dockerfile", Severity.LOW),

        # CI/CD
        ".gitlab-ci.yml": ("GitLab CI config", Severity.MEDIUM),
        ".github/workflows/main.yml": ("GitHub Actions", Severity.LOW),
        "Jenkinsfile": ("Jenkins pipeline", Severity.MEDIUM),

        # Server files
        ".htaccess": ("Apache configuration", Severity.MEDIUM),
        "web.config": ("IIS configuration", Severity.MEDIUM),
        "nginx.conf": ("Nginx configuration", Severity.MEDIUM),
        "server.key": ("SSL private key", Severity.CRITICAL),
        "server.pem": ("SSL certificate", Severity.HIGH),

        # Misc
        ".DS_Store": ("macOS metadata", Severity.LOW),
        "Thumbs.db": ("Windows thumbnails", Severity.LOW),
        "phpinfo.php": ("PHP info page", Severity.MEDIUM),
        "info.php": ("PHP info page", Severity.MEDIUM),
        "test.php": ("Test file", Severity.LOW),
        "adminer.php": ("Adminer DB tool", Severity.HIGH),
    }

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        for file_path, (description, severity) in self.KNOWN_FILES.items():
            await self._check_file(target, file_path, description, severity, result)

        return result

    async def _check_file(
        self,
        target: Target,
        file_path: str,
        description: str,
        severity: Severity,
        result: ScanResult,
    ):
        """Check if a file is accessible."""
        try:
            url = f"{target.base_url}/{file_path}"
            resp = self.client.get(url, follow_redirects=False)

            # Check for successful response
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "").lower()
                content_length = len(resp.content)

                # Skip if it looks like an error page
                if content_length < 50:
                    return
                if "text/html" in content_type and "<html" in resp.text.lower():
                    # Might be a 404 page returning 200
                    if "not found" in resp.text.lower() or "404" in resp.text:
                        return

                # Extract preview
                preview = resp.text[:200].replace("\n", " ") if resp.text else ""

                result.add_finding(Finding(
                    id=f"RECON-FILE-{file_path.replace('/', '-').replace('.', '-').upper()}",
                    name=f"Exposed File: {file_path}",
                    severity=severity,
                    description=description,
                    endpoint=f"/{file_path}",
                    evidence=f"Size: {content_length} bytes\nPreview: {preview}...",
                    remediation="Remove or restrict access to sensitive files",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))

        except Exception as e:
            # File not accessible is expected (good security)
            logger.debug(f"File {file_path} not accessible: {e}")
