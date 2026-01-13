"""Training mode for interactive learning with VulnAPI."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

import httpx
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core import Target, ScanResult, get_logger
from src.scanners import (
    AuthScanner,
    BOLAScanner,
    InjectionScanner,
    GraphQLScanner,
    HeadersScanner,
)

console = Console()
logger = get_logger("training")


class Difficulty(str, Enum):
    """Challenge difficulty levels."""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


@dataclass
class Challenge:
    """A security challenge."""
    id: str
    name: str
    description: str
    difficulty: Difficulty
    scanner_type: str
    vulnerability_id: str
    hints: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    learning_objectives: List[str] = field(default_factory=list)


@dataclass
class LearningPath:
    """A learning path containing multiple challenges."""
    id: str
    name: str
    description: str
    challenges: List[str]  # Challenge IDs
    prerequisites: List[str] = field(default_factory=list)


# Default challenges mapping to VulnAPI vulnerabilities
DEFAULT_CHALLENGES: Dict[str, Challenge] = {
    "V01": Challenge(
        id="V01",
        name="Broken Object Level Authorization (BOLA)",
        description="Access another user's data by manipulating object IDs",
        difficulty=Difficulty.EASY,
        scanner_type="bola",
        vulnerability_id="V01-BOLA",
        hints=[
            "Try accessing /api/users/2 when logged in as user 1",
            "Check if the API validates ownership of resources",
        ],
        resources=[
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        learning_objectives=[
            "Understand IDOR vulnerabilities",
            "Learn to test authorization controls",
        ],
    ),
    "V02": Challenge(
        id="V02",
        name="Broken Authentication",
        description="Exploit weak authentication mechanisms",
        difficulty=Difficulty.EASY,
        scanner_type="auth",
        vulnerability_id="V02-AUTH",
        hints=[
            "Check for user enumeration via different error messages",
            "Look at JWT token structure and algorithm",
            "Test for rate limiting on login endpoint",
        ],
        resources=[
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        ],
        learning_objectives=[
            "Identify authentication weaknesses",
            "Understand JWT security",
        ],
    ),
    "V03": Challenge(
        id="V03",
        name="Excessive Data Exposure",
        description="Find sensitive data exposed in API responses",
        difficulty=Difficulty.EASY,
        scanner_type="bola",
        vulnerability_id="V03-DATA",
        hints=[
            "Check the response fields for sensitive information",
            "Look for SSN, credit card, or internal notes",
        ],
        resources=[
            "https://owasp.org/API-Security/editions/2023/en/0xa3-excessive-data-exposure/",
        ],
        learning_objectives=[
            "Identify sensitive data in responses",
            "Understand data minimization principles",
        ],
    ),
    "V06": Challenge(
        id="V06",
        name="SQL Injection",
        description="Exploit SQL injection in search parameters",
        difficulty=Difficulty.MEDIUM,
        scanner_type="injection",
        vulnerability_id="V06-SQLI",
        hints=[
            "Try the search parameter with a single quote",
            "Use UNION SELECT to extract data",
            "Try boolean-based blind injection",
        ],
        resources=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
        learning_objectives=[
            "Understand SQL injection types",
            "Learn to craft injection payloads",
        ],
    ),
    "V07": Challenge(
        id="V07",
        name="Command Injection",
        description="Execute OS commands via vulnerable endpoints",
        difficulty=Difficulty.HARD,
        scanner_type="injection",
        vulnerability_id="V07-CMDI",
        hints=[
            "Try the ping endpoint with command separators",
            "Use ; | & or backticks to chain commands",
            "Try to read /etc/passwd",
        ],
        resources=[
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
        learning_objectives=[
            "Understand command injection vectors",
            "Learn to chain OS commands",
        ],
    ),
    "V08": Challenge(
        id="V08",
        name="Security Misconfiguration",
        description="Find security misconfigurations in the API",
        difficulty=Difficulty.EASY,
        scanner_type="headers",
        vulnerability_id="V08-MISCONFIG",
        hints=[
            "Check for missing security headers",
            "Look for debug endpoints",
            "Check CORS configuration",
        ],
        resources=[
            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        ],
        learning_objectives=[
            "Identify security header issues",
            "Understand secure configuration",
        ],
    ),
    "G01": Challenge(
        id="G01",
        name="GraphQL Introspection",
        description="Exploit enabled introspection to discover schema",
        difficulty=Difficulty.EASY,
        scanner_type="graphql",
        vulnerability_id="G01-INTROSPECTION",
        hints=[
            "Send __schema query to discover types",
            "Look for sensitive fields in the schema",
        ],
        resources=[
            "https://graphql.org/learn/introspection/",
        ],
        learning_objectives=[
            "Understand GraphQL introspection",
            "Learn to enumerate GraphQL schemas",
        ],
    ),
    "G02": Challenge(
        id="G02",
        name="GraphQL Depth Limit",
        description="Exploit missing query depth limits",
        difficulty=Difficulty.MEDIUM,
        scanner_type="graphql",
        vulnerability_id="G02-DEPTH",
        hints=[
            "Create deeply nested queries",
            "Try to cause resource exhaustion",
        ],
        resources=[
            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
        ],
        learning_objectives=[
            "Understand GraphQL DoS vectors",
            "Learn query complexity limits",
        ],
    ),
}

# Default learning paths
DEFAULT_PATHS: Dict[str, LearningPath] = {
    "beginner": LearningPath(
        id="beginner",
        name="API Security Fundamentals",
        description="Learn basic API vulnerabilities",
        challenges=["V01", "V03", "V02", "V08"],
    ),
    "intermediate": LearningPath(
        id="intermediate",
        name="Injection Attacks",
        description="Master injection vulnerabilities",
        challenges=["V06", "V07"],
        prerequisites=["beginner"],
    ),
    "graphql": LearningPath(
        id="graphql",
        name="GraphQL Security",
        description="Secure GraphQL APIs",
        challenges=["G01", "G02"],
        prerequisites=["beginner"],
    ),
}


class TrainingMode:
    """Interactive training mode with VulnAPI."""

    def __init__(
        self,
        target_url: str = "http://localhost:8000",
        config_path: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.challenges = DEFAULT_CHALLENGES.copy()
        self.paths = DEFAULT_PATHS.copy()
        self.completed: List[str] = []
        self.client: Optional[httpx.Client] = None

        if config_path:
            self._load_config(config_path)

    def _load_config(self, config_path: str) -> None:
        """Load custom challenges from YAML."""
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
                # Load custom challenges
                for ch_data in data.get("challenges", []):
                    ch = Challenge(
                        id=ch_data["id"],
                        name=ch_data["name"],
                        description=ch_data.get("description", ""),
                        difficulty=Difficulty(ch_data.get("difficulty", "medium")),
                        scanner_type=ch_data["scanner_type"],
                        vulnerability_id=ch_data.get("vulnerability_id", ch_data["id"]),
                        hints=ch_data.get("hints", []),
                        resources=ch_data.get("resources", []),
                        learning_objectives=ch_data.get("learning_objectives", []),
                    )
                    self.challenges[ch.id] = ch

    def _get_scanner(self, scanner_type: str, client: httpx.Client):
        """Get scanner instance by type."""
        scanners = {
            "auth": AuthScanner,
            "bola": BOLAScanner,
            "injection": InjectionScanner,
            "graphql": GraphQLScanner,
            "headers": HeadersScanner,
        }
        scanner_class = scanners.get(scanner_type)
        if scanner_class:
            return scanner_class(client)
        return None

    async def _get_flag(self, challenge_id: str) -> Optional[str]:
        """Try to get flag from VulnAPI for completed challenge."""
        try:
            # Login first
            login_resp = self.client.post(
                f"{self.target_url}/api/login",
                data={"username": "admin", "password": "admin123"},
            )
            if login_resp.status_code != 200:
                return None

            token = login_resp.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}

            # Try to get flag
            flag_resp = self.client.post(
                f"{self.target_url}/api/flags/submit",
                json={"vulnerability_id": challenge_id},
                headers=headers,
            )
            if flag_resp.status_code == 200:
                return flag_resp.json().get("flag")
        except Exception as e:
            logger.debug(f"Failed to get flag: {e}")
        return None

    async def run_challenge(self, challenge_id: str) -> bool:
        """
        Run a specific challenge and provide feedback.

        Returns True if vulnerability was detected.
        """
        challenge = self.challenges.get(challenge_id.upper())
        if not challenge:
            console.print(f"[red]Unknown challenge: {challenge_id}[/red]")
            console.print(f"Available: {', '.join(self.challenges.keys())}")
            return False

        # Display challenge info
        console.print()
        console.print(Panel(
            f"[bold]{challenge.name}[/bold]\n\n"
            f"{challenge.description}\n\n"
            f"[dim]Difficulty: {challenge.difficulty.value}[/dim]",
            title=f"Challenge {challenge.id}",
            border_style="blue",
        ))

        # Show learning objectives
        if challenge.learning_objectives:
            console.print("\n[bold]Learning Objectives:[/bold]")
            for obj in challenge.learning_objectives:
                console.print(f"  • {obj}")

        console.print("\n[dim]Running scanner...[/dim]\n")

        # Create target
        target = Target(
            base_url=self.target_url,
            name="VulnAPI",
            valid_username="admin",
            valid_password="admin123",
            login_endpoint="/api/login",
            graphql_endpoint="/graphql",
        )

        # Get and run scanner
        with httpx.Client(timeout=10) as client:
            self.client = client
            scanner = self._get_scanner(challenge.scanner_type, client)
            if not scanner:
                console.print(f"[red]Scanner not found: {challenge.scanner_type}[/red]")
                return False

            result = await scanner.scan(target)

        # Check results
        found = False
        for finding in result.findings:
            if challenge.vulnerability_id in finding.id:
                found = True
                break

        if found:
            console.print("[bold green]✓ VULNERABILITY DETECTED![/bold green]\n")

            # Try to get flag
            flag = await self._get_flag(challenge.id)
            if flag:
                console.print(f"[bold cyan]Flag: {flag}[/bold cyan]\n")

            self.completed.append(challenge.id)
            console.print("[green]Challenge completed![/green]")
        else:
            console.print("[bold yellow]✗ Vulnerability not detected[/bold yellow]\n")
            console.print("[dim]The scanner didn't find the vulnerability.")
            console.print("This could mean:[/dim]")
            console.print("  • The vulnerability requires manual testing")
            console.print("  • Try the hints below\n")

            # Show hints
            if challenge.hints:
                console.print("[bold]Hints:[/bold]")
                for i, hint in enumerate(challenge.hints, 1):
                    console.print(f"  {i}. {hint}")

        # Show resources
        if challenge.resources:
            console.print("\n[bold]Resources:[/bold]")
            for res in challenge.resources:
                console.print(f"  • {res}")

        return found

    async def run_all(self) -> Dict[str, bool]:
        """Run all challenges and return results."""
        results = {}

        console.print(Panel(
            "[bold]Running all challenges...[/bold]",
            border_style="blue",
        ))

        for challenge_id in self.challenges:
            console.print(f"\n{'='*60}\n")
            results[challenge_id] = await self.run_challenge(challenge_id)

        # Summary
        console.print(f"\n{'='*60}\n")
        self._print_summary(results)

        return results

    async def run_path(self, path_id: str) -> Dict[str, bool]:
        """Run all challenges in a learning path."""
        path = self.paths.get(path_id)
        if not path:
            console.print(f"[red]Unknown path: {path_id}[/red]")
            console.print(f"Available: {', '.join(self.paths.keys())}")
            return {}

        console.print(Panel(
            f"[bold]{path.name}[/bold]\n\n{path.description}",
            title=f"Learning Path: {path_id}",
            border_style="green",
        ))

        results = {}
        for challenge_id in path.challenges:
            console.print(f"\n{'='*60}\n")
            results[challenge_id] = await self.run_challenge(challenge_id)

        # Summary
        console.print(f"\n{'='*60}\n")
        self._print_summary(results)

        return results

    def _print_summary(self, results: Dict[str, bool]) -> None:
        """Print challenge results summary."""
        table = Table(title="Challenge Results")
        table.add_column("Challenge", style="cyan")
        table.add_column("Name")
        table.add_column("Difficulty")
        table.add_column("Status")

        for ch_id, detected in results.items():
            challenge = self.challenges.get(ch_id)
            if challenge:
                status = "[green]✓ Detected[/green]" if detected else "[yellow]✗ Manual[/yellow]"
                table.add_row(
                    ch_id,
                    challenge.name,
                    challenge.difficulty.value,
                    status,
                )

        console.print(table)

        detected = sum(1 for v in results.values() if v)
        total = len(results)
        console.print(f"\n[bold]Score: {detected}/{total} detected automatically[/bold]")

    def list_challenges(self) -> None:
        """List all available challenges."""
        table = Table(title="Available Challenges")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Difficulty")
        table.add_column("Scanner")

        for ch in sorted(self.challenges.values(), key=lambda x: x.id):
            diff_color = {
                Difficulty.EASY: "green",
                Difficulty.MEDIUM: "yellow",
                Difficulty.HARD: "red",
                Difficulty.EXPERT: "magenta",
            }.get(ch.difficulty, "white")

            table.add_row(
                ch.id,
                ch.name,
                f"[{diff_color}]{ch.difficulty.value}[/{diff_color}]",
                ch.scanner_type,
            )

        console.print(table)

    def list_paths(self) -> None:
        """List all available learning paths."""
        table = Table(title="Learning Paths")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Challenges")
        table.add_column("Prerequisites")

        for path in self.paths.values():
            table.add_row(
                path.id,
                path.name,
                ", ".join(path.challenges),
                ", ".join(path.prerequisites) if path.prerequisites else "-",
            )

        console.print(table)
