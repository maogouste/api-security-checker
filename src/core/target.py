"""Target configuration."""

from dataclasses import dataclass, field
from typing import Optional
import yaml


@dataclass
class Target:
    """Scan target configuration."""
    base_url: str
    name: str = "Unknown"
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"
    headers: dict[str, str] = field(default_factory=dict)

    # Credentials for auth testing
    valid_username: Optional[str] = None
    valid_password: Optional[str] = None
    login_endpoint: str = "/api/login"

    # Known endpoints
    endpoints: list[str] = field(default_factory=list)

    # GraphQL
    graphql_endpoint: Optional[str] = None

    # SSL verification (default: True for security)
    verify_ssl: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "Target":
        """Load target from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        """Create target from dictionary."""
        return cls(**data)

    def get_auth_header(self) -> dict[str, str]:
        """Get authorization header."""
        if self.auth_token:
            return {self.auth_header: f"{self.auth_prefix} {self.auth_token}"}
        return {}

    def get_headers(self) -> dict[str, str]:
        """Get all headers including auth."""
        headers = {"Content-Type": "application/json"}
        headers.update(self.headers)
        headers.update(self.get_auth_header())
        return headers
