"""Payload management for security testing."""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml


class PayloadManager:
    """
    Manages security testing payloads from YAML configuration.

    Payloads can be loaded from:
    1. Custom config file specified at init
    2. Default config/payloads.yaml in project root
    3. Built-in default payloads
    """

    _instance: Optional["PayloadManager"] = None
    _payloads: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[str] = None):
        """Singleton pattern for payload manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_payloads(config_path)
        return cls._instance

    def _load_payloads(self, config_path: Optional[str] = None) -> None:
        """Load payloads from YAML file or use defaults."""
        # Try to find config file
        paths_to_try = []

        if config_path:
            paths_to_try.append(Path(config_path))

        # Project root config
        paths_to_try.append(Path(__file__).parent.parent.parent / "config" / "payloads.yaml")

        # Current directory
        paths_to_try.append(Path.cwd() / "config" / "payloads.yaml")
        paths_to_try.append(Path.cwd() / "payloads.yaml")

        for path in paths_to_try:
            if path.exists():
                with open(path, "r") as f:
                    self._payloads = yaml.safe_load(f) or {}
                return

        # Use built-in defaults
        self._payloads = self._default_payloads()

    def _default_payloads(self) -> Dict[str, Any]:
        """Return built-in default payloads."""
        return {
            "sql_injection": {
                "error_based": ["'", "''", "' OR '1'='1", "' OR '1'='1'--"],
                "union_based": ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
                "time_based": ["' AND SLEEP(5)--"],
                "boolean_based": ["' AND '1'='1", "' AND '1'='2"],
            },
            "command_injection": {
                "basic": ["; id", "| id", "& id", "$(id)", "`id`"],
                "file_read": ["; cat /etc/passwd", "| cat /etc/passwd"],
                "blind": ["; sleep 5", "| sleep 5"],
            },
            "graphql": {
                "introspection": ["__schema { types { name } }"],
                "depth_test_levels": [5, 10, 20],
                "batch_sizes": [5, 10],
            },
            "authentication": {
                "weak_passwords": ["password", "123456", "admin"],
                "jwt_none_algorithms": ["none", "None", "NONE"],
            },
            "headers": {
                "security_required": [
                    "Strict-Transport-Security",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Content-Security-Policy",
                ],
                "sensitive_exposed": ["Server", "X-Powered-By"],
            },
            "files": {
                "sensitive": [".git/HEAD", ".env", "config.php"],
                "backups": ["backup.sql", "database.sql"],
            },
            "endpoints": {
                "admin": ["/admin", "/wp-admin"],
                "api": ["/api", "/graphql", "/swagger"],
                "debug": ["/debug", "/actuator", "/health"],
            },
        }

    def get(self, category: str, subcategory: Optional[str] = None) -> List[Any]:
        """
        Get payloads for a category.

        Args:
            category: Main category (e.g., 'sql_injection', 'command_injection')
            subcategory: Optional subcategory (e.g., 'error_based', 'basic')

        Returns:
            List of payloads. If subcategory is None, returns all payloads
            from all subcategories in the category.
        """
        data = self._payloads.get(category, {})

        if not data:
            return []

        if subcategory:
            result = data.get(subcategory, [])
            return result if isinstance(result, list) else [result]

        # Flatten all subcategories
        all_payloads = []
        for key, value in data.items():
            if isinstance(value, list):
                all_payloads.extend(value)
            else:
                all_payloads.append(value)

        return all_payloads

    def get_all(self, category: str) -> Dict[str, List[Any]]:
        """Get all subcategories for a category."""
        return self._payloads.get(category, {})

    def categories(self) -> List[str]:
        """List all available categories."""
        return list(self._payloads.keys())

    def reload(self, config_path: Optional[str] = None) -> None:
        """Reload payloads from file."""
        self._load_payloads(config_path)


# Convenience function
def get_payloads(category: str, subcategory: Optional[str] = None) -> List[Any]:
    """Get payloads using default manager."""
    manager = PayloadManager()
    return manager.get(category, subcategory)
