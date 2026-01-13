"""Excessive Data Exposure scanner (V03)."""

from src.core import (
    Scanner, ScanResult, Finding, Severity, Target, get_logger,
    is_sensitive_field, detect_sensitive_data,
)

logger = get_logger("scanners.exposure")


class DataExposureScanner(Scanner):
    """Scan for Excessive Data Exposure (V03).

    Detects when API responses contain more data than necessary,
    including internal fields, sensitive data, and implementation details.
    """

    name = "DataExposureScanner"
    description = "Detects excessive data exposure (V03)"

    # Fields that should not be exposed in public API responses
    SENSITIVE_FIELDS = [
        # Personal Identifiable Information
        "ssn", "social_security", "national_id",
        "credit_card", "creditCard", "card_number",
        "cvv", "cvc", "card_security",

        # Authentication data
        "password", "password_hash", "passwordHash", "hashed_password",
        "secret", "secret_key", "secretKey",
        "api_key", "apiKey", "access_key",
        "token", "auth_token", "refresh_token",

        # Internal data
        "internal_notes", "internalNotes", "internal_id",
        "supplier_cost", "supplierCost", "cost_price",
        "margin", "profit_margin",

        # Debug/system info
        "debug", "trace", "stack_trace",
        "query", "sql_query", "_raw",
    ]

    # Field patterns that suggest internal/debug data
    INTERNAL_PATTERNS = [
        "_id", "_internal", "_debug", "_raw",
        "__", "private_", "internal_",
    ]

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Test common endpoints without authentication
        await self._check_users_endpoint(target, result)
        await self._check_products_endpoint(target, result)

        # Test with authentication if available
        if target.valid_username and target.valid_password:
            token = await self._get_token(target)
            if token:
                await self._check_authenticated_endpoints(target, token, result)

        return result

    async def _get_token(self, target: Target) -> str | None:
        """Get auth token."""
        try:
            resp = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                json={"username": target.valid_username, "password": target.valid_password},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception:
            pass

        try:
            resp = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                data={"username": target.valid_username, "password": target.valid_password},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception:
            pass

        return None

    async def _check_users_endpoint(self, target: Target, result: ScanResult):
        """Check /api/users for data exposure."""
        try:
            resp = self.client.get(f"{target.base_url}/api/users")
            if resp.status_code == 200:
                users = resp.json()
                if isinstance(users, list) and users:
                    exposed = self._find_sensitive_fields(users[0])
                    if exposed:
                        result.add_finding(Finding(
                            id="V03-EXPOSURE-USERS",
                            name="Excessive Data Exposure in User List",
                            severity=Severity.HIGH,
                            description="User list endpoint exposes sensitive fields",
                            endpoint="/api/users",
                            evidence=f"Exposed sensitive fields: {exposed}",
                            remediation="Filter response to only include necessary public fields. Use DTOs or serializers.",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                        ))
        except Exception as e:
            logger.debug(f"Users endpoint check failed: {e}")

    async def _check_products_endpoint(self, target: Target, result: ScanResult):
        """Check /api/products for internal data exposure."""
        try:
            resp = self.client.get(f"{target.base_url}/api/products")
            if resp.status_code == 200:
                products = resp.json()
                if isinstance(products, list) and products:
                    exposed = self._find_sensitive_fields(products[0])
                    if exposed:
                        result.add_finding(Finding(
                            id="V03-EXPOSURE-PRODUCTS",
                            name="Internal Data Exposed in Products",
                            severity=Severity.MEDIUM,
                            description="Product endpoint exposes internal business data",
                            endpoint="/api/products",
                            evidence=f"Exposed internal fields: {exposed}",
                            remediation="Remove internal fields (cost, margins, notes) from public responses",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                        ))
        except Exception as e:
            logger.debug(f"Products endpoint check failed: {e}")

    async def _check_authenticated_endpoints(self, target: Target, token: str, result: ScanResult):
        """Check authenticated endpoints for data exposure."""
        headers = {"Authorization": f"Bearer {token}"}

        try:
            # Check /api/me or similar
            for endpoint in ["/api/me", "/api/users/me", "/api/profile"]:
                resp = self.client.get(f"{target.base_url}{endpoint}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    # Check for password hash exposure (critical)
                    if data.get("password_hash") or data.get("passwordHash"):
                        result.add_finding(Finding(
                            id="V03-EXPOSURE-PWHASH",
                            name="Password Hash Exposed",
                            severity=Severity.CRITICAL,
                            description="API returns password hash to authenticated user",
                            endpoint=endpoint,
                            evidence="password_hash field present in response",
                            remediation="Never include password hashes in API responses",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                        ))
                    break
        except Exception as e:
            logger.debug(f"Authenticated endpoint check failed: {e}")

    def _find_sensitive_fields(self, obj: dict) -> list[str]:
        """Find sensitive fields in an object using robust pattern matching."""
        if not isinstance(obj, dict):
            return []

        exposed = []
        for field, value in obj.items():
            # Use pattern-based detection for field names
            if is_sensitive_field(field):
                if value is not None:
                    exposed.append(field)
                continue

            # Check against known sensitive fields (fallback)
            field_lower = field.lower()
            if any(sensitive in field_lower for sensitive in self.SENSITIVE_FIELDS):
                if value is not None:
                    exposed.append(field)
                continue

            # Check for internal field patterns
            if any(pattern in field_lower for pattern in self.INTERNAL_PATTERNS):
                if value is not None:
                    exposed.append(field)
                continue

            # Check if field value contains sensitive data patterns
            if value and isinstance(value, str):
                detections = detect_sensitive_data(value)
                for detection in detections:
                    if detection.confidence >= 0.8:
                        exposed.append(f"{field} (contains {detection.pattern_name})")
                        break

        return exposed
