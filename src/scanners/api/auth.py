"""Authentication vulnerability scanner."""

import base64
import json
from src.core import Scanner, ScanResult, Finding, Severity, Target


class AuthScanner(Scanner):
    """Scan for authentication vulnerabilities."""

    name = "AuthScanner"
    description = "Detects authentication weaknesses (V02, V04)"

    # Common weak JWT secrets to test
    WEAK_SECRETS = [
        "secret",
        "secret123",
        "password",
        "123456",
        "changeme",
        "vulnerable-secret-key-change-in-production",
    ]

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Test 1: User enumeration via login
        await self._check_user_enumeration(target, result)

        # Test 2: Weak JWT secret
        await self._check_weak_jwt(target, result)

        # Test 3: No rate limiting
        await self._check_rate_limiting(target, result)

        return result

    async def _check_user_enumeration(self, target: Target, result: ScanResult):
        """Check if login reveals user existence."""
        try:
            # Try invalid user
            resp1 = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                json={"username": "nonexistent_user_xyz", "password": "wrong"},
            )
            msg1 = resp1.json().get("detail", resp1.json().get("message", ""))

            # Try valid user with wrong password
            if target.valid_username:
                resp2 = self.client.post(
                    f"{target.base_url}{target.login_endpoint}",
                    json={"username": target.valid_username, "password": "wrong_password"},
                )
                msg2 = resp2.json().get("detail", resp2.json().get("message", ""))

                # If messages differ, user enumeration is possible
                if msg1.lower() != msg2.lower() and msg1 and msg2:
                    result.add_finding(Finding(
                        id="V02-ENUM",
                        name="User Enumeration",
                        severity=Severity.MEDIUM,
                        description="Login endpoint reveals whether a username exists through different error messages",
                        endpoint=target.login_endpoint,
                        evidence=f"Invalid user: '{msg1}' vs Valid user wrong password: '{msg2}'",
                        remediation="Use generic error messages like 'Invalid credentials' for all login failures",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                    ))
        except Exception as e:
            result.add_error(f"User enumeration check failed: {e}")

    async def _check_weak_jwt(self, target: Target, result: ScanResult):
        """Check for weak JWT secrets."""
        if not target.valid_username or not target.valid_password:
            return

        try:
            # Login to get a token
            resp = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                json={"username": target.valid_username, "password": target.valid_password},
            )
            if resp.status_code != 200:
                return

            token = resp.json().get("access_token")
            if not token:
                return

            # Decode JWT header and payload (without verification)
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Check if it's HS256 (symmetric, crackable)
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            if header.get("alg") == "HS256":
                result.add_finding(Finding(
                    id="V02-JWT",
                    name="JWT with Symmetric Algorithm",
                    severity=Severity.HIGH,
                    description="JWT uses HS256 symmetric algorithm. If the secret is weak, tokens can be forged.",
                    endpoint=target.login_endpoint,
                    evidence=f"Algorithm: {header.get('alg')}",
                    remediation="Use asymmetric algorithms (RS256) or ensure strong secrets (256+ bits)",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                ))

        except Exception as e:
            result.add_error(f"JWT check failed: {e}")

    async def _check_rate_limiting(self, target: Target, result: ScanResult):
        """Check for rate limiting on login."""
        try:
            blocked = False
            attempts = 10

            for i in range(attempts):
                resp = self.client.post(
                    f"{target.base_url}{target.login_endpoint}",
                    json={"username": "test", "password": f"wrong{i}"},
                )
                if resp.status_code == 429:
                    blocked = True
                    break

            if not blocked:
                result.add_finding(Finding(
                    id="V04-RATE",
                    name="No Rate Limiting on Login",
                    severity=Severity.MEDIUM,
                    description=f"Login endpoint allows {attempts}+ attempts without rate limiting",
                    endpoint=target.login_endpoint,
                    evidence=f"Sent {attempts} requests without being blocked (no 429 response)",
                    remediation="Implement rate limiting (e.g., 5 attempts per minute per IP)",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                ))

        except Exception as e:
            result.add_error(f"Rate limiting check failed: {e}")
