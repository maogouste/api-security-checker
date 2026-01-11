"""BOLA (Broken Object Level Authorization) scanner."""

from src.core import Scanner, ScanResult, Finding, Severity, Target


class BOLAScanner(Scanner):
    """Scan for Broken Object Level Authorization (V01)."""

    name = "BOLAScanner"
    description = "Detects BOLA/IDOR vulnerabilities (V01)"

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Need auth to test BOLA
        if not target.valid_username or not target.valid_password:
            result.add_error("Credentials required for BOLA testing")
            return result

        # Login first
        token = await self._get_token(target)
        if not token:
            result.add_error("Could not authenticate for BOLA testing")
            return result

        # Test user endpoints
        await self._check_user_bola(target, token, result)

        return result

    async def _get_token(self, target: Target) -> str | None:
        """Get auth token."""
        # Try JSON first (Express, Go, PHP, Java)
        try:
            resp = self.client.post(
                f"{target.base_url}{target.login_endpoint}",
                json={"username": target.valid_username, "password": target.valid_password},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception:
            pass

        # Try form data (FastAPI OAuth2)
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

    async def _check_user_bola(self, target: Target, token: str, result: ScanResult):
        """Check if user can access other users' data."""
        headers = {"Authorization": f"Bearer {token}"}

        try:
            # Get current user info
            me_resp = self.client.get(
                f"{target.base_url}/api/users/me",
                headers=headers,
            )
            if me_resp.status_code != 200:
                return

            my_id = me_resp.json().get("id")

            # Try to access other user IDs
            test_ids = [1, 2, 3, my_id - 1 if my_id and my_id > 1 else 999]

            for test_id in test_ids:
                if test_id == my_id:
                    continue

                resp = self.client.get(
                    f"{target.base_url}/api/users/{test_id}",
                    headers=headers,
                )

                if resp.status_code == 200:
                    other_user = resp.json()
                    # Check if we got sensitive data
                    sensitive_fields = ["ssn", "credit_card", "creditCard", "secret_note", "api_key"]
                    exposed = [f for f in sensitive_fields if other_user.get(f)]

                    result.add_finding(Finding(
                        id="V01-BOLA",
                        name="Broken Object Level Authorization",
                        severity=Severity.HIGH,
                        description=f"User {my_id} can access data of user {test_id}",
                        endpoint=f"/api/users/{test_id}",
                        evidence=f"Exposed fields: {exposed}" if exposed else f"Full user object returned for user {test_id}",
                        remediation="Verify that authenticated user has permission to access the requested resource",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                    ))
                    break  # One finding is enough

        except Exception as e:
            result.add_error(f"BOLA check failed: {e}")
