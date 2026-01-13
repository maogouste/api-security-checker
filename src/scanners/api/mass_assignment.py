"""Mass Assignment scanner (V05)."""

from src.core import Scanner, ScanResult, Finding, Severity, Target, get_logger

logger = get_logger("scanners.mass_assignment")


class MassAssignmentScanner(Scanner):
    """Scan for Mass Assignment vulnerabilities (V05).

    Detects when API accepts and applies fields that should be protected,
    such as role, admin status, or internal IDs.
    """

    name = "MassAssignmentScanner"
    description = "Detects mass assignment vulnerabilities (V05)"

    # Fields that should not be user-modifiable
    PROTECTED_FIELDS = {
        "role": ["admin", "superadmin", "root", "administrator"],
        "is_admin": [True, 1, "true", "1"],
        "isAdmin": [True, 1, "true", "1"],
        "admin": [True, 1, "true", "1"],
        "is_active": [False, 0],  # Deactivate other accounts
        "verified": [True, 1],
        "is_verified": [True, 1],
        "permissions": ["*", "admin", "all"],
        "level": [99, 100, "admin"],
        "user_type": ["admin", "superuser"],
        "account_type": ["premium", "enterprise", "admin"],
    }

    async def scan(self, target: Target) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        # Need auth for mass assignment testing
        if not target.valid_username or not target.valid_password:
            result.add_error("Credentials required for mass assignment testing")
            return result

        # Login first
        token = await self._get_token(target)
        if not token:
            result.add_error("Could not authenticate for mass assignment testing")
            return result

        # Get current user info
        user_id = await self._get_user_id(target, token)
        if not user_id:
            result.add_error("Could not determine user ID")
            return result

        # Test mass assignment on user profile
        await self._test_role_escalation(target, token, user_id, result)
        await self._test_protected_fields(target, token, user_id, result)

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

    async def _get_user_id(self, target: Target, token: str) -> int | None:
        """Get current user's ID."""
        headers = {"Authorization": f"Bearer {token}"}

        for endpoint in ["/api/me", "/api/users/me"]:
            try:
                resp = self.client.get(f"{target.base_url}{endpoint}", headers=headers)
                if resp.status_code == 200:
                    return resp.json().get("id")
            except Exception:
                pass

        return None

    async def _test_role_escalation(self, target: Target, token: str, user_id: int, result: ScanResult):
        """Test if role can be escalated via mass assignment."""
        headers = {"Authorization": f"Bearer {token}"}

        # Get original user data
        try:
            resp = self.client.get(f"{target.base_url}/api/users/{user_id}", headers=headers)
            if resp.status_code != 200:
                return
            original_role = resp.json().get("role", "user")
        except Exception:
            return

        # Try to escalate role to admin
        try:
            resp = self.client.put(
                f"{target.base_url}/api/users/{user_id}",
                json={"role": "admin"},
                headers=headers,
            )

            if resp.status_code == 200:
                new_data = resp.json()
                new_role = new_data.get("role")

                if new_role == "admin" and original_role != "admin":
                    result.add_finding(Finding(
                        id="V05-MASS-ROLE",
                        name="Role Escalation via Mass Assignment",
                        severity=Severity.CRITICAL,
                        description="User role can be changed to admin via PUT request",
                        endpoint=f"/api/users/{user_id}",
                        evidence=f"Role changed from '{original_role}' to 'admin'",
                        remediation="Whitelist allowed fields in update operations. Never allow role/permission changes via user-controllable input.",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
                    ))

                    # Reset role back
                    self.client.put(
                        f"{target.base_url}/api/users/{user_id}",
                        json={"role": original_role},
                        headers=headers,
                    )

        except Exception as e:
            logger.debug(f"Role escalation test failed: {e}")

    async def _test_protected_fields(self, target: Target, token: str, user_id: int, result: ScanResult):
        """Test if other protected fields can be modified."""
        headers = {"Authorization": f"Bearer {token}"}

        for field, test_values in self.PROTECTED_FIELDS.items():
            if field == "role":
                continue  # Already tested

            for test_value in test_values[:1]:  # Test first value only
                try:
                    # Get original value
                    resp = self.client.get(f"{target.base_url}/api/users/{user_id}", headers=headers)
                    if resp.status_code != 200:
                        continue
                    original = resp.json().get(field)

                    # Try to modify
                    resp = self.client.put(
                        f"{target.base_url}/api/users/{user_id}",
                        json={field: test_value},
                        headers=headers,
                    )

                    if resp.status_code == 200:
                        new_data = resp.json()
                        new_value = new_data.get(field)

                        if new_value == test_value and original != test_value:
                            result.add_finding(Finding(
                                id=f"V05-MASS-{field.upper()}",
                                name=f"Mass Assignment: {field}",
                                severity=Severity.HIGH,
                                description=f"Protected field '{field}' can be modified via mass assignment",
                                endpoint=f"/api/users/{user_id}",
                                evidence=f"Field '{field}' changed to '{test_value}'",
                                remediation=f"Prevent modification of '{field}' field via user input",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
                            ))

                            # Reset field
                            if original is not None:
                                self.client.put(
                                    f"{target.base_url}/api/users/{user_id}",
                                    json={field: original},
                                    headers=headers,
                                )
                            break

                except Exception as e:
                    logger.debug(f"Protected field test for {field} failed: {e}")
