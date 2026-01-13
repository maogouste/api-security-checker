"""Shared test fixtures for API Security Checker."""

import pytest
import httpx
import respx

from src.core import Target


@pytest.fixture
def base_url():
    """Base URL for testing."""
    return "http://testserver:8000"


@pytest.fixture
def target(base_url):
    """Create a test target configuration."""
    return Target(
        base_url=base_url,
        name="TestTarget",
        valid_username="testuser",
        valid_password="testpass123",
        login_endpoint="/api/login",
        graphql_endpoint="/graphql",
    )


@pytest.fixture
def target_no_auth(base_url):
    """Create a test target without authentication."""
    return Target(
        base_url=base_url,
        name="TestTargetNoAuth",
    )


@pytest.fixture
def mock_client(base_url):
    """Create a mocked httpx client with respx."""
    with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
        with httpx.Client(base_url=base_url) as client:
            yield client, respx_mock


@pytest.fixture
def http_client(base_url):
    """Create a real httpx client (for integration tests)."""
    with httpx.Client(base_url=base_url, timeout=5) as client:
        yield client


# Common mock responses
@pytest.fixture
def login_success_response():
    """Successful login response."""
    return {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJ0ZXN0dXNlciJ9.fake",
        "token_type": "bearer",
    }


@pytest.fixture
def user_response():
    """User data response."""
    return {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "role": "user",
    }


@pytest.fixture
def user_with_sensitive_data():
    """User data with sensitive fields exposed."""
    return {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "role": "user",
        "ssn": "123-45-6789",
        "credit_card": "4111111111111111",
        "api_key": "sk-secret-key-12345",
    }


@pytest.fixture
def sql_error_response():
    """Response containing SQL error."""
    return "Error: You have an error in your SQL syntax near ''"


@pytest.fixture
def products_response():
    """Normal products response."""
    return [
        {"id": 1, "name": "Product 1", "price": 10.0},
        {"id": 2, "name": "Product 2", "price": 20.0},
    ]


@pytest.fixture
def command_output_response():
    """Response containing command execution output."""
    return {
        "output": "uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)"
    }


@pytest.fixture
def graphql_introspection_response():
    """GraphQL introspection response."""
    return {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query", "fields": [{"name": "users", "type": {"name": "User"}}]},
                    {"name": "User", "fields": [{"name": "id", "type": {"name": "ID"}}]},
                    {"name": "Product", "fields": [{"name": "id", "type": {"name": "ID"}}]},
                ]
            }
        }
    }


@pytest.fixture
def graphql_users_response():
    """GraphQL users query response with sensitive data."""
    return {
        "data": {
            "users": [
                {"id": 1, "username": "admin", "ssn": "111-22-3333", "creditCard": "4111111111111111"},
                {"id": 2, "username": "user", "ssn": "444-55-6666", "creditCard": "5555555555554444"},
            ]
        }
    }
