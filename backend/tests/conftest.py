"""Test configuration: every test session uses its own temporary database and data folder."""
import os
import sys
import tempfile
from pathlib import Path

_TEST_DATA_DIR = tempfile.mkdtemp(prefix="sentinel_test_")
os.environ["MCP_SENTINEL_DATA_DIR"] = _TEST_DATA_DIR
os.environ["MCP_SENTINEL_JWT_SECRET"] = "test-only-secret-not-used-in-production"
os.environ["MCP_SENTINEL_PBKDF2_ITERATIONS"] = "1000"
os.environ["MCP_SENTINEL_MODE"] = "C_CONTROLLER"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client, username: str, password: str) -> dict:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin_headers(client):
    return login(client, "admin", "Admin@123")


@pytest.fixture()
def fresh(client, admin_headers):
    """Reset the database to the seeded demo state before a test."""
    assert client.post("/api/admin/reset", headers=admin_headers).status_code == 200
    return client
