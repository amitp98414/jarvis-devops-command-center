from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_dashboard_is_available():
    response = client.get("/")

    assert response.status_code == 200
    assert "J.A.R.V.I.S" in response.text


def test_system_api():
    response = client.get("/api/system")

    assert response.status_code == 200

    data = response.json()

    assert "hostname" in data
    assert "cpu_percent" in data
    assert "memory" in data
    assert "disk" in data


def test_scope_api():
    response = client.get("/api/security/scope")

    assert response.status_code == 200

    data = response.json()

    assert "program_name" in data
    assert isinstance(data["allowed_targets"], list)


def test_unknown_page_returns_404():
    response = client.get("/this-page-does-not-exist")

    assert response.status_code == 404
