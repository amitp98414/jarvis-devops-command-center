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


def test_git_agent_status():
    response = client.get("/api/git/status")

    assert response.status_code == 200

    data = response.json()

    assert "available" in data


def test_forge_configuration():
    from app.forge_agent import load_forge_config

    config = load_forge_config()

    assert config["owner"] == "amitp98414"
    assert (
        config["repository"]
        == "jarvis-devops-command-center"
    )
    assert config["workflow_file"] == "ci.yml"
    assert config["branch"] == "main"
