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


def test_memory_agent_health():
    response = client.get(
        "/api/memory/health"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["available"] is True
    assert data["status"] == "ready"


def test_audit_event_creation():
    response = client.post(
        "/api/memory/audit",
        json={
            "agent": "TEST",
            "action": "pipeline_test",
            "target": "jarvis",
            "status": "success",
            "details": {
                "source": "pytest"
            }
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] > 0

    history = client.get(
        "/api/memory/audit?limit=10"
    )

    assert history.status_code == 200
    assert history.json()["count"] >= 1


def test_approval_lifecycle():
    request = client.post(
        "/api/memory/approvals",
        json={
            "action": "restart_container",
            "target": "test-container",
            "reason": "Automated approval test",
            "requested_by": "pytest"
        },
    )

    assert request.status_code == 201

    approval_id = request.json()["id"]

    decision = client.post(
        (
            f"/api/memory/approvals/"
            f"{approval_id}/decision"
        ),
        json={
            "decision": "approved",
            "note": "Approved during test"
        },
    )

    assert decision.status_code == 200
    assert (
        decision.json()["status"]
        == "approved"
    )


def test_docker_restart_requires_approval():
    response = client.post(
        "/api/containers/demo-container/action",
        json={
            "action": "restart"
        },
    )

    assert response.status_code == 403
    assert "approval" in response.json()["detail"].lower()


def test_container_action_request_creates_approval():
    response = client.post(
        (
            "/api/containers/"
            "demo-container/action-request"
        ),
        json={
            "action": "restart",
            "reason": (
                "Automated SENTINEL approval test"
            )
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["approval_id"] > 0
    assert data["status"] == "pending"
    assert data["action"] == "restart"
