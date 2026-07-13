from datetime import datetime, timezone
import socket

import docker
import psutil
from docker.errors import DockerException
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.recon import router as recon_router
from app.git_agent import router as git_router
from app.forge_agent import router as forge_router
from app.memory_agent import (
    create_approval_record,
    finish_approval_execution,
    get_approval_record,
    initialise_database,
    record_audit_event,
    reserve_approval_execution,
    router as memory_router,
)

app = FastAPI(
    title="JARVIS DevOps Command Center",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
app.include_router(recon_router)
app.include_router(git_router)
app.include_router(forge_router)
app.include_router(memory_router)
initialise_database()


@app.get("/")
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.get("/api/system")
def get_system_status():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "hostname": socket.gethostname(),
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "memory": {
            "total_gb": round(memory.total / (1024 ** 3), 2),
            "used_gb": round(memory.used / (1024 ** 3), 2),
            "available_gb": round(memory.available / (1024 ** 3), 2),
            "percent": memory.percent,
        },
        "disk": {
            "total_gb": round(disk.total / (1024 ** 3), 2),
            "used_gb": round(disk.used / (1024 ** 3), 2),
            "free_gb": round(disk.free / (1024 ** 3), 2),
            "percent": disk.percent,
        },
        "boot_time": datetime.fromtimestamp(
            psutil.boot_time(),
            tz=timezone.utc,
        ).isoformat(),
    }


@app.get("/api/containers")
def get_docker_containers():
    try:
        client = docker.from_env()
        client.ping()

        containers = []

        for container in client.containers.list(all=True):
            state = container.attrs.get("State", {})
            health = state.get("Health", {}).get(
                "Status",
                "not-configured",
            )

            image_name = (
                container.image.tags[0]
                if container.image.tags
                else container.image.short_id
            )

            containers.append(
                {
                    "name": container.name,
                    "id": container.short_id,
                    "image": image_name,
                    "status": container.status,
                    "health": health,
                }
            )

        return {
            "docker": "connected",
            "count": len(containers),
            "containers": containers,
        }

    except DockerException as error:
        return {
            "docker": "unavailable",
            "count": 0,
            "containers": [],
            "error": str(error),
        }


@app.get("/api/containers/{container_name}/logs")
def get_container_logs(container_name: str, tail: int = 100):
    """
    Read recent stdout/stderr logs from a Docker container.
    This endpoint is read-only.
    """

    container_name = container_name.strip()

    if not container_name:
        raise HTTPException(
            status_code=400,
            detail="Container name cannot be empty.",
        )

    if tail < 1 or tail > 500:
        raise HTTPException(
            status_code=400,
            detail="tail must be between 1 and 500",
        )

    client = None

    try:
        client = docker.from_env()
        client.ping()

        container = client.containers.get(container_name)

        raw_logs = container.logs(
            stdout=True,
            stderr=True,
            tail=tail,
            timestamps=True,
        )

        logs = raw_logs.decode(
            "utf-8",
            errors="replace",
        )

        return {
            "container": container.name,
            "container_id": container.short_id,
            "status": container.status,
            "tail": tail,
            "logs": logs,
        }

    except docker.errors.NotFound as error:
        raise HTTPException(
            status_code=404,
            detail=f"Container '{container_name}' was not found.",
        ) from error

    except docker.errors.APIError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Docker API error: {error}",
        ) from error

    except DockerException as error:
        raise HTTPException(
            status_code=503,
            detail=f"Docker engine unavailable: {error}",
        ) from error

    finally:
        if client is not None:
            client.close()


class ContainerActionRequest(BaseModel):
    action: str
    approval_id: int | None = None


class ContainerApprovalRequest(BaseModel):
    action: str
    reason: str = (
        "Operator requested Docker operation "
        "from JARVIS dashboard."
    )


@app.post(
    "/api/containers/{container_name}/action-request",
    status_code=201,
)
def request_container_action_approval(
    container_name: str,
    request: ContainerApprovalRequest,
):
    container_name = container_name.strip()
    action = request.action.strip().lower()
    reason = request.reason.strip()

    protected_actions = {
        "stop",
        "restart",
    }

    if not container_name:
        raise HTTPException(
            status_code=400,
            detail="Container name cannot be empty.",
        )

    if action not in protected_actions:
        raise HTTPException(
            status_code=400,
            detail=(
                "Approval requests are supported only "
                "for stop and restart actions."
            ),
        )

    if not reason:
        raise HTTPException(
            status_code=400,
            detail="Approval reason cannot be empty.",
        )

    approval_id = create_approval_record(
        action=f"{action}_container",
        target=container_name,
        reason=reason,
        requested_by="JARVIS operator",
    )

    return {
        "approval_id": approval_id,
        "container": container_name,
        "action": action,
        "status": "pending",
        "message": (
            "SENTINEL created an approval request. "
            "Approve it before execution."
        ),
    }


@app.post("/api/containers/{container_name}/action")
def control_container(
    container_name: str,
    request: ContainerActionRequest,
):
    """
    Start is allowed directly.

    Stop and restart require a matching, approved,
    unused SENTINEL approval request.
    """

    container_name = container_name.strip()
    action = request.action.strip().lower()

    allowed_actions = {
        "start",
        "stop",
        "restart",
    }

    protected_actions = {
        "stop",
        "restart",
    }

    if not container_name:
        raise HTTPException(
            status_code=400,
            detail="Container name cannot be empty.",
        )

    if action not in allowed_actions:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported action. Allowed actions: "
                "start, stop, restart."
            ),
        )

    approval_reserved = False

    if action in protected_actions:
        if request.approval_id is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"{action.upper()} requires SENTINEL "
                    "approval. Create an action request first."
                ),
            )

        approval = get_approval_record(
            request.approval_id
        )

        if approval is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Approval request "
                    f"{request.approval_id} was not found."
                ),
            )

        expected_action = f"{action}_container"

        if (
            approval["action"] != expected_action
            or approval["target"] != container_name
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Approval action or target does not "
                    "match this Docker operation."
                ),
            )

        reserve_approval_execution(
            approval_id=request.approval_id,
            executor="DOCKER Agent",
        )

        approval_reserved = True

    client = None

    try:
        client = docker.from_env()
        client.ping()

        container = client.containers.get(
            container_name
        )
        container.reload()

        previous_status = container.status

        if action == "start":
            if container.status == "running":
                message = (
                    "Container is already running."
                )
            else:
                container.start()
                message = (
                    "Container started successfully."
                )

        elif action == "stop":
            if container.status != "running":
                message = (
                    f"Container is already "
                    f"{container.status}."
                )
            else:
                container.stop(timeout=10)
                message = (
                    "Container stopped successfully."
                )

        else:
            container.restart(timeout=10)
            message = (
                "Container restarted successfully."
            )

        container.reload()

        result = {
            "container": container.name,
            "container_id": container.short_id,
            "action": action,
            "previous_status": previous_status,
            "current_status": container.status,
            "approval_id": request.approval_id,
            "message": message,
        }

        record_audit_event(
            agent="DOCKER",
            action=f"container_{action}",
            target=container.name,
            event_status="success",
            details=result,
        )

        if (
            approval_reserved
            and request.approval_id is not None
        ):
            finish_approval_execution(
                approval_id=request.approval_id,
                result_status="success",
                details=result,
            )

        return result

    except docker.errors.NotFound as error:
        detail = (
            f"Container '{container_name}' "
            "was not found."
        )

        if (
            approval_reserved
            and request.approval_id is not None
        ):
            finish_approval_execution(
                approval_id=request.approval_id,
                result_status="failed",
                details=detail,
            )

        raise HTTPException(
            status_code=404,
            detail=detail,
        ) from error

    except docker.errors.APIError as error:
        detail = f"Docker API error: {error}"

        if (
            approval_reserved
            and request.approval_id is not None
        ):
            finish_approval_execution(
                approval_id=request.approval_id,
                result_status="failed",
                details=detail,
            )

        raise HTTPException(
            status_code=502,
            detail=detail,
        ) from error

    except DockerException as error:
        detail = (
            f"Docker engine unavailable: {error}"
        )

        if (
            approval_reserved
            and request.approval_id is not None
        ):
            finish_approval_execution(
                approval_id=request.approval_id,
                result_status="failed",
                details=detail,
            )

        raise HTTPException(
            status_code=503,
            detail=detail,
        ) from error

    finally:
        if client is not None:
            client.close()
