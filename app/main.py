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

app = FastAPI(
    title="JARVIS DevOps Command Center",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
app.include_router(recon_router)


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


@app.post("/api/containers/{container_name}/action")
def control_container(
    container_name: str,
    request: ContainerActionRequest,
):
    """
    Safely start, stop or restart a Docker container.
    Delete/remove operations are intentionally not supported.
    """

    container_name = container_name.strip()
    action = request.action.strip().lower()

    allowed_actions = {
        "start",
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

    client = None

    try:
        client = docker.from_env()
        client.ping()

        container = client.containers.get(container_name)
        container.reload()

        previous_status = container.status

        if action == "start":
            if container.status == "running":
                message = "Container is already running."
            else:
                container.start()
                message = "Container started successfully."

        elif action == "stop":
            if container.status != "running":
                message = (
                    f"Container is already {container.status}."
                )
            else:
                container.stop(timeout=10)
                message = "Container stopped successfully."

        else:
            container.restart(timeout=10)
            message = "Container restarted successfully."

        container.reload()

        return {
            "container": container.name,
            "container_id": container.short_id,
            "action": action,
            "previous_status": previous_status,
            "current_status": container.status,
            "message": message,
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
