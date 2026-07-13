import json
import os
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException


router = APIRouter(
    prefix="/api/forge",
    tags=["FORGE CI/CD Agent"],
)

CONFIG_FILE = Path("config/forge.json")

_CACHE = {
    "expires_at": 0.0,
    "payload": None,
}


def load_forge_config() -> dict:
    if not CONFIG_FILE.exists():
        raise RuntimeError(
            "FORGE configuration file is missing."
        )

    try:
        config = json.loads(
            CONFIG_FILE.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Invalid FORGE JSON configuration: {error}"
        ) from error

    required_fields = {
        "owner",
        "repository",
        "workflow_file",
        "branch",
    }

    missing_fields = sorted(
        required_fields.difference(config)
    )

    if missing_fields:
        raise RuntimeError(
            "Missing FORGE configuration fields: "
            + ", ".join(missing_fields)
        )

    return config


def parse_github_time(value: str | None) -> datetime | None:
    if not value:
        return None

    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def calculate_duration_seconds(
    started_at: str | None,
    completed_at: str | None,
) -> int | None:
    start = parse_github_time(started_at)
    end = parse_github_time(completed_at)

    if start is None or end is None:
        return None

    return max(
        int((end - start).total_seconds()),
        0,
    )


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "JARVIS-DevSecOps-FORGE-Agent",
    }

    token = os.getenv("GITHUB_TOKEN", "").strip()

    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


def request_json(
    client: httpx.Client,
    url: str,
    parameters: dict | None = None,
) -> tuple[dict, httpx.Headers]:
    response = client.get(
        url,
        params=parameters,
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=(
                "GitHub API request failed with status "
                f"{response.status_code}."
            ),
        )

    return response.json(), response.headers


def normalise_job(job: dict) -> dict:
    return {
        "id": job.get("id"),
        "name": job.get("name"),
        "status": job.get("status"),
        "conclusion": job.get("conclusion"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "duration_seconds": calculate_duration_seconds(
            job.get("started_at"),
            job.get("completed_at"),
        ),
        "html_url": job.get("html_url"),
    }


def normalise_run(run: dict) -> dict:
    return {
        "id": run.get("id"),
        "run_number": run.get("run_number"),
        "run_attempt": run.get("run_attempt"),
        "name": run.get("name"),
        "title": run.get("display_title"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "branch": run.get("head_branch"),
        "commit_sha": run.get("head_sha"),
        "short_sha": (
            run.get("head_sha", "")[:7]
            if run.get("head_sha")
            else None
        ),
        "actor": (
            run.get("actor", {}).get("login")
            if run.get("actor")
            else None
        ),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "started_at": run.get("run_started_at"),
        "duration_seconds": calculate_duration_seconds(
            run.get("run_started_at"),
            run.get("updated_at"),
        ),
        "html_url": run.get("html_url"),
    }


@router.get("/status")
def get_forge_status(force_refresh: bool = False):
    try:
        config = load_forge_config()
    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error

    now = time.monotonic()

    if (
        not force_refresh
        and _CACHE["payload"] is not None
        and now < _CACHE["expires_at"]
    ):
        cached_payload = dict(_CACHE["payload"])
        cached_payload["cached"] = True
        return cached_payload

    owner = config["owner"]
    repository = config["repository"]
    workflow_file = quote(
        config["workflow_file"],
        safe="",
    )

    runs_url = (
        f"https://api.github.com/repos/{owner}/{repository}"
        f"/actions/workflows/{workflow_file}/runs"
    )

    try:
        with httpx.Client(
            timeout=httpx.Timeout(12.0),
            headers=github_headers(),
            follow_redirects=True,
        ) as client:
            runs_data, runs_headers = request_json(
                client,
                runs_url,
                parameters={
                    "branch": config["branch"],
                    "per_page": 5,
                },
            )

            workflow_runs = runs_data.get(
                "workflow_runs",
                [],
            )

            recent_runs = [
                normalise_run(run)
                for run in workflow_runs
            ]

            latest_run = (
                recent_runs[0]
                if recent_runs
                else None
            )

            jobs = []
            jobs_error = None

            if workflow_runs:
                latest_raw_run = workflow_runs[0]
                jobs_url = latest_raw_run.get("jobs_url")

                if jobs_url:
                    try:
                        jobs_data, _ = request_json(
                            client,
                            jobs_url,
                            parameters={
                                "per_page": 20,
                            },
                        )

                        jobs = [
                            normalise_job(job)
                            for job in jobs_data.get(
                                "jobs",
                                [],
                            )
                        ]
                    except HTTPException as error:
                        jobs_error = error.detail

            payload = {
                "available": True,
                "cached": False,
                "repository": f"{owner}/{repository}",
                "workflow_file": config[
                    "workflow_file"
                ],
                "branch": config["branch"],
                "total_runs": runs_data.get(
                    "total_count",
                    0,
                ),
                "latest_run": latest_run,
                "recent_runs": recent_runs,
                "jobs": jobs,
                "jobs_error": jobs_error,
                "token_configured": bool(
                    os.getenv(
                        "GITHUB_TOKEN",
                        "",
                    ).strip()
                ),
                "rate_limit_remaining": (
                    runs_headers.get(
                        "x-ratelimit-remaining"
                    )
                ),
            }

    except httpx.RequestError as error:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub connection failed: {error}",
        ) from error

    cache_seconds = int(
        config.get("cache_seconds", 60)
    )

    _CACHE["payload"] = payload
    _CACHE["expires_at"] = (
        time.monotonic() + cache_seconds
    )

    return payload
