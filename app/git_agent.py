import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter


router = APIRouter(
    prefix="/api/git",
    tags=["Git Agent"],
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or "Git command failed."
        )

    return result.stdout.strip()


def sanitise_remote(remote_url: str) -> str:
    """
    Remove username, password or embedded tokens from HTTPS remotes.
    SSH-style Git remotes are returned unchanged.
    """

    if "://" not in remote_url:
        return remote_url

    parsed = urlsplit(remote_url)

    hostname = parsed.hostname or ""

    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"

    return urlunsplit(
        (
            parsed.scheme,
            hostname,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


@router.get("/status")
def get_git_status():
    try:
        inside_repository = run_git(
            "rev-parse",
            "--is-inside-work-tree",
        )

        if inside_repository.lower() != "true":
            return {
                "available": False,
                "message": "Project is not inside a Git repository.",
            }

        branch = run_git(
            "branch",
            "--show-current",
        )

        if not branch:
            branch = "DETACHED HEAD"

        status_lines = run_git(
            "status",
            "--porcelain=v1",
        ).splitlines()

        modified_files = []
        untracked_files = []

        for line in status_lines:
            if not line:
                continue

            status_code = line[:2]
            filename = line[3:].strip()

            if status_code == "??":
                untracked_files.append(filename)
            else:
                modified_files.append(
                    {
                        "status": status_code,
                        "file": filename,
                    }
                )

        try:
            remote = sanitise_remote(
                run_git(
                    "remote",
                    "get-url",
                    "origin",
                )
            )
        except RuntimeError:
            remote = None

        return {
            "available": True,
            "repository_path": str(PROJECT_ROOT),
            "branch": branch,
            "clean": len(status_lines) == 0,
            "changes_count": len(status_lines),
            "modified_files": modified_files,
            "untracked_files": untracked_files,
            "remote": remote,
            "latest_commit": {
                "short_sha": run_git(
                    "rev-parse",
                    "--short",
                    "HEAD",
                ),
                "full_sha": run_git(
                    "rev-parse",
                    "HEAD",
                ),
                "message": run_git(
                    "log",
                    "-1",
                    "--pretty=%s",
                ),
                "author": run_git(
                    "log",
                    "-1",
                    "--pretty=%an",
                ),
                "date": run_git(
                    "log",
                    "-1",
                    "--pretty=%cI",
                ),
            },
        }

    except (
        RuntimeError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ) as error:
        return {
            "available": False,
            "message": str(error),
        }
