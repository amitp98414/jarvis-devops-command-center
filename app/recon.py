import ipaddress
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/api/security",
    tags=["Authorized Security Research"],
)

SCOPE_FILE = Path("config/scope.json")
AUDIT_FILE = Path("data/audit.log")


class ReconRequest(BaseModel):
    url: str = Field(
        ...,
        description="An explicitly authorised in-scope HTTP or HTTPS target",
        examples=["https://example.com"],
    )


def load_scope() -> dict:
    if not SCOPE_FILE.exists():
        raise HTTPException(
            status_code=500,
            detail="Scope configuration file is missing.",
        )

    try:
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid scope configuration: {error}",
        ) from error


def normalise_url(value: str) -> tuple[str, str]:
    value = value.strip()

    if not value:
        raise HTTPException(
            status_code=400,
            detail="Target URL cannot be empty.",
        )

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS targets are supported.",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="Credentials must not be included in the URL.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="A valid hostname is required.",
        )

    host = parsed.hostname.lower().rstrip(".")

    return value, host


def domain_matches(host: str, scope_entry: str) -> bool:
    entry = scope_entry.lower().strip().rstrip(".")

    if entry.startswith("*."):
        base_domain = entry[2:]

        return host.endswith(f".{base_domain}")

    return host == entry


def verify_scope(host: str, scope: dict) -> None:
    allowed_targets = scope.get("allowed_targets", [])
    excluded_targets = scope.get("excluded_targets", [])

    for excluded in excluded_targets:
        if domain_matches(host, excluded):
            raise HTTPException(
                status_code=403,
                detail=f"Target '{host}' is explicitly excluded from scope.",
            )

    is_allowed = any(
        domain_matches(host, allowed)
        for allowed in allowed_targets
    )

    if not is_allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Target '{host}' is not present in the configured "
                "authorised scope."
            ),
        )


def resolve_public_ips(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise HTTPException(
            status_code=400,
            detail=f"DNS resolution failed: {error}",
        ) from error

    addresses = sorted(
        {
            record[4][0]
            for record in records
        }
    )

    if not addresses:
        raise HTTPException(
            status_code=400,
            detail="No IP addresses were found for this host.",
        )

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if not ip.is_global:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Private, local, reserved or non-public "
                    f"address blocked: {address}"
                ),
            )

    return addresses


def security_header_observations(
    headers: dict[str, str],
    scheme: str,
) -> list[str]:
    normalised = {
        key.lower(): value
        for key, value in headers.items()
    }

    observations: list[str] = []

    recommended_headers = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    if scheme == "https":
        recommended_headers[
            "strict-transport-security"
        ] = "Strict-Transport-Security"

    for header_key, display_name in recommended_headers.items():
        if header_key not in normalised:
            observations.append(
                f"{display_name} header was not observed."
            )

    csp = normalised.get("content-security-policy", "")

    if (
        "x-frame-options" not in normalised
        and "frame-ancestors" not in csp.lower()
    ):
        observations.append(
            "No obvious clickjacking protection header was observed."
        )

    observations.append(
        "Missing headers are observations only and require manual review."
    )

    return observations


async def probe_url(
    client: httpx.AsyncClient,
    url: str,
    capture_body: bool = False,
) -> dict:
    try:
        async with client.stream(
            method="GET",
            url=url,
            follow_redirects=False,
        ) as response:
            body = b""

            if capture_body:
                async for chunk in response.aiter_bytes():
                    body += chunk

                    if len(body) >= 65536:
                        body = body[:65536]
                        break

            return {
                "url": str(response.url),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_preview": (
                    body.decode("utf-8", errors="replace")[:500]
                    if capture_body
                    else None
                ),
            }

    except httpx.RequestError as error:
        return {
            "url": url,
            "status_code": None,
            "headers": {},
            "body_preview": None,
            "error": str(error),
        }


def write_audit_log(host: str, result: str) -> None:
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(
            f"{timestamp}\tPASSIVE_RECON\t{host}\t{result}\n"
        )


@router.get("/scope")
def get_scope():
    scope = load_scope()

    return {
        "program_name": scope.get("program_name"),
        "allowed_targets": scope.get("allowed_targets", []),
        "excluded_targets": scope.get("excluded_targets", []),
        "max_requests_per_run": scope.get(
            "max_requests_per_run",
            5,
        ),
    }


@router.post("/passive-recon")
async def passive_recon(request: ReconRequest):
    scope = load_scope()

    target_url, host = normalise_url(request.url)

    verify_scope(host, scope)

    addresses = resolve_public_ips(host)

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    user_agent = scope.get(
        "user_agent",
        "JARVIS-Authorized-Security-Research/1.0",
    )

    timeout = httpx.Timeout(
        connect=5.0,
        read=8.0,
        write=5.0,
        pool=5.0,
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
        verify=True,
    ) as client:
        main_result = await probe_url(
            client,
            target_url,
        )

        robots_result = await probe_url(
            client,
            f"{base_url}/robots.txt",
            capture_body=True,
        )

        security_txt_result = await probe_url(
            client,
            f"{base_url}/.well-known/security.txt",
            capture_body=True,
        )

    headers = main_result.get("headers", {})

    important_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() in {
            "server",
            "x-powered-by",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
            "location",
            "access-control-allow-origin",
        }
    }

    observations = security_header_observations(
        headers,
        parsed.scheme,
    )

    write_audit_log(host, "COMPLETED")

    return {
        "mode": "authorised-passive-recon",
        "program": scope.get("program_name"),
        "target": {
            "url": target_url,
            "hostname": host,
            "resolved_ips": addresses,
            "scope_status": "authorised",
        },
        "http": {
            "status_code": main_result.get("status_code"),
            "redirect_location": headers.get("location"),
            "important_headers": important_headers,
            "error": main_result.get("error"),
        },
        "well_known_files": {
            "robots_txt": {
                "status_code": robots_result.get("status_code"),
                "preview": robots_result.get("body_preview"),
            },
            "security_txt": {
                "status_code": security_txt_result.get(
                    "status_code"
                ),
                "preview": security_txt_result.get(
                    "body_preview"
                ),
            },
        },
        "observations": observations,
        "notice": (
            "These are preliminary observations, not confirmed "
            "vulnerabilities. Manually verify program eligibility."
        ),
    }
