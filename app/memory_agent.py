import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/api/memory",
    tags=["Memory, Audit and Approval Agent"],
)

DATABASE_PATH = Path(
    os.getenv(
        "JARVIS_DB_PATH",
        "data/jarvis.db",
    )
)


class AuditEventCreate(BaseModel):
    agent: str = Field(
        min_length=1,
        max_length=100,
    )
    action: str = Field(
        min_length=1,
        max_length=200,
    )
    target: str | None = Field(
        default=None,
        max_length=500,
    )
    status: str = Field(
        default="info",
        min_length=1,
        max_length=50,
    )
    details: dict[str, Any] | str | None = None


class ApprovalRequestCreate(BaseModel):
    action: str = Field(
        min_length=1,
        max_length=200,
    )
    target: str = Field(
        min_length=1,
        max_length=500,
    )
    reason: str = Field(
        min_length=1,
        max_length=1000,
    )
    requested_by: str = Field(
        default="operator",
        min_length=1,
        max_length=100,
    )


class ApprovalDecision(BaseModel):
    decision: Literal[
        "approved",
        "rejected",
    ]
    note: str | None = Field(
        default=None,
        max_length=1000,
    )


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialise_database() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (
                        status IN (
                            'pending',
                            'approved',
                            'rejected'
                        )
                    ),
                decided_at TEXT,
                decision_note TEXT
            );

            CREATE INDEX IF NOT EXISTS
                idx_audit_events_created_at
            ON audit_events(created_at);

            CREATE INDEX IF NOT EXISTS
                idx_approval_requests_status
            ON approval_requests(status);
            """
        )


def serialise_details(
    details: dict[str, Any] | str | None,
) -> str | None:
    if details is None:
        return None

    if isinstance(details, str):
        return details

    return json.dumps(
        details,
        ensure_ascii=False,
    )


def deserialise_details(
    details: str | None,
) -> Any:
    if details is None:
        return None

    try:
        return json.loads(details)
    except json.JSONDecodeError:
        return details


def audit_row_to_dict(
    row: sqlite3.Row,
) -> dict:
    result = dict(row)
    result["details"] = deserialise_details(
        result.get("details")
    )

    return result


def record_audit_event(
    *,
    agent: str,
    action: str,
    target: str | None = None,
    event_status: str = "info",
    details: dict[str, Any] | str | None = None,
) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO audit_events (
                created_at,
                agent,
                action,
                target,
                status,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                agent,
                action,
                target,
                event_status,
                serialise_details(details),
            ),
        )

        return int(cursor.lastrowid)


@router.get("/health")
def memory_health():
    initialise_database()

    return {
        "available": True,
        "database": str(DATABASE_PATH),
        "status": "ready",
    }


@router.post(
    "/audit",
    status_code=status.HTTP_201_CREATED,
)
def create_audit_event(
    event: AuditEventCreate,
):
    event_id = record_audit_event(
        agent=event.agent,
        action=event.action,
        target=event.target,
        event_status=event.status,
        details=event.details,
    )

    return {
        "id": event_id,
        "message": "Audit event recorded.",
    }


@router.get("/audit")
def list_audit_events(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                agent,
                action,
                target,
                status,
                details
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "count": len(rows),
        "events": [
            audit_row_to_dict(row)
            for row in rows
        ],
    }


@router.post(
    "/approvals",
    status_code=status.HTTP_201_CREATED,
)
def create_approval_request(
    request: ApprovalRequestCreate,
):
    created_at = utc_now()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO approval_requests (
                created_at,
                action,
                target,
                reason,
                requested_by,
                status
            )
            VALUES (?, ?, ?, ?, ?, 'pending')
            """,
            (
                created_at,
                request.action,
                request.target,
                request.reason,
                request.requested_by,
            ),
        )

        approval_id = int(
            cursor.lastrowid
        )

    record_audit_event(
        agent="SENTINEL",
        action="approval_requested",
        target=request.target,
        event_status="pending",
        details={
            "approval_id": approval_id,
            "requested_action": request.action,
            "reason": request.reason,
            "requested_by": request.requested_by,
        },
    )

    return {
        "id": approval_id,
        "status": "pending",
        "message": "Approval request created.",
    }


@router.get("/approvals")
def list_approval_requests(
    approval_status: Literal[
        "pending",
        "approved",
        "rejected",
    ] | None = Query(
        default=None,
        alias="status",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):
    query = """
        SELECT
            id,
            created_at,
            action,
            target,
            reason,
            requested_by,
            status,
            decided_at,
            decision_note
        FROM approval_requests
    """

    parameters: list[Any] = []

    if approval_status is not None:
        query += " WHERE status = ?"
        parameters.append(
            approval_status
        )

    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(limit)

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

    return {
        "count": len(rows),
        "requests": [
            dict(row)
            for row in rows
        ],
    }


@router.post(
    "/approvals/{approval_id}/decision"
)
def decide_approval_request(
    approval_id: int,
    decision: ApprovalDecision,
):
    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT *
            FROM approval_requests
            WHERE id = ?
            """,
            (approval_id,),
        ).fetchone()

        if existing is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Approval request "
                    f"{approval_id} was not found."
                ),
            )

        if existing["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail=(
                    "This approval request "
                    "has already been decided."
                ),
            )

        decided_at = utc_now()

        connection.execute(
            """
            UPDATE approval_requests
            SET
                status = ?,
                decided_at = ?,
                decision_note = ?
            WHERE id = ?
            """,
            (
                decision.decision,
                decided_at,
                decision.note,
                approval_id,
            ),
        )

    record_audit_event(
        agent="SENTINEL",
        action="approval_decided",
        target=existing["target"],
        event_status=decision.decision,
        details={
            "approval_id": approval_id,
            "requested_action": existing["action"],
            "decision": decision.decision,
            "note": decision.note,
        },
    )

    return {
        "id": approval_id,
        "status": decision.decision,
        "decided_at": decided_at,
        "message": (
            f"Approval request "
            f"{decision.decision}."
        ),
    }
