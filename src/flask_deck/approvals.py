from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

ApprovalStatus = Literal["pending", "approved", "rejected", "cancelled"]
ApprovalOperation = Literal["create", "edit", "delete", "action"]


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class ApprovalRequest:
    """Four-eyes Maker-Checker pending mutation or action request."""

    id: str
    model_slug: str
    model_label: str
    operation: ApprovalOperation
    record_pk: str
    record_repr: str
    payload: dict[str, Any] = field(default_factory=dict)
    diff: dict[str, dict[str, Any]] = field(default_factory=dict)
    reason: str = ""
    status: ApprovalStatus = "pending"
    requester_id: str = ""
    requester_name: str = ""
    actor_type: str = "human"
    reviewer_id: str | None = None
    reviewer_name: str | None = None
    review_note: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: datetime | None = None


@runtime_checkable
class ApprovalStore(Protocol):
    """Persistence contract for four-eyes Maker-Checker approval requests."""

    def create(self, req: ApprovalRequest) -> ApprovalRequest: ...

    def get(self, approval_id: str) -> ApprovalRequest | None: ...

    def list_requests(
        self,
        *,
        status: str | None = None,
        model_slug: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]: ...

    def pending_count(self) -> int: ...

    def resolve(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        reviewer_id: str,
        reviewer_name: str,
        review_note: str = "",
    ) -> ApprovalRequest | None: ...


def make_approval_request(
    *,
    model_slug: str,
    model_label: str,
    operation: ApprovalOperation,
    record_pk: str,
    record_repr: str,
    payload: dict[str, Any],
    diff: dict[str, dict[str, Any]],
    reason: str,
    requester_id: str,
    requester_name: str,
    actor_type: str = "human",
) -> ApprovalRequest:
    """Create a fresh pending ApprovalRequest stamped in UTC."""
    return ApprovalRequest(
        id=uuid.uuid4().hex[:16],
        model_slug=model_slug,
        model_label=model_label,
        operation=operation,
        record_pk=record_pk,
        record_repr=record_repr,
        payload=payload,
        diff=diff,
        reason=reason,
        status="pending",
        requester_id=requester_id,
        requester_name=requester_name,
        actor_type=actor_type,
        created_at=datetime.now(timezone.utc),
    )


class InMemoryApprovalStore:
    """Thread-safe in-memory Maker-Checker approval store."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def create(self, req: ApprovalRequest) -> ApprovalRequest:
        stored = replace(
            req,
            payload=dict(req.payload),
            diff={k: dict(v) for k, v in req.diff.items()},
        )
        with self._lock:
            self._records[stored.id] = stored
        return replace(stored)

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            rec = self._records.get(approval_id)
            return replace(rec) if rec is not None else None

    def list_requests(
        self,
        *,
        status: str | None = None,
        model_slug: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        with self._lock:
            items = list(self._records.values())
        if status:
            items = [r for r in items if r.status == status]
        if model_slug:
            items = [r for r in items if r.model_slug == model_slug]
        items.sort(key=lambda r: r.created_at, reverse=True)
        return [replace(r) for r in items[: max(1, int(limit))]]

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._records.values() if r.status == "pending")

    def resolve(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        reviewer_id: str,
        reviewer_name: str,
        review_note: str = "",
    ) -> ApprovalRequest | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            rec = self._records.get(approval_id)
            if rec is None or rec.status != "pending":
                return None
            if status in {"approved", "rejected"} and rec.requester_id == reviewer_id:
                return None
            rec.status = status
            rec.reviewer_id = reviewer_id
            rec.reviewer_name = reviewer_name
            rec.review_note = review_note
            rec.reviewed_at = now
            return replace(rec)


class SQLAlchemyApprovalStore:
    """Multi-worker SQLAlchemy Maker-Checker approval queue (`deck_approvals`)."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "deck_approvals",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("model_slug", sa.String(128), nullable=False, index=True),
            sa.Column("model_label", sa.String(128), nullable=False),
            sa.Column("operation", sa.String(16), nullable=False),
            sa.Column("record_pk", sa.String(256), nullable=False, index=True),
            sa.Column("record_repr", sa.String(256), nullable=False),
            sa.Column("payload_json", sa.Text, nullable=False),
            sa.Column("diff_json", sa.Text, nullable=False),
            sa.Column("reason", sa.Text, nullable=False, default=""),
            sa.Column("status", sa.String(16), nullable=False, index=True),
            sa.Column("requester_id", sa.String(128), nullable=False, index=True),
            sa.Column("requester_name", sa.String(128), nullable=False),
            sa.Column("actor_type", sa.String(32), nullable=False, default="human"),
            sa.Column("reviewer_id", sa.String(128), nullable=True),
            sa.Column("reviewer_name", sa.String(128), nullable=True),
            sa.Column("review_note", sa.Text, nullable=False, default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)
        self._lock = threading.Lock()
        self._pending_cache: tuple[float, int] | None = None

    @staticmethod
    def _row_to_req(row: Any) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        try:
            payload = json.loads(row.payload_json or "{}")
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}
        try:
            diff = json.loads(row.diff_json or "{}")
            if not isinstance(diff, dict):
                diff = {}
        except Exception:
            diff = {}
        return ApprovalRequest(
            id=str(row.id),
            model_slug=str(row.model_slug),
            model_label=str(row.model_label),
            operation=row.operation,
            record_pk=str(row.record_pk),
            record_repr=str(row.record_repr),
            payload=payload,
            diff=diff,
            reason=str(row.reason or ""),
            status=row.status,
            requester_id=str(row.requester_id),
            requester_name=str(row.requester_name),
            actor_type=str(row.actor_type or "human"),
            reviewer_id=str(row.reviewer_id) if row.reviewer_id is not None else None,
            reviewer_name=str(row.reviewer_name) if row.reviewer_name is not None else None,
            review_note=str(row.review_note or ""),
            created_at=_ensure_utc(row.created_at) or now,
            reviewed_at=_ensure_utc(row.reviewed_at),
        )

    def create(self, req: ApprovalRequest) -> ApprovalRequest:
        now = req.created_at or datetime.now(timezone.utc)
        with Session(self._engine) as sess:
            sess.execute(
                self._table.insert().values(
                    id=req.id,
                    model_slug=req.model_slug[:128],
                    model_label=req.model_label[:128],
                    operation=req.operation,
                    record_pk=req.record_pk[:256],
                    record_repr=req.record_repr[:256],
                    payload_json=json.dumps(req.payload, default=str),
                    diff_json=json.dumps(req.diff, default=str),
                    reason=req.reason,
                    status=req.status,
                    requester_id=req.requester_id[:128],
                    requester_name=req.requester_name[:128],
                    actor_type=req.actor_type[:32],
                    reviewer_id=req.reviewer_id[:128] if req.reviewer_id else None,
                    reviewer_name=req.reviewer_name[:128] if req.reviewer_name else None,
                    review_note=req.review_note,
                    created_at=now,
                    reviewed_at=req.reviewed_at,
                )
            )
            sess.commit()
        with self._lock:
            self._pending_cache = None
        return replace(req, created_at=now)

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == approval_id)
            ).first()
            return self._row_to_req(row) if row is not None else None

    def list_requests(
        self,
        *,
        status: str | None = None,
        model_slug: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        stmt = sa.select(self._table)
        if status:
            stmt = stmt.where(self._table.c.status == status)
        if model_slug:
            stmt = stmt.where(self._table.c.model_slug == model_slug)
        stmt = stmt.order_by(self._table.c.created_at.desc()).limit(max(1, int(limit)))
        with Session(self._engine) as sess:
            return [self._row_to_req(r) for r in sess.execute(stmt)]

    def pending_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            cached = self._pending_cache
            if cached is not None and (now - cached[0]) < 2.0:
                return cached[1]
        with Session(self._engine) as sess:
            cnt = sess.execute(
                sa.select(sa.func.count())
                .select_from(self._table)
                .where(self._table.c.status == "pending")
            ).scalar_one()
            count = int(cnt or 0)
        with self._lock:
            self._pending_cache = (time.monotonic(), count)
        return count

    def resolve(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        reviewer_id: str,
        reviewer_name: str,
        review_note: str = "",
    ) -> ApprovalRequest | None:
        now = datetime.now(timezone.utc)
        conds: list[Any] = [
            self._table.c.id == approval_id,
            self._table.c.status == "pending",
        ]
        if status in {"approved", "rejected"}:
            conds.append(self._table.c.requester_id != reviewer_id)
        with Session(self._engine) as sess:
            res = sess.execute(
                self._table.update()
                .where(*conds)
                .values(
                    status=status,
                    reviewer_id=reviewer_id[:128],
                    reviewer_name=reviewer_name[:128],
                    review_note=review_note,
                    reviewed_at=now,
                )
            )
            sess.commit()
            with self._lock:
                self._pending_cache = None
            if (getattr(res, "rowcount", 0) or 0) != 1:
                return None
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == approval_id)
            ).first()
            return self._row_to_req(row) if row is not None else None
