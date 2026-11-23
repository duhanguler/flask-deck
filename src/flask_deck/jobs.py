from __future__ import annotations

import json
import logging
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.engine import Engine

logger = logging.getLogger("flask_deck.jobs")

JobStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]
TERMINAL_JOB_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "cancelled"})


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class JobRecord:
    """Mutable tracked state of one asynchronous Flask-Deck background job."""

    id: str
    name: str
    label: str
    actor_id: str
    actor_name: str
    model_slug: str = ""
    status: JobStatus = "queued"
    progress: int = 0
    message: str = "Queued"
    logs: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifact_key: str | None = None
    artifact_filename: str | None = None
    artifact_mime: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        duration_ms: int | None = None
        if self.started_at is not None:
            end = _ensure_utc(self.finished_at) or datetime.now(timezone.utc)
            started = _ensure_utc(self.started_at) or end
            duration_ms = max(0, int((end - started).total_seconds() * 1000))
        return {
            "id": self.id,
            "name": self.name,
            "label": self.label,
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "model_slug": self.model_slug,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "logs": list(self.logs),
            "created_at": (_ensure_utc(self.created_at) or self.created_at).isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": duration_ms,
            "artifact_filename": self.artifact_filename,
            "error": self.error,
        }


class _JobUpdater(Protocol):
    def _update(
        self,
        job_id: str,
        *,
        status: JobStatus | None = None,
        progress: int | None = None,
        message: str | None = None,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> JobRecord | None: ...

    def _append_log(self, job_id: str, line: str) -> None: ...

    def _attach_artifact(
        self, job_id: str, *, key: str, filename: str, content_type: str
    ) -> None: ...

    def _is_cancelled(self, job_id: str) -> bool: ...


class JobContext:
    """Progress, log, artifact, and cancellation controller passed to async job functions."""

    __slots__ = ("_backend", "_cancel_event", "job_id")

    def __init__(
        self,
        backend: _JobUpdater,
        job_id: str,
        cancel_event: threading.Event,
    ) -> None:
        self._backend = backend
        self.job_id = job_id
        self._cancel_event = cancel_event

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set() or self._backend._is_cancelled(self.job_id)

    def set_progress(self, pct: int, message: str | None = None) -> None:
        self._backend._update(
            self.job_id,
            progress=max(0, min(100, int(pct))),
            message=message,
        )

    def log(self, line: str) -> None:
        self._backend._append_log(self.job_id, line)

    def attach_artifact(self, *, key: str, filename: str, content_type: str) -> None:
        self._backend._attach_artifact(
            self.job_id, key=key, filename=filename, content_type=content_type
        )


JobCallable = Callable[[JobContext], str | None]


@dataclass(frozen=True, slots=True)
class ScheduledJobSpec:
    """Declarative scheduled / manually triggerable operational job registered on Deck."""

    name: str
    label: str
    schedule: str
    fn: JobCallable
    description: str = ""
    permission: str | None = None
    model_slug: str = "_scheduled"


@runtime_checkable
class JobBackend(Protocol):
    """Pluggable background job runner contract (ThreadPool & SQLAlchemy built-in)."""

    def submit(
        self,
        *,
        name: str,
        label: str,
        actor_id: str,
        actor_name: str,
        model_slug: str,
        fn: JobCallable,
        app: Flask | None = None,
        on_complete: Callable[[JobRecord], None] | None = None,
    ) -> JobRecord:
        """Enqueue fn and return initial JobRecord."""

    def get(self, job_id: str) -> JobRecord | None:
        """Return JobRecord snapshot by ID."""

    def list_jobs(
        self,
        *,
        actor_id: str | None = None,
        limit: int = 50,
    ) -> list[JobRecord]:
        """Return newest jobs first, optionally filtered by actor_id."""

    def cancel(self, job_id: str) -> bool:
        """Request cooperative cancellation of a queued or running job."""


def _invoke_completion(
    job_id: str,
    final_rec: JobRecord | None,
    app: Flask | None,
    on_complete: Callable[[JobRecord], None] | None,
) -> None:
    if final_rec is None or on_complete is None:
        return
    try:
        if app is not None:
            with app.app_context():
                on_complete(final_rec)
        else:
            on_complete(final_rec)
    except Exception as exc:
        logger.warning("Job on_complete callback error for %s: %s", job_id, exc)


def _execute_job(
    updater: _JobUpdater,
    job_id: str,
    cancel_ev: threading.Event,
    fn: JobCallable,
    app: Flask | None,
    on_complete: Callable[[JobRecord], None] | None,
) -> None:
    ctx = JobContext(updater, job_id, cancel_ev)
    try:
        if app is not None:
            with app.app_context():
                result_msg = fn(ctx)
        else:
            result_msg = fn(ctx)
        if ctx.is_cancelled():
            final = updater._update(
                job_id,
                status="cancelled",
                message="Cancelled by operator",
                finished_at=datetime.now(timezone.utc),
            )
        else:
            if isinstance(result_msg, str):
                done_msg = result_msg or "Completed successfully"
            elif result_msg is None:
                done_msg = "Completed successfully"
            else:
                done_msg = json.dumps(result_msg, default=str)
            final = updater._update(
                job_id,
                status="succeeded",
                progress=100,
                message=done_msg[:500],
                finished_at=datetime.now(timezone.utc),
            )
    except Exception as exc:
        updater._append_log(job_id, f"ERROR: {exc}")
        final = updater._update(
            job_id,
            status="failed",
            message="Failed",
            error=str(exc),
            finished_at=datetime.now(timezone.utc),
        )
    _invoke_completion(job_id, final, app, on_complete)


class ThreadPoolJobBackend:
    """Zero-dependency bounded thread-pool job runner with Flask app_context propagation."""

    __slots__ = (
        "_callables",
        "_cancel_events",
        "_executor",
        "_jobs",
        "_lock",
        "_max_history",
        "_max_logs",
        "_on_evict",
    )

    def __init__(
        self,
        *,
        max_workers: int = 2,
        max_history: int = 100,
        max_logs_per_job: int = 100,
        on_evict: Callable[[JobRecord], None] | None = None,
    ) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)),
            thread_name_prefix="flask-deck-job",
        )
        self._jobs: OrderedDict[str, JobRecord] = OrderedDict()
        self._cancel_events: dict[str, threading.Event] = {}
        self._callables: dict[
            str, tuple[JobCallable, Flask | None, Callable[[JobRecord], None] | None]
        ] = {}
        self._lock = threading.Lock()
        self._max_history = max(10, int(max_history))
        self._max_logs = max(10, int(max_logs_per_job))
        self._on_evict = on_evict

    def set_on_evict(self, callback: Callable[[JobRecord], None] | None) -> None:
        """Attach an eviction callback (e.g. to purge expired artifact storage keys)."""
        with self._lock:
            self._on_evict = callback

    @staticmethod
    def _snapshot(rec: JobRecord) -> JobRecord:
        return replace(rec, logs=list(rec.logs))

    def _is_cancelled(self, job_id: str) -> bool:
        ev = self._cancel_events.get(job_id)
        return ev.is_set() if ev is not None else False

    def _update(
        self,
        job_id: str,
        *,
        status: JobStatus | None = None,
        progress: int | None = None,
        message: str | None = None,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> JobRecord | None:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return None
            if status is not None:
                rec.status = status
            if progress is not None:
                rec.progress = progress
            if message is not None:
                rec.message = message
            if error is not None:
                rec.error = error
            if started_at is not None:
                rec.started_at = started_at
            if finished_at is not None:
                rec.finished_at = finished_at
            return self._snapshot(rec)

    def _append_log(self, job_id: str, line: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {line}"
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return
            rec.logs.append(entry)
            if len(rec.logs) > self._max_logs:
                del rec.logs[: len(rec.logs) - self._max_logs]

    def _attach_artifact(self, job_id: str, *, key: str, filename: str, content_type: str) -> None:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is not None:
                rec.artifact_key = key
                rec.artifact_filename = filename
                rec.artifact_mime = content_type

    def _evict_terminal_locked(self) -> list[JobRecord]:
        evicted: list[JobRecord] = []
        if len(self._jobs) <= self._max_history:
            return evicted
        terminal_ids = [
            jid for jid, item in self._jobs.items() if item.status in TERMINAL_JOB_STATUSES
        ]
        for jid in terminal_ids:
            if len(self._jobs) <= self._max_history:
                break
            old = self._jobs.pop(jid, None)
            self._cancel_events.pop(jid, None)
            self._callables.pop(jid, None)
            if old is not None:
                evicted.append(self._snapshot(old))
        return evicted

    def can_retry(self, job_id: str) -> bool:
        with self._lock:
            rec = self._jobs.get(job_id)
            return (
                rec is not None
                and rec.status in {"failed", "cancelled"}
                and job_id in self._callables
            )

    def retry(self, job_id: str) -> JobRecord | None:
        with self._lock:
            rec = self._jobs.get(job_id)
            spec = self._callables.get(job_id)
            if rec is None or spec is None or rec.status not in {"failed", "cancelled"}:
                return None
            fn, app, on_complete = spec
        return self.submit(
            name=rec.name,
            label=f"Retry: {rec.label}",
            actor_id=rec.actor_id,
            actor_name=rec.actor_name,
            model_slug=rec.model_slug,
            fn=fn,
            app=app,
            on_complete=on_complete,
        )

    def submit(
        self,
        *,
        name: str,
        label: str,
        actor_id: str,
        actor_name: str,
        model_slug: str,
        fn: JobCallable,
        app: Flask | None = None,
        on_complete: Callable[[JobRecord], None] | None = None,
    ) -> JobRecord:
        job_id = uuid.uuid4().hex[:16]
        rec = JobRecord(
            id=job_id,
            name=name,
            label=label,
            actor_id=actor_id,
            actor_name=actor_name,
            model_slug=model_slug,
        )
        cancel_ev = threading.Event()
        with self._lock:
            self._jobs[job_id] = rec
            self._cancel_events[job_id] = cancel_ev
            self._callables[job_id] = (fn, app, on_complete)
            evicted = self._evict_terminal_locked()
            evict_cb = self._on_evict
            initial_snapshot = self._snapshot(rec)

        if evict_cb is not None:
            for old_rec in evicted:
                try:
                    evict_cb(old_rec)
                except Exception as exc:
                    logger.warning("Job eviction cleanup error for %s: %s", old_rec.id, exc)

        def _runner() -> None:
            with self._lock:
                cur = self._jobs.get(job_id)
                if cur is None:
                    return
                if cancel_ev.is_set() or cur.status == "cancelled":
                    cur.status = "cancelled"
                    cur.message = "Cancelled before start"
                    cur.finished_at = cur.finished_at or datetime.now(timezone.utc)
                    cancelled_snap = self._snapshot(cur)
                else:
                    cur.status = "running"
                    cur.progress = 5
                    cur.message = "Running…"
                    cur.started_at = datetime.now(timezone.utc)
                    cancelled_snap = None

            if cancelled_snap is not None:
                _invoke_completion(job_id, cancelled_snap, app, on_complete)
                return

            _execute_job(self, job_id, cancel_ev, fn, app, on_complete)

        self._executor.submit(_runner)
        return initial_snapshot

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            rec = self._jobs.get(job_id)
            return self._snapshot(rec) if rec is not None else None

    def list_jobs(
        self,
        *,
        actor_id: str | None = None,
        limit: int = 50,
    ) -> list[JobRecord]:
        with self._lock:
            items = [self._snapshot(j) for j in reversed(self._jobs.values())]
        if actor_id is not None:
            items = [j for j in items if j.actor_id == actor_id]
        return items[: max(1, limit)]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            rec = self._jobs.get(job_id)
            ev = self._cancel_events.get(job_id)
            if rec is None or ev is None or rec.status in TERMINAL_JOB_STATUSES:
                return False
            ev.set()
            if rec.status == "queued":
                rec.status = "cancelled"
                rec.message = "Cancelled"
                rec.finished_at = datetime.now(timezone.utc)
            return True

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = True) -> None:
        """Gracefully shut down the background worker thread pool."""
        self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)


class SQLAlchemyJobBackend:
    """Multi-worker durable job store backed by SQLAlchemy (PostgreSQL / MySQL / SQLite)."""

    def __init__(
        self,
        engine: Engine | None = None,
        *,
        db_uri: str | None = None,
        max_workers: int = 2,
        max_logs_per_job: int = 100,
        callable_resolver: Callable[[str], JobCallable | None] | None = None,
    ) -> None:
        if engine is None and not db_uri:
            raise ValueError("Provide engine or db_uri for SQLAlchemyJobBackend")
        self._owned_engine = engine is None
        if engine is None:
            assert db_uri is not None
            kwargs: dict[str, Any] = {}
            if db_uri.startswith("sqlite"):
                kwargs["connect_args"] = {"check_same_thread": False}
            self._engine: Engine = sa.create_engine(db_uri, **kwargs)
        else:
            self._engine = engine

        self._meta = sa.MetaData()
        self._table = sa.Table(
            "deck_jobs",
            self._meta,
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("label", sa.String(255), nullable=False),
            sa.Column("actor_id", sa.String(128), nullable=False, index=True),
            sa.Column("actor_name", sa.String(128), nullable=False),
            sa.Column("model_slug", sa.String(128), nullable=False, default=""),
            sa.Column("status", sa.String(24), nullable=False, index=True),
            sa.Column("progress", sa.Integer, nullable=False, default=0),
            sa.Column("message", sa.Text, nullable=False, default="Queued"),
            sa.Column("logs_json", sa.Text, nullable=False, default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("artifact_key", sa.String(512), nullable=True),
            sa.Column("artifact_filename", sa.String(255), nullable=True),
            sa.Column("artifact_mime", sa.String(128), nullable=True),
            sa.Column("error", sa.Text, nullable=True),
        )
        self._meta.create_all(self._engine, checkfirst=True)
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)),
            thread_name_prefix="flask-deck-sajob",
        )
        self._lock = threading.Lock()
        self._cancel_events: dict[str, threading.Event] = {}
        self._callables: dict[
            str, tuple[JobCallable, Flask | None, Callable[[JobRecord], None] | None]
        ] = {}
        self._max_logs = max(10, int(max_logs_per_job))
        self._callable_resolver = callable_resolver

    @staticmethod
    def _row_to_record(row: Any) -> JobRecord:
        try:
            logs_raw = json.loads(row.logs_json or "[]")
            logs = [str(x) for x in logs_raw] if isinstance(logs_raw, list) else []
        except Exception:
            logs = []
        return JobRecord(
            id=str(row.id),
            name=str(row.name),
            label=str(row.label),
            actor_id=str(row.actor_id),
            actor_name=str(row.actor_name),
            model_slug=str(row.model_slug or ""),
            status=row.status,
            progress=int(row.progress or 0),
            message=str(row.message or ""),
            logs=logs,
            created_at=_ensure_utc(row.created_at) or datetime.now(timezone.utc),
            started_at=_ensure_utc(row.started_at),
            finished_at=_ensure_utc(row.finished_at),
            artifact_key=row.artifact_key,
            artifact_filename=row.artifact_filename,
            artifact_mime=row.artifact_mime,
            error=row.error,
        )

    def set_callable_resolver(self, resolver: Callable[[str], JobCallable | None] | None) -> None:
        self._callable_resolver = resolver

    def _is_cancelled(self, job_id: str) -> bool:
        ev = self._cancel_events.get(job_id)
        if ev is not None and ev.is_set():
            return True
        with self._engine.connect() as conn:
            st = conn.execute(
                sa.select(self._table.c.status).where(self._table.c.id == job_id)
            ).scalar_one_or_none()
            return st == "cancelled"

    def _update(
        self,
        job_id: str,
        *,
        status: JobStatus | None = None,
        progress: int | None = None,
        message: str | None = None,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> JobRecord | None:
        values: dict[str, Any] = {}
        if status is not None:
            values["status"] = status
        if progress is not None:
            values["progress"] = progress
        if message is not None:
            values["message"] = message
        if error is not None:
            values["error"] = error
        if started_at is not None:
            values["started_at"] = started_at
        if finished_at is not None:
            values["finished_at"] = finished_at
        if values:
            with self._engine.begin() as conn:
                conn.execute(
                    self._table.update().where(self._table.c.id == job_id).values(**values)
                )
        return self.get(job_id)

    def _append_log(self, job_id: str, line: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {line}"
        with self._lock, self._engine.begin() as conn:
            raw = conn.execute(
                sa.select(self._table.c.logs_json).where(self._table.c.id == job_id)
            ).scalar_one_or_none()
            if raw is None:
                return
            try:
                logs = json.loads(raw) if raw else []
            except Exception:
                logs = []
            logs.append(entry)
            if len(logs) > self._max_logs:
                logs = logs[-self._max_logs :]
            conn.execute(
                self._table.update()
                .where(self._table.c.id == job_id)
                .values(logs_json=json.dumps(logs))
            )

    def _attach_artifact(self, job_id: str, *, key: str, filename: str, content_type: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                self._table.update()
                .where(self._table.c.id == job_id)
                .values(artifact_key=key, artifact_filename=filename, artifact_mime=content_type)
            )

    def _resolve_retry_spec(
        self, rec: JobRecord
    ) -> tuple[JobCallable, Flask | None, Callable[[JobRecord], None] | None] | None:
        with self._lock:
            spec = self._callables.get(rec.id)
        if spec is not None:
            return spec
        if self._callable_resolver is not None:
            fn = self._callable_resolver(rec.name)
            if fn is not None:
                return (fn, None, None)
        return None

    def can_retry(self, job_id: str) -> bool:
        rec = self.get(job_id)
        if rec is None or rec.status not in {"failed", "cancelled"}:
            return False
        return self._resolve_retry_spec(rec) is not None

    def retry(self, job_id: str) -> JobRecord | None:
        rec = self.get(job_id)
        if rec is None or rec.status not in {"failed", "cancelled"}:
            return None
        spec = self._resolve_retry_spec(rec)
        if spec is None:
            return None
        fn, app, on_complete = spec
        return self.submit(
            name=rec.name,
            label=f"Retry: {rec.label}",
            actor_id=rec.actor_id,
            actor_name=rec.actor_name,
            model_slug=rec.model_slug,
            fn=fn,
            app=app,
            on_complete=on_complete,
        )

    def submit(
        self,
        *,
        name: str,
        label: str,
        actor_id: str,
        actor_name: str,
        model_slug: str,
        fn: JobCallable,
        app: Flask | None = None,
        on_complete: Callable[[JobRecord], None] | None = None,
    ) -> JobRecord:
        job_id = uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc)
        rec = JobRecord(
            id=job_id,
            name=name,
            label=label,
            actor_id=actor_id,
            actor_name=actor_name,
            model_slug=model_slug,
            created_at=now,
        )
        with self._engine.begin() as conn:
            conn.execute(
                self._table.insert().values(
                    id=job_id,
                    name=name,
                    label=label,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    model_slug=model_slug,
                    status="queued",
                    progress=0,
                    message="Queued",
                    logs_json="[]",
                    created_at=now,
                )
            )
        cancel_ev = threading.Event()
        with self._lock:
            self._cancel_events[job_id] = cancel_ev
            self._callables[job_id] = (fn, app, on_complete)
            if len(self._callables) > 200:
                oldest = next(iter(self._callables))
                self._callables.pop(oldest, None)

        def _runner() -> None:
            cur = self.get(job_id)
            if cur is None:
                return
            if cancel_ev.is_set() or cur.status == "cancelled":
                cancelled = self._update(
                    job_id,
                    status="cancelled",
                    message="Cancelled before start",
                    finished_at=cur.finished_at or datetime.now(timezone.utc),
                )
                _invoke_completion(job_id, cancelled, app, on_complete)
                return
            self._update(
                job_id,
                status="running",
                progress=5,
                message="Running…",
                started_at=datetime.now(timezone.utc),
            )
            _execute_job(self, job_id, cancel_ev, fn, app, on_complete)

        self._executor.submit(_runner)
        return rec

    def get(self, job_id: str) -> JobRecord | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._table).where(self._table.c.id == job_id)
            ).first()
            return self._row_to_record(row) if row is not None else None

    def list_jobs(
        self,
        *,
        actor_id: str | None = None,
        limit: int = 50,
    ) -> list[JobRecord]:
        stmt = sa.select(self._table)
        if actor_id is not None:
            stmt = stmt.where(self._table.c.actor_id == actor_id)
        stmt = stmt.order_by(self._table.c.created_at.desc(), self._table.c.id.desc()).limit(
            max(1, limit)
        )
        with self._engine.connect() as conn:
            return [self._row_to_record(r) for r in conn.execute(stmt)]

    def cancel(self, job_id: str) -> bool:
        ev = self._cancel_events.get(job_id)
        if ev is not None:
            ev.set()
        now = datetime.now(timezone.utc)
        with self._engine.begin() as conn:
            cur = conn.execute(
                sa.select(self._table.c.status).where(self._table.c.id == job_id)
            ).scalar_one_or_none()
            if cur is None or cur in TERMINAL_JOB_STATUSES:
                return False
            if cur == "queued":
                conn.execute(
                    self._table.update()
                    .where(self._table.c.id == job_id)
                    .values(status="cancelled", message="Cancelled", finished_at=now)
                )
            else:
                conn.execute(
                    self._table.update()
                    .where(self._table.c.id == job_id)
                    .values(status="cancelled", message="Cancellation requested")
                )
            return True

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = True) -> None:
        """Stop executor threads cleanly and dispose owned engine."""
        self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)
        if self._owned_engine:
            self._engine.dispose()
