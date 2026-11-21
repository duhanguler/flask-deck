from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

from flask import Flask

logger = logging.getLogger("flask_deck.jobs")

JobStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]
TERMINAL_JOB_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "cancelled"})


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
            end = self.finished_at or datetime.now(timezone.utc)
            duration_ms = max(0, int((end - self.started_at).total_seconds() * 1000))
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
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": duration_ms,
            "artifact_filename": self.artifact_filename,
            "error": self.error,
        }


class JobContext:
    """Progress, log, artifact, and cancellation controller passed to async job functions."""

    __slots__ = ("_backend", "_cancel_event", "job_id")

    def __init__(
        self,
        backend: ThreadPoolJobBackend,
        job_id: str,
        cancel_event: threading.Event,
    ) -> None:
        self._backend = backend
        self.job_id = job_id
        self._cancel_event = cancel_event

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

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


@runtime_checkable
class JobBackend(Protocol):
    """Pluggable background job runner contract (ThreadPool built-in; Celery/RQ adaptable)."""

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


class ThreadPoolJobBackend:
    """Zero-dependency bounded thread-pool job runner with Flask app_context propagation."""

    __slots__ = (
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
            if old is not None:
                evicted.append(self._snapshot(old))
        return evicted

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
            evicted = self._evict_terminal_locked()
            evict_cb = self._on_evict
            initial_snapshot = self._snapshot(rec)

        if evict_cb is not None:
            for old_rec in evicted:
                try:
                    evict_cb(old_rec)
                except Exception as exc:
                    logger.warning("Job eviction cleanup error for %s: %s", old_rec.id, exc)

        ctx = JobContext(self, job_id, cancel_ev)

        def _invoke_on_complete(final_rec: JobRecord | None) -> None:
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

        def _runner() -> None:
            # Atomically check cancellation and transition queued -> running under _lock
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
                _invoke_on_complete(cancelled_snap)
                return

            try:
                if app is not None:
                    with app.app_context():
                        result_msg = fn(ctx)
                else:
                    result_msg = fn(ctx)
                if cancel_ev.is_set():
                    final = self._update(
                        job_id,
                        status="cancelled",
                        message="Cancelled by operator",
                        finished_at=datetime.now(timezone.utc),
                    )
                else:
                    final = self._update(
                        job_id,
                        status="succeeded",
                        progress=100,
                        message=result_msg or "Completed successfully",
                        finished_at=datetime.now(timezone.utc),
                    )
            except Exception as exc:
                self._append_log(job_id, f"ERROR: {exc}")
                final = self._update(
                    job_id,
                    status="failed",
                    message="Failed",
                    error=str(exc),
                    finished_at=datetime.now(timezone.utc),
                )
            _invoke_on_complete(final)

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
