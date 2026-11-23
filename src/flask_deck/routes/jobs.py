from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    stream_with_context,
    url_for,
)
from werkzeug.exceptions import NotFound

from flask_deck.events import DeckEvent, WebhookSink
from flask_deck.exceptions import PermissionDeniedError
from flask_deck.jobs import TERMINAL_JOB_STATUSES, JobRecord
from flask_deck.storage import sanitize_filename, stream_storage_object

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def get_authorized_job(deck: Deck, job_id: str, *, mode: str = "view") -> JobRecord:
    """Fetch a job and authorize access without leaking job ID existence to unprivileged users."""
    if deck.job_backend is None:
        abort(404)
    user = deck._current_user()
    is_super = user is not None and user.is_superuser
    can_see_any = is_super or (
        mode == "view" and deck.auth.has_permission(user, "jobs:view_all")
    ) or (
        mode == "cancel" and deck.auth.has_permission(user, "jobs:cancel_all")
    )
    rec = deck.job_backend.get(job_id)
    if rec is None:
        if can_see_any:
            abort(404)
        raise PermissionDeniedError("Not authorized to access this background job.")
    is_owner = user is not None and rec.actor_id == user.id
    if mode == "artifact":
        allowed = is_owner or is_super
    elif mode == "cancel":
        allowed = is_owner or is_super or deck.auth.has_permission(user, "jobs:cancel_all")
    else:
        allowed = is_owner or is_super or deck.auth.has_permission(user, "jobs:view_all")
    if not allowed:
        raise PermissionDeniedError("Not authorized to access this background job.")
    return rec


def _safe_last_event_id(raw: str | None) -> int:
    if not raw:
        return -1
    try:
        return int(raw.strip())
    except ValueError:
        return -1


def register_job_routes(bp: Blueprint, deck: Deck) -> None:
    """Register Background Jobs console, JSON polling, SSE streaming, cancel, retry, scheduled & artifacts."""
    bp_name = deck.config.name

    @bp.route("/_jobs")
    def jobs_list() -> str:
        if deck.job_backend is None:
            abort(404)
        user = deck._current_user()
        can_all = deck.auth.has_permission(user, "jobs:view_all") or (
            user is not None and user.is_superuser
        )
        actor_filter = None if can_all else (user.id if user else "__none__")
        jobs = deck.job_backend.list_jobs(actor_id=actor_filter, limit=50)
        can_retry_fn = getattr(deck.job_backend, "can_retry", None)
        retryable_ids = (
            {
                j.id
                for j in jobs
                if j.status in {"failed", "cancelled"} and bool(can_retry_fn(j.id))
            }
            if callable(can_retry_fn)
            else set()
        )
        can_run_scheduled = (
            deck.auth.has_permission(user, "jobs:run_scheduled")
            or (user is not None and user.is_superuser)
        )
        scheduled_jobs = [
            spec
            for spec in deck.scheduled_jobs.values()
            if (
                can_run_scheduled
                or (spec.permission and deck.auth.has_permission(user, spec.permission))
            )
        ]
        focus_id = request.args.get("focus", "").strip()
        return render_template(
            "flask_deck/jobs_list.html",
            **deck._base_context(
                page_title="Background Jobs",
                active_nav="_jobs",
                jobs=jobs,
                retryable_ids=retryable_ids,
                scheduled_jobs=scheduled_jobs,
                focus_id=focus_id,
            ),
        )

    @bp.route("/_api/jobs/<job_id>")
    def api_job_status(job_id: str) -> Any:
        try:
            rec = get_authorized_job(deck, job_id, mode="view")
        except NotFound:
            return jsonify({"error": "Job not found."}), 404
        return jsonify(rec.to_dict())

    @bp.route("/_api/jobs/<job_id>/stream")
    def api_job_stream(job_id: str) -> Any:
        try:
            rec = get_authorized_job(deck, job_id, mode="view")
        except NotFound:
            return jsonify({"error": "Job not found."}), 404
        backend = deck.job_backend
        assert backend is not None
        last_id = _safe_last_event_id(request.headers.get("Last-Event-ID"))
        try:
            req_max = float(request.args.get("max_seconds", "15"))
        except ValueError:
            req_max = 15.0
        max_ticks = max(1, min(120, int(req_max / 0.25)))

        def _gen() -> Iterator[str]:
            yield "retry: 2000\n"
            prev_payload: str | None = None
            seq = max(0, last_id + 1)
            for _ in range(max_ticks):
                cur = backend.get(rec.id)
                if cur is None:
                    break
                payload = json.dumps(cur.to_dict(), sort_keys=True)
                if payload != prev_payload or seq == 0:
                    yield f"id: {seq}\ndata: {payload}\n\n"
                    prev_payload = payload
                    seq += 1
                if cur.status in TERMINAL_JOB_STATUSES:
                    break
                time.sleep(0.25)

        resp = Response(stream_with_context(_gen()), mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-cache, no-store"
        resp.headers["X-Accel-Buffering"] = "no"
        return resp

    @bp.route("/_jobs/<job_id>/cancel", methods=["POST"])
    def job_cancel(job_id: str) -> Any:
        rec = get_authorized_job(deck, job_id, mode="cancel")
        assert deck.job_backend is not None
        if deck.job_backend.cancel(rec.id):
            flash(f"Cancellation requested for job #{rec.id}.", "warn")
        else:
            flash(f"Job #{rec.id} is already finished.", "neutral")
        return redirect(url_for(f"{bp_name}.jobs_list", focus=rec.id))

    @bp.route("/_jobs/<job_id>/retry", methods=["POST"])
    def job_retry(job_id: str) -> Any:
        rec = get_authorized_job(deck, job_id, mode="cancel")
        retry_fn = getattr(deck.job_backend, "retry", None)
        if not callable(retry_fn):
            flash("Configured job backend does not support retries.", "warn")
            return redirect(url_for(f"{bp_name}.jobs_list", focus=rec.id))
        new_rec = retry_fn(rec.id)
        if not isinstance(new_rec, JobRecord):
            flash(f"Job #{rec.id} cannot be retried.", "warn")
            return redirect(url_for(f"{bp_name}.jobs_list", focus=rec.id))
        flash(f"Queued retry job #{new_rec.id} for #{rec.id}.", "ok")
        return redirect(url_for(f"{bp_name}.jobs_list", focus=new_rec.id))

    @bp.route("/_jobs/scheduled/<name>/run", methods=["POST"])
    def scheduled_job_run(name: str) -> Any:
        if deck.job_backend is None:
            abort(404)
        spec = deck.scheduled_jobs.get(name)
        if spec is None:
            abort(404)
        user = deck._current_user()
        allowed = (user is not None and user.is_superuser) or deck.auth.has_permission(
            user, spec.permission or "jobs:run_scheduled"
        )
        if not allowed:
            raise PermissionDeniedError("Not authorized to trigger this scheduled job.")
        rec = deck.run_scheduled_job(spec.name, user=user)
        flash(f"Triggered scheduled job '{spec.label}' (#{rec.id}).", "ok")
        return redirect(url_for(f"{bp_name}.jobs_list", focus=rec.id))

    @bp.route("/_jobs/<job_id>/artifact")
    def job_artifact(job_id: str) -> Response:
        rec = get_authorized_job(deck, job_id, mode="artifact")
        if not rec.artifact_key or not rec.artifact_filename:
            abort(404)
        try:
            chunk_iter, detected = stream_storage_object(deck.job_storage, rec.artifact_key)
        except (FileNotFoundError, ValueError):
            abort(404)
        mime = rec.artifact_mime or detected or "application/octet-stream"
        safe_name = sanitize_filename(rec.artifact_filename)
        resp = Response(chunk_iter, mimetype=mime)
        resp.headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
        resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def _require_webhook_perm() -> Any:
        user = deck._current_user()
        if not (
            (user is not None and user.is_superuser)
            or deck.auth.has_permission(user, "webhooks:view")
        ):
            raise PermissionDeniedError("Missing permission: webhooks:view")
        return user

    @bp.route("/_webhooks")
    def webhooks_list() -> str:
        if not deck.config.enable_webhooks_ui or deck.webhook_delivery_store is None:
            abort(404)
        _require_webhook_perm()
        status_filter = request.args.get("status", "").strip() or None
        deliveries = deck.webhook_delivery_store.list_deliveries(status=status_filter, limit=100)
        return render_template(
            "flask_deck/webhooks_list.html",
            **deck._base_context(
                page_title="Webhooks & DLQ",
                active_nav="_webhooks",
                sinks=deck._webhook_sinks,
                deliveries=deliveries,
                active_status=status_filter or "",
            ),
        )

    @bp.route("/_webhooks/test", methods=["POST"])
    def webhooks_test() -> Any:
        if not deck.config.enable_webhooks_ui or deck.webhook_delivery_store is None:
            abort(404)
        user = _require_webhook_perm()
        if not deck._webhook_sinks:
            flash("No webhook sinks are registered.", "warn")
            return redirect(url_for(f"{bp_name}.webhooks_list"))
        try:
            idx = int(request.form.get("sink_index", "0"))
        except ValueError:
            idx = 0
        if idx < 0 or idx >= len(deck._webhook_sinks):
            abort(404)
        sink: WebhookSink = deck._webhook_sinks[idx]
        test_event = DeckEvent(
            name="webhook.test",
            actor_id=user.id if user else "system",
            actor_name=user.label if user else "System",
            model_slug="_webhooks",
            record_pk=str(idx),
            payload={"ping": True},
        )
        try:
            sink(test_event)
            if sink.async_delivery:
                sink.flush(timeout=2.0)
            flash(f"Dispatched test webhook to {sink.url}.", "ok")
        except Exception as exc:
            flash(f"Webhook test failed: {exc}", "danger")
        return redirect(url_for(f"{bp_name}.webhooks_list"))

    @bp.route("/_webhooks/<delivery_id>/redeliver", methods=["POST"])
    def webhook_redeliver(delivery_id: str) -> Any:
        if not deck.config.enable_webhooks_ui or deck.webhook_delivery_store is None:
            abort(404)
        _require_webhook_perm()
        rec = deck.webhook_delivery_store.get(delivery_id)
        if rec is None:
            abort(404)
        matching_sink = next(
            (s for s in deck._webhook_sinks if s.url == rec.webhook_url), None
        )
        if matching_sink is None:
            flash("Original webhook sink is no longer registered.", "danger")
            return redirect(url_for(f"{bp_name}.webhooks_list"))
        updated = matching_sink.redeliver(rec)
        if updated.status == "delivered":
            flash(f"Redelivered webhook #{updated.id} (HTTP {updated.last_status_code}).", "ok")
        else:
            flash(f"Redelivery failed: {updated.last_error}", "danger")
        return redirect(url_for(f"{bp_name}.webhooks_list"))
