from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.exc import SQLAlchemyError

from flask_deck.adapters.sqlalchemy import encode_pk
from flask_deck.audit import AuditEntry, compute_diff
from flask_deck.exceptions import PermissionDeniedError, ValidationError
from flask_deck.i18n import LOCALE_SESSION_KEY, TZ_SESSION_KEY, is_valid_timezone, normalize_locale
from flask_deck.model_view import coerce_form_value
from flask_deck.security import is_safe_redirect_url, sanitize_csv_cell

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_governance_routes(bp: Blueprint, deck: Deck) -> None:
    """Register Audit Ledger, Safe Revert, RBAC Matrix, and User Preferences routes."""
    bp_name = deck.config.name

    @bp.route("/_preferences", methods=["POST"])
    def update_preferences() -> Any:
        if not deck.config.enable_user_preferences:
            abort(404)
        req_locale = request.form.get("locale", "").strip()
        req_tz = request.form.get("timezone", "").strip()
        if req_locale:
            norm = normalize_locale(req_locale)
            if deck.config.available_locales and norm not in deck.config.available_locales:
                abort(400, description="Unsupported locale.")
            session[LOCALE_SESSION_KEY] = norm
        if req_tz:
            if not is_valid_timezone(req_tz):
                abort(400, description="Invalid IANA timezone.")
            session[TZ_SESSION_KEY] = req_tz
        nxt = request.form.get("next", "").strip()
        dest = nxt if is_safe_redirect_url(nxt) else url_for(f"{bp_name}.index")
        return redirect(dest)

    def _parse_date_bounds(
        raw_from: str, raw_to: str
    ) -> tuple[datetime | None, datetime | None]:
        dt_from: datetime | None = None
        dt_to: datetime | None = None
        if raw_from:
            try:
                dt_from = datetime.strptime(raw_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                dt_from = None
        if raw_to:
            try:
                dt_to = datetime.strptime(raw_to, "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc
                )
            except ValueError:
                dt_to = None
        return dt_from, dt_to

    @bp.route("/_audit")
    def audit_list() -> str:
        if deck.audit_store is None:
            abort(404)
        deck._require_perm("audit:view")
        user = deck._current_user()
        model_filter = request.args.get("model", "").strip() or None
        action_filter = request.args.get("action", "").strip() or None
        actor_filter = request.args.get("actor", "").strip() or None
        q = request.args.get("q", "").strip() or None
        date_from_str = request.args.get("date_from", "").strip()
        date_to_str = request.args.get("date_to", "").strip()
        dt_from, dt_to = _parse_date_bounds(date_from_str, date_to_str)
        try:
            page = max(1, min(1_000_000, int(request.args.get("page", "1"))))
        except ValueError:
            page = 1
        limit = 40
        excluded_models = deck._excluded_audit_models(user)
        search_changes = not deck._user_has_field_restrictions(user)
        raw_entries, total = deck.audit_store.list_entries(
            model_slug=model_filter,
            action=action_filter,
            actor=actor_filter,
            search=q,
            date_from=dt_from,
            date_to=dt_to,
            excluded_models=excluded_models,
            search_changes=search_changes,
            limit=limit,
            offset=(page - 1) * limit,
        )
        entries = [deck._sanitize_audit_entry(e, user) for e in raw_entries]
        audit_models = [
            (slug, v)
            for slug, v in deck.views.items()
            if slug not in excluded_models
        ]
        pages = max(1, (total + limit - 1) // limit)
        can_revert = (
            deck.config.enable_audit_revert
            and not deck.config.read_only
            and deck.auth.has_permission(user, "audit:revert")
        )
        hash_chain_enabled = bool(getattr(deck.audit_store, "hash_chain", False))
        hash_chain_valid = True
        if hash_chain_enabled and hasattr(deck.audit_store, "verify_chain"):
            hash_chain_valid, _ = deck.audit_store.verify_chain()
        return render_template(
            "flask_deck/audit_list.html",
            **deck._base_context(
                page_title="Audit Ledger",
                active_nav="_audit",
                entries=entries,
                total=total,
                page=page,
                pages=pages,
                model_filter=model_filter or "",
                action_filter=action_filter or "",
                actor_filter=actor_filter or "",
                search_term=q or "",
                date_from=date_from_str,
                date_to=date_to_str,
                can_revert=can_revert,
                audit_models=audit_models,
                hash_chain_enabled=hash_chain_enabled,
                hash_chain_valid=hash_chain_valid,
            ),
        )

    @bp.route("/_audit/export")
    def audit_export() -> Response:
        if deck.audit_store is None:
            abort(404)
        deck._require_perm("audit:view")
        user = deck._current_user()
        fmt = request.args.get("format", "csv").strip().lower()
        if fmt not in {"csv", "jsonl"}:
            abort(400, description="Unsupported export format. Use 'csv' or 'jsonl'.")
        model_filter = request.args.get("model", "").strip() or None
        action_filter = request.args.get("action", "").strip() or None
        actor_filter = request.args.get("actor", "").strip() or None
        q = request.args.get("q", "").strip() or None
        date_from_str = request.args.get("date_from", "").strip()
        date_to_str = request.args.get("date_to", "").strip()
        dt_from, dt_to = _parse_date_bounds(date_from_str, date_to_str)
        excluded_models = deck._excluded_audit_models(user)
        search_changes = not deck._user_has_field_restrictions(user)
        store = deck.audit_store

        def _iter_sanitized() -> Iterator[AuditEntry]:
            offset = 0
            batch_size = 500
            while True:
                batch, total_cnt = store.list_entries(
                    model_slug=model_filter,
                    action=action_filter,
                    actor=actor_filter,
                    search=q,
                    date_from=dt_from,
                    date_to=dt_to,
                    excluded_models=excluded_models,
                    search_changes=search_changes,
                    limit=batch_size,
                    offset=offset,
                )
                if not batch:
                    break
                for entry in batch:
                    yield deck._sanitize_audit_entry(entry, user)
                offset += len(batch)
                if offset >= total_cnt:
                    break

        if fmt == "jsonl":
            def _gen_jsonl() -> Iterator[str]:
                for e in _iter_sanitized():
                    row = {
                        "id": e.id,
                        "timestamp": e.timestamp.isoformat(),
                        "actor_id": e.actor_id,
                        "actor_name": e.actor_name,
                        "actor_ip": e.actor_ip,
                        "action": e.action,
                        "model_slug": e.model_slug,
                        "model_label": e.model_label,
                        "record_pk": e.record_pk,
                        "record_repr": e.record_repr,
                        "changes": e.changes,
                        "metadata": e.metadata,
                        "prev_hash": e.prev_hash,
                        "entry_hash": e.entry_hash,
                    }
                    yield json.dumps(row, default=str) + "\n"

            return Response(
                _gen_jsonl(),
                mimetype="application/x-ndjson; charset=utf-8",
                headers={
                    "Content-Disposition": 'attachment; filename="flask_deck_audit.jsonl"'
                },
            )

        def _gen_csv() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                [
                    "id",
                    "timestamp",
                    "actor_id",
                    "actor_name",
                    "actor_ip",
                    "action",
                    "model_slug",
                    "model_label",
                    "record_pk",
                    "record_repr",
                    "changes_json",
                    "metadata_json",
                    "prev_hash",
                    "entry_hash",
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            for e in _iter_sanitized():
                writer.writerow(
                    [
                        sanitize_csv_cell(e.id),
                        sanitize_csv_cell(e.timestamp.isoformat()),
                        sanitize_csv_cell(e.actor_id),
                        sanitize_csv_cell(e.actor_name),
                        sanitize_csv_cell(e.actor_ip),
                        sanitize_csv_cell(e.action),
                        sanitize_csv_cell(e.model_slug),
                        sanitize_csv_cell(e.model_label),
                        sanitize_csv_cell(e.record_pk),
                        sanitize_csv_cell(e.record_repr),
                        sanitize_csv_cell(json.dumps(e.changes, default=str)),
                        sanitize_csv_cell(json.dumps(e.metadata, default=str)),
                        sanitize_csv_cell(e.prev_hash),
                        sanitize_csv_cell(e.entry_hash),
                    ]
                )
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        return Response(
            _gen_csv(),
            mimetype="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="flask_deck_audit.csv"'
            },
        )

    @bp.route("/_audit/<entry_id>/revert", methods=["POST"])
    def audit_revert(entry_id: str) -> Any:
        if deck.audit_store is None or not deck.config.enable_audit_revert:
            abort(404)
        deck._require_perm("audit:revert")
        entry = deck.audit_store.get_entry(entry_id)
        if entry is None or not entry.is_revertible:
            abort(404)
        view = deck.get_view(entry.model_slug)
        if not view.can_edit:
            abort(403)
        deck._require_perm(f"{view.meta.slug}:edit", model_slug=view.meta.slug)
        obj, pk_vals = deck._fetch_scoped_record(view, entry.record_pk)
        deck._require_perm(f"{view.meta.slug}:edit", model_slug=view.meta.slug, obj=obj)

        if (
            deck.config.environment == "production"
            and deck.config.require_confirm_text_in_prod
            and request.form.get("confirm_text", "").strip() != "REVERT"
        ):
            flash("Production safeguard: enter 'REVERT' to confirm rollback.", "danger")
            return redirect(url_for(f"{bp_name}.audit_list"))

        user = deck._current_user()
        writable = set(view.allowed_form_fields(deck.auth, user, mode="edit"))
        masked = deck.auth.masked_fields_for(user, view.meta.slug)
        before_snap = view.extract_snapshot(obj)
        sess = deck.get_session(view.bind_key)
        reverted_values: dict[str, Any] = {}

        try:
            for fname, delta in entry.changes.items():
                if (
                    fname not in writable
                    or fname in masked
                    or fname in view.meta.sensitive_fields
                    or fname in view.file_fields
                ):
                    continue
                old_val = delta.get("old")
                if old_val == "[REDACTED]":
                    continue
                fmeta = view.meta.fields_by_name.get(fname)
                if fmeta is None or fmeta.field_type == "binary":
                    continue
                coerced = (
                    None
                    if old_val is None
                    else coerce_form_value(
                        old_val,
                        fmeta,
                        max_json_depth=deck.config.max_json_depth,
                        utc_passthrough=True,
                    )
                )
                reverted_values[fname] = coerced
            if not reverted_values:
                flash("No revertible fields remain writable on this record.", "warn")
                return redirect(url_for(f"{bp_name}.audit_list"))
            custom_errs = view.validate(reverted_values, obj=obj)
            if custom_errs:
                raise ValidationError(custom_errs)
            val_fn = view.get_form_validator()
            if val_fn is not None:
                ext_errs = val_fn({**before_snap, **reverted_values}, obj, False)
                if ext_errs:
                    raise ValidationError(dict(ext_errs))
            for fname, coerced in reverted_values.items():
                setattr(obj, fname, coerced)
            view.on_model_change(obj, is_created=False, user=user)
            sess.commit()
        except (ValueError, ValidationError, SQLAlchemyError) as exc:
            sess.rollback()
            flash(f"Revert failed: {exc}", "danger")
            return redirect(url_for(f"{bp_name}.audit_list"))

        reverted_fields = len(reverted_values)
        pk_str = encode_pk(pk_vals)
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        after_snap = view.extract_snapshot(obj)
        diff = compute_diff(
            before_snap,
            after_snap,
            sensitive_fields=view.meta.sensitive_fields,
            extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
        )
        deck._record_audit(
            action_name="revert",
            view=view,
            record_pk=pk_str,
            record_repr=safe_repr,
            changes=diff,
            metadata={"reverted_entry_id": entry.id, "fields": reverted_fields},
        )
        deck._emit_event(
            "record.updated",
            model_slug=view.meta.slug,
            record_pk=pk_str,
            payload={"reverted_entry_id": entry.id, "fields": sorted(reverted_values.keys())},
        )
        flash(f"Reverted {reverted_fields} field(s) on {safe_repr}.", "ok")
        return redirect(url_for(f"{bp_name}.audit_list"))

    @bp.route("/_rbac")
    def rbac_matrix() -> str:
        roles = list(deck.auth.get_roles())
        if not roles:
            abort(404)
        deck._require_perm("rbac:view")
        actions = ("view", "create", "edit", "delete", "export", "import")
        matrix: list[dict[str, Any]] = []
        for role in roles:
            model_rows = []
            for v in deck.views.values():
                slug = v.meta.slug
                grants = {act: role.grants(f"{slug}:{act}") for act in actions}
                hidden = sorted(
                    set(role.hidden_fields.get("*", ())) | set(role.hidden_fields.get(slug, ()))
                )
                readonly = sorted(
                    set(role.readonly_fields.get("*", ()))
                    | set(role.readonly_fields.get(slug, ()))
                )
                masked = sorted(
                    set(role.masked_fields.get("*", ())) | set(role.masked_fields.get(slug, ()))
                )
                model_rows.append(
                    {
                        "slug": slug,
                        "label": v.plural_label,
                        "grants": grants,
                        "hidden": hidden,
                        "readonly": readonly,
                        "masked": masked,
                    }
                )
            matrix.append(
                {
                    "role": role,
                    "audit_view": role.grants("audit:view"),
                    "audit_revert": role.grants("audit:revert"),
                    "models": model_rows,
                }
            )
        return render_template(
            "flask_deck/rbac_matrix.html",
            **deck._base_context(
                page_title="RBAC Policy Matrix",
                active_nav="_rbac",
                actions=actions,
                matrix=matrix,
            ),
        )

    @bp.route("/_approvals")
    def approvals_list() -> str:
        if deck.approval_store is None:
            abort(404)
        user = deck._current_user()
        can_view = user is not None and (
            user.is_superuser
            or deck.auth.has_permission(user, "approvals:view")
            or deck.auth.has_permission(user, "approvals:review")
        )
        if not can_view:
            raise PermissionDeniedError("Missing permission: approvals:view")
        status_filter = request.args.get("status", "pending").strip().lower()
        if status_filter not in {"pending", "approved", "rejected", "cancelled", "all"}:
            status_filter = "pending"
        model_filter = request.args.get("model", "").strip() or None
        raw_reqs = deck.approval_store.list_requests(
            status=None if status_filter == "all" else status_filter,
            model_slug=model_filter,
            limit=100,
        )
        sanitized_reqs: list[dict[str, Any]] = []
        for req in raw_reqs:
            hidden = deck.auth.hidden_fields_for(user, req.model_slug)
            filtered_diff = {
                k: v for k, v in req.diff.items() if k not in hidden
            }
            sanitized_reqs.append({"req": req, "diff": filtered_diff})
        can_review = (
            not deck.config.read_only
            and user is not None
            and (user.is_superuser or deck.auth.has_permission(user, "approvals:review"))
        )
        return render_template(
            "flask_deck/approvals_list.html",
            **deck._base_context(
                page_title="Approval Queue",
                active_nav="_approvals",
                requests_list=sanitized_reqs,
                status_filter=status_filter,
                model_filter=model_filter or "",
                can_review=can_review,
                current_user_id=user.id if user else "",
            ),
        )

    @bp.route("/_approvals/<approval_id>/approve", methods=["POST"])
    def approval_approve(approval_id: str) -> Any:
        if deck.approval_store is None:
            abort(404)
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "approvals:review")
        ):
            raise PermissionDeniedError("Missing permission: approvals:review")
        req = deck.approval_store.get(approval_id)
        if req is None:
            abort(404)
        if user.id == req.requester_id:
            raise PermissionDeniedError("Four-eyes policy forbids approving your own request.")
        if req.status != "pending":
            flash(f"Approval #{req.id} is already {req.status}.", "warn")
            return redirect(url_for(f"{bp_name}.approvals_list"))

        review_note = request.form.get("review_note", "").strip()[:500]
        resolved = deck.approval_store.resolve(
            req.id,
            status="approved",
            reviewer_id=user.id,
            reviewer_name=user.label,
            review_note=review_note,
        )
        if resolved is None:
            flash(
                "Approval request could not be resolved (already processed or four-eyes conflict).",
                "warn",
            )
            return redirect(url_for(f"{bp_name}.approvals_list"))

        try:
            deck._execute_approved_request(resolved, reviewer=user)
        except (ValueError, ValidationError, SQLAlchemyError) as exc:
            target_view = deck.views.get(resolved.model_slug)
            if target_view is not None:
                deck.get_session(target_view.bind_key).rollback()
            flash(f"Approved request #{resolved.id} failed during execution: {exc}", "danger")
            return redirect(url_for(f"{bp_name}.approvals_list"))

        flash(
            f"Approved and executed {resolved.model_label} {resolved.operation} (#{resolved.id}).",
            "ok",
        )
        return redirect(url_for(f"{bp_name}.approvals_list"))

    @bp.route("/_approvals/<approval_id>/reject", methods=["POST"])
    def approval_reject(approval_id: str) -> Any:
        if deck.approval_store is None:
            abort(404)
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "approvals:review")
        ):
            raise PermissionDeniedError("Missing permission: approvals:review")
        req = deck.approval_store.get(approval_id)
        if req is None:
            abort(404)
        if user.id == req.requester_id:
            raise PermissionDeniedError("Four-eyes policy forbids rejecting your own request.")
        if req.status != "pending":
            flash(f"Approval #{req.id} is already {req.status}.", "warn")
            return redirect(url_for(f"{bp_name}.approvals_list"))

        review_note = request.form.get("review_note", "").strip()[:500]
        resolved = deck.approval_store.resolve(
            req.id,
            status="rejected",
            reviewer_id=user.id,
            reviewer_name=user.label,
            review_note=review_note,
        )
        if resolved is None:
            flash("Approval request is no longer pending.", "warn")
            return redirect(url_for(f"{bp_name}.approvals_list"))

        target_view = deck.views.get(resolved.model_slug)
        if target_view is not None:
            deck._record_audit(
                action_name="approval_rejected",
                view=target_view,
                record_pk=resolved.record_pk,
                record_repr=resolved.record_repr,
                changes={"status": {"old": "pending", "new": "rejected"}},
                metadata={
                    "approval_id": resolved.id,
                    "operation": resolved.operation,
                    "requester_id": resolved.requester_id,
                    "reviewer_id": user.id,
                    "review_note": review_note,
                    "actor_type": resolved.actor_type,
                },
            )
        deck._emit_event(
            "approval.rejected",
            model_slug=resolved.model_slug,
            record_pk=resolved.record_pk,
            payload={
                "approval_id": resolved.id,
                "operation": resolved.operation,
                "reviewer_id": user.id,
                "review_note": review_note,
            },
        )
        flash(f"Rejected approval request #{resolved.id}.", "ok")
        return redirect(url_for(f"{bp_name}.approvals_list"))
