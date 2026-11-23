from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

import sqlalchemy as sa
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup
from sqlalchemy.exc import SQLAlchemyError

from flask_deck.adapters.sqlalchemy import encode_pk, extract_pk
from flask_deck.audit import AuditEntry, compute_diff
from flask_deck.exceptions import PermissionDeniedError, ValidationError
from flask_deck.i18n import to_user_timezone
from flask_deck.icons import render_icon
from flask_deck.model_view import coerce_form_value
from flask_deck.query import build_filter_condition, build_search_clause, soft_delete_predicate
from flask_deck.saved_views import RecordNote, SavedViewRecord, SavedViewScope, render_safe_markdown
from flask_deck.security import CSRF_FORM_FIELD, get_csrf_token

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_api_routes(bp: Blueprint, deck: Deck) -> None:
    """Register internal UI JSON & partial API routes (Cmd-K, FK, Drawer, Quick-Edit, Notifications)."""
    bp_name = deck.config.name

    @bp.route("/_api/search")
    def api_search() -> Response:
        q = request.args.get("q", "").strip()
        user = deck._current_user()
        results: list[dict[str, Any]] = []

        q_lower = q.lower()
        for v in deck.views.values():
            if not v.can_view or not deck.auth.has_permission(
                user, f"{v.meta.slug}:view", model_slug=v.meta.slug
            ):
                continue
            if not q_lower or q_lower in v.plural_label.lower() or q_lower in v.meta.slug:
                results.append(
                    {
                        "kind": "model",
                        "title": v.plural_label,
                        "subtitle": f"Open {v.plural_label} table",
                        "badge": "Model",
                        "url": url_for(f"{bp_name}.model_list", slug=v.meta.slug),
                    }
                )

        if len(q) >= deck.config.search_min_chars:
            for v in deck.views.values():
                if not v.can_view or not v.resolved_searchable:
                    continue
                if not deck.auth.has_permission(
                    user, f"{v.meta.slug}:view", model_slug=v.meta.slug
                ):
                    continue
                allowed_search, _, _ = deck._allowed_query_fields(v, user)
                clause, joins = build_search_clause(v.meta, allowed_search, q)
                if clause is None:
                    continue
                stmt = v.scope_query(sa.select(v.model), user)
                sd_pred = soft_delete_predicate(v.meta, v.soft_delete_column, trashed=False)
                if sd_pred is not None:
                    stmt = stmt.where(sd_pred)
                for rel_attr in joins:
                    stmt = stmt.outerjoin(rel_attr)
                stmt = stmt.where(clause).limit(deck.config.search_limit_per_model)
                for item in deck.get_session(v.bind_key).scalars(stmt).unique().all():
                    pk_str = encode_pk(extract_pk(item, v.meta))
                    results.append(
                        {
                            "kind": "record",
                            "title": v.format_record_repr(item, auth=deck.auth, user=user),
                            "subtitle": f"{v.label} #{pk_str}",
                            "badge": v.label,
                            "url": url_for(f"{bp_name}.model_detail", slug=v.meta.slug, raw_pk=pk_str),
                        }
                    )

        return jsonify({"query": q, "results": results[:24]})

    @bp.route("/_api/fk/<slug>")
    def api_fk(slug: str) -> Response:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        q = request.args.get("q", "").strip()
        dep_col = request.args.get("dep_col", "").strip()
        dep_val = request.args.get("dep_val", "").strip()
        user = deck._current_user()
        restricted = deck.auth.hidden_fields_for(user, slug) | deck.auth.masked_fields_for(
            user, slug
        )
        allowed_search, _, _ = deck._allowed_query_fields(view, user)
        stmt = view.scope_query(sa.select(view.model), user)
        sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
        if sd_pred is not None:
            stmt = stmt.where(sd_pred)
        if (
            dep_col
            and dep_val
            and dep_col in view.meta.fields_by_name
            and dep_col not in restricted
            and not view.meta.fields_by_name[dep_col].is_sensitive
        ):
            cond = build_filter_condition(view.meta, dep_col, dep_val)
            if cond is not None:
                stmt = stmt.where(cond)
        if q and allowed_search:
            clause, joins = build_search_clause(view.meta, allowed_search, q)
            for rel_attr in joins:
                stmt = stmt.outerjoin(rel_attr)
            if clause is not None:
                stmt = stmt.where(clause)
        stmt = stmt.order_by(getattr(view.model, view.meta.primary_keys[0].name).asc()).limit(25)
        items = list(deck.get_session(view.bind_key).scalars(stmt).unique().all())
        return jsonify(
            {
                "items": [
                    {
                        "id": encode_pk(extract_pk(it, view.meta)),
                        "label": view.format_record_repr(it, auth=deck.auth, user=user),
                    }
                    for it in items
                ]
            }
        )

    @bp.route("/_api/<slug>/<raw_pk>/drawer")
    def api_drawer(slug: str, raw_pk: str) -> str:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()
        hidden = deck.auth.hidden_fields_for(user, slug)
        is_soft_deleted = deck._is_soft_deleted(view, obj)

        media_builder = deck._media_url_builder(view)
        rel_url_builder = deck._rel_url_builder(user)
        fields_display = []
        for f in view.meta.fields:
            if f.name in hidden or f.is_sensitive:
                continue
            fk_rel = view.meta.fk_column_to_rel.get(f.name)
            col_key = fk_rel.name if (fk_rel is not None and fk_rel.name not in hidden) else f.name
            fields_display.append(
                {
                    "name": f.name,
                    "label": view.get_column_label(f.name),
                    "formatted": view.format_cell(
                        col_key,
                        obj,
                        auth=deck.auth,
                        user=user,
                        media_url_builder=media_builder,
                        rel_repr=deck._rel_repr,
                        rel_url_builder=rel_url_builder,
                    ),
                }
            )
        relations_display = []
        for rel in view.meta.relationships:
            if rel.name in hidden:
                continue
            val = getattr(obj, rel.name, None)
            rel_items = (
                list(val)
                if (rel.uselist and val is not None)
                else ([val] if val is not None else [])
            )
            relations_display.append(
                {
                    "name": rel.name,
                    "label": rel.label,
                    "count": len(rel_items),
                    "records": [
                        {
                            "label": deck._rel_repr(rel.target_model, it),
                            "href": rel_url_builder(rel.target_model, it),
                        }
                        for it in rel_items[:20]
                    ],
                }
            )
        history: list[AuditEntry] = []
        if deck.audit_store is not None and deck.auth.has_permission(user, "audit:view"):
            raw_hist, _ = deck.audit_store.list_entries(
                model_slug=slug, record_pk=pk_str, limit=10
            )
            history = [deck._sanitize_audit_entry(e, user) for e in raw_hist]
        can_edit = (
            view.can_edit
            and not is_soft_deleted
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
        )
        can_create = (
            view.can_create
            and not is_soft_deleted
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:create", model_slug=slug)
        )
        can_revert = (
            deck.config.enable_audit_revert
            and not deck.config.read_only
            and deck.auth.has_permission(user, "audit:revert")
        )
        active_tz = str(getattr(g, "_flask_deck_tz", deck.config.default_timezone))
        record_notes = (
            deck.note_store.list_notes(slug, pk_str) if deck.note_store is not None else []
        )
        can_write_notes = bool(
            deck.note_store is not None
            and not deck.config.read_only
            and (
                deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
                or deck.auth.has_permission(user, "notes:write", model_slug=slug, obj=obj)
            )
        )
        return render_template(
            "flask_deck/partials/drawer_detail.html",
            view=view,
            bp_name=bp_name,
            pk_str=pk_str,
            record_repr=view.format_record_repr(obj, auth=deck.auth, user=user),
            fields_display=fields_display,
            relations_display=relations_display,
            history=history,
            record_notes=record_notes,
            render_note_md=render_safe_markdown,
            can_write_notes=can_write_notes,
            current_user_id=user.id if user else "",
            is_superuser=bool(user and user.is_superuser),
            can_edit=can_edit,
            can_create=can_create,
            can_revert=can_revert,
            csrf_field=CSRF_FORM_FIELD,
            csrf_token=get_csrf_token(),
            config=deck.config,
            deck_icon=render_icon,
            _=deck.translator.translate,
            format_dt=lambda dt, fmt="%Y-%m-%d %H:%M": (
                to_user_timezone(dt, active_tz).strftime(fmt)
                if isinstance(dt, datetime)
                else str(dt)
            ),
        )

    @bp.route("/_api/<slug>/<raw_pk>/quick-edit", methods=["PATCH"])
    def api_quick_edit(slug: str, raw_pk: str) -> tuple[Response, int]:
        view = deck.get_view(slug)
        if not view.can_edit:
            return jsonify({"error": "Editing is disabled for this model."}), 403
        deck._require_perm(f"{slug}:edit", model_slug=slug)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:edit", model_slug=slug, obj=obj)
        if deck._is_soft_deleted(view, obj):
            return jsonify({"error": "Restore record from Trash before editing."}), 409

        payload = request.get_json(silent=True)
        if not isinstance(payload, Mapping):
            return jsonify({"error": "Expected JSON object payload."}), 400

        field_name = str(payload.get("field", "")).strip()
        user = deck._current_user()
        if deck.approval_store is not None and view.requires_approval(
            user, "edit", obj=obj, payload={field_name: payload.get("value")}
        ):
            return (
                jsonify(
                    {
                        "error": "Edits to this model require four-eyes approval. Use the full edit form."
                    }
                ),
                403,
            )
        writable = set(view.allowed_form_fields(deck.auth, user, mode="edit")) - deck.auth.masked_fields_for(
            user, slug
        )
        quick_allowed = set(view.resolved_inline_editable)
        if view.kanban_column:
            quick_allowed.add(view.kanban_column)
        if field_name not in quick_allowed or field_name not in writable:
            return jsonify({"error": f"Field '{field_name}' is not inline-editable."}), 403

        fmeta = view.meta.fields_by_name[field_name]
        before_snap = view.extract_snapshot(obj)
        try:
            coerced = coerce_form_value(
                payload.get("value"), fmeta, max_json_depth=deck.config.max_json_depth
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 422

        custom_errs = view.validate({field_name: coerced}, obj=obj)
        if custom_errs:
            return jsonify({"error": "; ".join(custom_errs.get(field_name, ["Invalid value"]))}), 422
        val_fn = view.get_form_validator()
        if val_fn is not None:
            ext_errs = val_fn({**before_snap, field_name: coerced}, obj, False)
            if ext_errs:
                first_msgs = next(iter(ext_errs.values()), ["Validation failed."])
                return jsonify({"error": "; ".join(first_msgs)}), 422

        sess = deck.get_session(view.bind_key)
        try:
            setattr(obj, field_name, coerced)
            if view.version_column:
                vf = view.meta.fields_by_name.get(view.version_column)
                if vf is not None and vf.field_type == "integer":
                    setattr(
                        obj,
                        view.version_column,
                        int(before_snap.get(view.version_column) or 0) + 1,
                    )
            view.on_model_change(obj, is_created=False, user=user)
            sess.commit()
        except ValidationError as exc:
            sess.rollback()
            first_msgs = next(iter(exc.errors.values()), ["Validation failed."])
            return jsonify({"error": "; ".join(first_msgs)}), 422
        except SQLAlchemyError as exc:
            sess.rollback()
            return jsonify({"error": f"Database error: {exc.__class__.__name__}"}), 400

        pk_str = encode_pk(pk_vals)
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        after_snap = view.extract_snapshot(obj)
        diff = compute_diff(
            before_snap,
            after_snap,
            sensitive_fields=view.meta.sensitive_fields,
            extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
        )
        if diff:
            deck._record_audit(
                action_name="inline_edit",
                view=view,
                record_pk=pk_str,
                record_repr=safe_repr,
                changes=diff,
            )
            deck._emit_event(
                "record.updated",
                model_slug=slug,
                record_pk=pk_str,
                payload={"fields": sorted(diff.keys()), "inline": True},
            )
        rendered = view.format_cell(
            field_name,
            obj,
            auth=deck.auth,
            user=user,
            rel_repr=deck._rel_repr,
            rel_url_builder=deck._rel_url_builder(user),
        )
        json_val: Any = coerced
        if hasattr(coerced, "value"):
            json_val = coerced.value
        elif hasattr(coerced, "isoformat"):
            json_val = coerced.isoformat()
        elif isinstance(coerced, Decimal):
            json_val = str(coerced)
        return (
            jsonify(
                {
                    "ok": True,
                    "field": field_name,
                    "value": json_val,
                    "display": str(Markup.escape(rendered)),
                }
            ),
            200,
        )

    @bp.route("/_api/notifications")
    def api_notifications() -> Response:
        user = deck._current_user()
        active_tz = str(getattr(g, "_flask_deck_tz", deck.config.default_timezone))
        items: list[dict[str, str]] = []
        if deck.audit_store is not None and deck.auth.has_permission(user, "audit:view"):
            excluded = deck._excluded_audit_models(user)
            entries, _ = deck.audit_store.list_entries(limit=12, excluded_models=excluded)
            for e in entries:
                safe_e = deck._sanitize_audit_entry(e, user)
                items.append(
                    {
                        "action": safe_e.action,
                        "title": f"{safe_e.model_label} · {safe_e.record_repr}",
                        "actor": safe_e.actor_name,
                        "time": to_user_timezone(safe_e.timestamp, active_tz).strftime("%m-%d %H:%M"),
                        "url": url_for(f"{bp_name}.audit_list"),
                    }
                )
                if len(items) >= 8:
                    break
        return jsonify({"items": items})

    def _wants_json() -> bool:
        return bool(
            request.is_json or "application/json" in (request.headers.get("Accept") or "")
        )

    def _clean_saved_qs(raw: str) -> str:
        qs = raw.strip().lstrip("?")
        if any(ord(c) < 32 for c in qs):
            raise ValueError("Invalid control character in query string.")
        low = qs.lower()
        if low.startswith(("http://", "https://", "javascript:", "data:", "//")):
            raise ValueError("Query string must not contain URL schemes.")
        return qs[:1000]

    @bp.route("/_api/<slug>/saved-views", methods=["GET", "POST"])
    def api_saved_views(slug: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        if deck.saved_view_store is None:
            abort(404)
        user = deck._current_user()

        if request.method == "GET":
            items = deck.saved_view_store.list_for_model(
                slug,
                user_id=user.id if user else "",
                roles=user.roles if user else (),
            )
            return jsonify(
                {
                    "items": [
                        {
                            "id": r.id,
                            "name": r.name,
                            "scope": r.scope,
                            "query_string": r.query_string,
                            "owner_id": r.owner_id,
                            "owner_name": r.owner_name,
                            "default_for_role": r.default_for_role,
                        }
                        for r in items
                    ]
                }
            )

        data: Mapping[str, Any]
        if request.is_json:
            parsed = request.get_json(silent=True)
            if not isinstance(parsed, Mapping):
                return jsonify({"error": "Expected JSON payload."}), 400
            data = parsed
        else:
            data = request.form

        name = str(data.get("name", "")).strip()[:120]
        if not name:
            if _wants_json():
                return jsonify({"error": "Saved view name is required."}), 422
            flash("Saved view name is required.", "danger")
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        raw_scope = str(data.get("scope", "personal")).strip().lower()
        if raw_scope not in {"personal", "team", "role"}:
            if _wants_json():
                return jsonify({"error": "Invalid scope. Use personal, team, or role."}), 422
            flash("Invalid saved view scope.", "danger")
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))
        scope = cast(SavedViewScope, raw_scope)

        if scope in {"team", "role"}:
            can_manage = user is not None and (
                user.is_superuser or deck.auth.has_permission(user, "saved_views:manage")
            )
            if not can_manage:
                if _wants_json():
                    return (
                        jsonify({"error": "Missing permission: saved_views:manage"}),
                        403,
                    )
                raise PermissionDeniedError("Missing permission: saved_views:manage")

        default_role: str | None = None
        if scope == "role":
            default_role = str(data.get("default_for_role", "")).strip()[:64] or None
            if not default_role:
                if _wants_json():
                    return jsonify({"error": "default_for_role is required for role views."}), 422
                flash("Target role is required for role-default saved views.", "danger")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        try:
            clean_qs = _clean_saved_qs(str(data.get("query_string", "")))
        except ValueError as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 422
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        rec = SavedViewRecord(
            id="",
            model_slug=slug,
            name=name,
            query_string=clean_qs,
            scope=scope,
            owner_id=user.id if user else "",
            owner_name=user.label if user else "",
            default_for_role=default_role,
        )
        saved = deck.saved_view_store.create(rec)
        if _wants_json():
            return (
                jsonify(
                    {
                        "ok": True,
                        "saved_view": {
                            "id": saved.id,
                            "name": saved.name,
                            "scope": saved.scope,
                            "query_string": saved.query_string,
                            "default_for_role": saved.default_for_role,
                        },
                    }
                ),
                201,
            )
        flash(f"Saved {saved.scope} view '{saved.name}'.", "ok")
        base_url = url_for(f"{bp_name}.model_list", slug=slug)
        return redirect(f"{base_url}?{saved.query_string}" if saved.query_string else base_url)

    @bp.route("/_api/<slug>/saved-views/<view_id>/delete", methods=["POST"])
    def api_saved_view_delete(slug: str, view_id: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        if deck.saved_view_store is None:
            abort(404)
        user = deck._current_user()
        rec = deck.saved_view_store.get(view_id)
        if rec is None or rec.model_slug != slug:
            if _wants_json():
                return jsonify({"error": "Saved view not found."}), 404
            abort(404)
        if user is None or (not user.is_superuser and rec.owner_id != user.id):
            if _wants_json():
                return jsonify({"error": "Only the owner or superuser may delete this view."}), 403
            raise PermissionDeniedError("Only the owner or superuser may delete this view.")
        deck.saved_view_store.delete(
            view_id, actor_id=user.id, is_superuser=user.is_superuser
        )
        if _wants_json():
            return jsonify({"ok": True})
        flash(f"Deleted saved view '{rec.name}'.", "ok")
        return redirect(url_for(f"{bp_name}.model_list", slug=slug))

    def _can_write_notes_for(user: Any, slug: str, obj: Any) -> bool:
        return bool(
            user is not None
            and (
                deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
                or deck.auth.has_permission(user, "notes:write", model_slug=slug, obj=obj)
            )
        )

    @bp.route("/_api/<slug>/<raw_pk>/notes", methods=["GET", "POST"])
    def api_record_notes(slug: str, raw_pk: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        if deck.note_store is None:
            abort(404)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()

        if request.method == "GET":
            notes = deck.note_store.list_notes(slug, pk_str)
            return jsonify(
                {
                    "items": [
                        {
                            "id": n.id,
                            "author_id": n.author_id,
                            "author_name": n.author_name,
                            "body": n.body,
                            "rendered_html": str(render_safe_markdown(n.body)),
                            "pinned": n.pinned,
                            "created_at": n.created_at.isoformat(),
                        }
                        for n in notes
                    ]
                }
            )

        if not _can_write_notes_for(user, slug, obj):
            if _wants_json():
                return jsonify({"error": "Missing permission to add record notes."}), 403
            raise PermissionDeniedError("Missing permission to add record notes.")

        data: Mapping[str, Any]
        if request.is_json:
            parsed = request.get_json(silent=True)
            if not isinstance(parsed, Mapping):
                return jsonify({"error": "Expected JSON payload."}), 400
            data = parsed
        else:
            data = request.form

        body_text = str(data.get("body", "")).strip()[:4000]
        if not body_text:
            if _wants_json():
                return jsonify({"error": "Note text cannot be empty."}), 422
            flash("Note text cannot be empty.", "danger")
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))

        pinned = str(data.get("pinned", "")).strip().lower() in {"1", "true", "yes", "on"}
        saved = deck.note_store.add(
            RecordNote(
                id="",
                model_slug=slug,
                record_pk=pk_str,
                author_id=user.id if user else "system",
                author_name=user.label if user else "System",
                body=body_text,
                pinned=pinned,
            )
        )
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        deck._record_audit(
            action_name="note_added",
            view=view,
            record_pk=pk_str,
            record_repr=safe_repr,
            changes={"note": {"old": None, "new": body_text[:120]}},
            metadata={"note_id": saved.id, "pinned": saved.pinned},
        )
        deck._emit_event(
            "note.added",
            model_slug=slug,
            record_pk=pk_str,
            payload={"note_id": saved.id, "pinned": saved.pinned},
        )
        if _wants_json():
            return (
                jsonify(
                    {
                        "ok": True,
                        "note": {
                            "id": saved.id,
                            "author_id": saved.author_id,
                            "author_name": saved.author_name,
                            "body": saved.body,
                            "rendered_html": str(render_safe_markdown(saved.body)),
                            "pinned": saved.pinned,
                            "created_at": saved.created_at.isoformat(),
                        },
                    }
                ),
                201,
            )
        flash("Added record note.", "ok")
        return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))

    @bp.route("/_api/<slug>/<raw_pk>/notes/<note_id>/pin", methods=["POST"])
    def api_record_note_pin(slug: str, raw_pk: str, note_id: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        if deck.note_store is None:
            abort(404)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()
        if not _can_write_notes_for(user, slug, obj):
            if _wants_json():
                return jsonify({"error": "Missing permission to pin notes."}), 403
            raise PermissionDeniedError("Missing permission to pin notes.")
        updated = deck.note_store.toggle_pin(note_id, model_slug=slug, record_pk=pk_str)
        if updated is None:
            if _wants_json():
                return jsonify({"error": "Note not found."}), 404
            abort(404)
        if _wants_json():
            return jsonify({"ok": True, "id": updated.id, "pinned": updated.pinned})
        flash("Updated note pin.", "ok")
        return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))

    @bp.route("/_api/<slug>/<raw_pk>/notes/<note_id>/delete", methods=["POST"])
    def api_record_note_delete(slug: str, raw_pk: str, note_id: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        if deck.note_store is None:
            abort(404)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()
        if not _can_write_notes_for(user, slug, obj):
            if _wants_json():
                return jsonify({"error": "Missing permission to delete notes."}), 403
            raise PermissionDeniedError("Missing permission to delete notes.")
        note = deck.note_store.get(note_id)
        if note is None or note.model_slug != slug or note.record_pk != pk_str:
            if _wants_json():
                return jsonify({"error": "Note not found."}), 404
            abort(404)
        if user is None or (not user.is_superuser and note.author_id != user.id):
            if _wants_json():
                return jsonify({"error": "Only the author or superuser can delete this note."}), 403
            raise PermissionDeniedError("Only the author or superuser can delete this note.")
        deck.note_store.delete(note_id, actor_id=user.id, is_superuser=user.is_superuser)
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        deck._record_audit(
            action_name="note_deleted",
            view=view,
            record_pk=pk_str,
            record_repr=safe_repr,
            changes={"note": {"old": note.body[:120], "new": None}},
            metadata={"note_id": note.id},
        )
        if _wants_json():
            return jsonify({"ok": True})
        flash("Deleted record note.", "ok")
        return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
