from __future__ import annotations

import enum
import json
from collections.abc import Mapping
from datetime import date, datetime, time
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

import sqlalchemy as sa
from flask import Blueprint, Response, g, jsonify, request, url_for
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk, extract_pk
from flask_deck.approvals import make_approval_request
from flask_deck.audit import compute_diff
from flask_deck.auth import DeckUser
from flask_deck.exceptions import PermissionDeniedError, ValidationError
from flask_deck.introspection import introspect_model
from flask_deck.model_view import ModelView
from flask_deck.query import execute_list_query, soft_delete_predicate

if TYPE_CHECKING:
    from flask_deck.api_keys import APIKeyRecord
    from flask_deck.deck import Deck


def json_safe_value(value: Any) -> Any:
    """Convert a SQLAlchemy / Python field value to JSON-serializable primitive."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (Decimal, UUID)):
        return str(value)
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, Mapping):
        return {str(k): json_safe_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe_value(v) for v in value]
    return str(value)


def serialize_record_for_api(
    deck: Deck,
    view: ModelView,
    obj: Any,
    user: DeckUser | None,
    *,
    include_version: bool = True,
) -> dict[str, Any]:
    """Serialize one ORM instance obeying hidden, sensitive, and masked RBAC rules."""
    slug = view.meta.slug
    hidden = deck.auth.hidden_fields_for(user, slug)
    masked = deck.auth.masked_fields_for(user, slug)
    pk_vals = extract_pk(obj, view.meta)
    pk_str = encode_pk(pk_vals)
    data: dict[str, Any] = {
        "_pk": pk_str,
        "_repr": view.format_record_repr(obj, auth=deck.auth, user=user),
    }
    if include_version:
        data["_version"] = view.compute_version_token(obj, auth=deck.auth, user=user)

    for f in view.meta.fields:
        if f.name in hidden or f.is_sensitive:
            continue
        raw_v = getattr(obj, f.name, None)
        if f.name in masked:
            data[f.name] = deck.auth.mask_field_value(user, slug, f.name, raw_v)
        else:
            data[f.name] = json_safe_value(raw_v)
    return data


def _value_to_form_strings(value: Any) -> list[str]:
    if value is None:
        return [""]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, (list, tuple)):
        return ["true" if v is True else ("false" if v is False else str(v)) for v in value]
    if isinstance(value, dict):
        return [json.dumps(value)]
    return [str(value)]


def _current_obj_to_form_strings(obj: Any, col: str, view: ModelView) -> list[str]:
    fmeta = view.meta.fields_by_name.get(col)
    if fmeta is not None:
        val = getattr(obj, col, None)
        if val is None:
            return [""]
        if isinstance(val, bool):
            return ["true" if val else "false"]
        if isinstance(val, enum.Enum):
            return [str(val.value)]
        if isinstance(val, (dict, list)):
            return [json.dumps(val)]
        return [str(val)]
    rel = view.meta.relationships_by_name.get(col)
    if rel is not None and rel.direction == "MANYTOMANY":
        items = list(getattr(obj, col, None) or [])
        t_meta = introspect_model(rel.target_model)
        return [encode_pk(extract_pk(item, t_meta)) for item in items]
    return []


def build_multidict_from_json(
    deck: Deck,
    view: ModelView,
    data: Mapping[str, Any],
    *,
    user: DeckUser | None,
    mode: str,
    obj: Any | None = None,
) -> MultiDict[str, str]:
    """Validate incoming JSON field keys against RBAC write rules and return form MultiDict."""
    slug = view.meta.slug
    masked = deck.auth.masked_fields_for(user, slug)
    target_obj_ctx = obj if mode == "edit" else None
    writable = set(view.allowed_form_fields(deck.auth, user, mode=mode, obj=target_obj_ctx))
    if mode == "edit":
        writable -= masked
    rejected: dict[str, list[str]] = {}
    for k in data:
        if str(k).startswith("_"):
            continue
        if str(k) not in writable:
            rejected[str(k)] = ["Field is unknown, read-only, or forbidden for this role."]
    if rejected:
        raise ValidationError(rejected)

    md: MultiDict[str, str] = MultiDict()
    for col, raw_v in data.items():
        key = str(col)
        if key not in writable:
            continue
        for s_val in _value_to_form_strings(raw_v):
            md.add(key, s_val)
    return md


def apply_json_mutation(
    deck: Deck,
    sess: Session,
    view: ModelView,
    obj: Any,
    form_md: MultiDict[str, str],
    *,
    user: DeckUser | None,
    mode: str,
    run_hooks: bool = True,
) -> None:
    """Apply validated MultiDict mutation to ORM object cleanly."""

    def _scope_m2m(target_cls: type[Any], s: sa.Select[Any]) -> sa.Select[Any]:
        tv = deck._views_by_model.get(target_cls)
        return tv.scope_query(s, user) if tv is not None else s

    vdata = view.apply_form_data(
        sess,
        obj,
        form_md,
        auth=deck.auth,
        user=user,
        mode=mode,
        max_json_depth=deck.config.max_json_depth,
        m2m_getter=form_md.getlist,
        m2m_scope=_scope_m2m,
        partial=(mode == "edit"),
        utc_passthrough=True,
    )
    if run_hooks:
        view.invoke_on_model_change(obj, is_created=(mode == "create"), user=user, virtual_data=vdata)


def build_openapi_spec(deck: Deck, user: DeckUser | None) -> dict[str, Any]:
    """Generate an OpenAPI 3.1.0 specification covering accessible REST v1 endpoints."""
    prefix = deck.config.url_prefix.rstrip("/")
    paths: dict[str, Any] = {
        f"{prefix}/_api/v1/models": {
            "get": {
                "summary": "List accessible models",
                "security": [{"BearerAuth": []}],
                "responses": {"200": {"description": "Accessible model schemas"}},
            }
        },
        f"{prefix}/_api/v1/approvals": {
            "get": {
                "summary": "List four-eyes approval requests",
                "security": [{"BearerAuth": []}],
                "responses": {"200": {"description": "Approval requests"}},
            }
        },
    }
    schemas: dict[str, Any] = {}
    hidden_cache: dict[str, frozenset[str]] = {}

    for slug, view in deck.views.items():
        if not view.can_view or not deck._has_perm(user, f"{slug}:view", model_slug=slug):
            continue
        hidden = deck.auth.hidden_fields_for(user, slug)
        hidden_cache[slug] = hidden
        props: dict[str, Any] = {}
        for f in view.meta.fields:
            if f.name in hidden or f.is_sensitive:
                continue
            js_type = "string"
            if f.field_type == "integer":
                js_type = "integer"
            elif f.field_type in {"float", "decimal"}:
                js_type = "number"
            elif f.field_type == "boolean":
                js_type = "boolean"
            elif f.field_type == "array":
                js_type = "array"
            elif f.field_type == "json":
                js_type = "object"
            props[f.name] = {"type": js_type}
        schema_name = view.meta.name if view.meta.name not in schemas else f"{view.meta.name}_{slug}"
        schemas[schema_name] = {"type": "object", "properties": props}

        collection_item: dict[str, Any] = {
            "get": {
                "summary": f"List {view.plural_label}",
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "page", "in": "query", "schema": {"type": "integer"}},
                    {"name": "page_size", "in": "query", "schema": {"type": "integer"}},
                    {"name": "sort", "in": "query", "schema": {"type": "string"}},
                    {"name": "dir", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": f"Paginated {view.plural_label}"}},
            }
        }
        if view.can_create and deck._has_perm(user, f"{slug}:create", model_slug=slug):
            collection_item["post"] = {
                "summary": f"Create {view.label}",
                "security": [{"BearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema_name}"}}},
                },
                "responses": {
                    "201": {"description": "Created"},
                    "202": {"description": "Queued for four-eyes approval"},
                },
            }
        paths[f"{prefix}/_api/v1/{slug}"] = collection_item

        item_ops: dict[str, Any] = {
            "get": {
                "summary": f"Get {view.label}",
                "security": [{"BearerAuth": []}],
                "parameters": [{"name": "raw_pk", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": view.label}},
            }
        }
        if view.can_edit and deck._has_perm(user, f"{slug}:edit", model_slug=slug):
            item_ops["patch"] = {
                "summary": f"Update {view.label}",
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {"name": "raw_pk", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "If-Match", "in": "header", "required": False, "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"description": "Updated"},
                    "202": {"description": "Queued for approval"},
                    "409": {"description": "Optimistic concurrency conflict"},
                },
            }
        if view.can_delete and deck._has_perm(user, f"{slug}:delete", model_slug=slug):
            item_ops["delete"] = {
                "summary": f"Delete {view.label}",
                "security": [{"BearerAuth": []}],
                "parameters": [{"name": "raw_pk", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Deleted"},
                    "202": {"description": "Queued for approval"},
                },
            }
        paths[f"{prefix}/_api/v1/{slug}/{{raw_pk}}"] = item_ops

    return {
        "openapi": "3.1.0",
        "info": {
            "title": f"{deck.config.title} API",
            "version": "1.0.0",
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API Key (dk_live_...)",
                }
            },
            "schemas": schemas,
        },
        "security": [{"BearerAuth": []}],
        "paths": paths,
    }


def _actor_meta(deck: Deck, source: str) -> dict[str, Any]:
    key_rec: APIKeyRecord | None = getattr(g, "_deck_api_key", None)
    meta: dict[str, Any] = {"source": source}
    if key_rec is not None:
        meta["api_key_id"] = key_rec.id
        meta["api_key_prefix"] = key_rec.prefix
    return meta


def register_rest_api_routes(bp: Blueprint, deck: Deck) -> None:
    """Register headless versioned JSON REST API routes (``/_api/v1/...``)."""
    bp_name = deck.config.name

    @bp.route("/_api/v1/openapi.json")
    def rest_v1_openapi() -> Response:
        user = deck._current_user()
        return jsonify(build_openapi_spec(deck, user))

    @bp.route("/_api/v1/models")
    def rest_v1_models() -> Response:
        user = deck._current_user()
        items: list[dict[str, Any]] = []
        for slug, view in deck.views.items():
            if not view.can_view or not deck._has_perm(user, f"{slug}:view", model_slug=slug):
                continue
            hidden = deck.auth.hidden_fields_for(user, slug)
            items.append(
                {
                    "slug": slug,
                    "name": view.meta.name,
                    "label": view.label,
                    "plural_label": view.plural_label,
                    "can_create": view.can_create and deck._has_perm(user, f"{slug}:create", model_slug=slug),
                    "can_edit": view.can_edit and deck._has_perm(user, f"{slug}:edit", model_slug=slug),
                    "can_delete": view.can_delete and deck._has_perm(user, f"{slug}:delete", model_slug=slug),
                    "approval_required": (
                        view.requires_approval(user, "create")
                        or view.requires_approval(user, "edit")
                        or view.requires_approval(user, "delete")
                    ),
                    "fields": [
                        {
                            "name": f.name,
                            "type": f.field_type,
                            "nullable": f.nullable,
                            "primary_key": f.primary_key,
                            "choices": [list(c) for c in f.choices],
                        }
                        for f in view.meta.fields
                        if f.name not in hidden and not f.is_sensitive
                    ],
                    "actions": [
                        {"name": spec.name, "label": spec.label, "require_approval": spec.require_approval}
                        for spec in view.get_actions(user).values()
                    ],
                }
            )
        return jsonify({"models": items})

    @bp.route("/_api/v1/<slug>", methods=["GET", "POST"])
    def rest_v1_collection(slug: str) -> tuple[Response, int] | Response:
        view = deck.get_view(slug)
        if not view.can_view:
            return jsonify({"error": "Model is disabled."}), 404
        user = deck._current_user()

        if request.method == "GET":
            deck._require_perm(f"{slug}:view", model_slug=slug)
            visible_cols = view.visible_list_columns(deck.auth, user)
            allowed_searchable, allowed_filterable, allowed_sortable = deck._allowed_query_fields(
                view, user
            )
            filter_pairs = [
                (k[2:], v.strip())
                for k, v in request.args.items(multi=True)
                if k.startswith("f_") and v.strip()
            ]
            try:
                page = max(1, int(request.args.get("page", "1")))
            except ValueError:
                page = 1
            default_ps = view.page_size or deck.config.page_size
            try:
                page_size = int(request.args.get("page_size", str(default_ps)))
            except ValueError:
                page_size = default_ps
            trashed = bool(view.soft_delete_column and request.args.get("trashed") == "1")
            result = execute_list_query(
                deck.get_session(view.bind_key),
                view.meta,
                base_stmt=view.scope_query(sa.select(view.model), user),
                displayed_columns=visible_cols,
                searchable_columns=allowed_searchable,
                filterable_columns=allowed_filterable,
                sortable_columns=allowed_sortable,
                quick_tabs=view.quick_tabs,
                active_tab_key=None,
                search_term=request.args.get("q", "").strip(),
                filter_params=filter_pairs,
                sort_by=request.args.get("sort", "").strip() or None,
                sort_dir=request.args.get("dir", "desc").strip(),
                default_sort=view.default_sort,
                page=page,
                page_size=page_size,
                max_page_size=deck.config.max_page_size,
                pagination_mode=view.pagination_mode or deck.config.default_pagination_mode,
                count_mode=view.count_mode,
                after_cursor=request.args.get("after", "").strip() or None,
                before_cursor=request.args.get("before", "").strip() or None,
                cursor_secret=deck._cursor_secret(),
                soft_delete_column=view.soft_delete_column,
                trashed=trashed,
                show_full_result_count=False,
            )
            return jsonify(
                {
                    "items": [serialize_record_for_api(deck, view, it, user) for it in result.items],
                    "total": result.total,
                    "page": result.page,
                    "page_size": result.page_size,
                    "pages": result.pages,
                    "next_cursor": result.next_cursor,
                    "prev_cursor": result.prev_cursor,
                }
            )

        if not view.can_create:
            return jsonify({"error": "Creation is disabled for this model."}), 403
        deck._require_perm(f"{slug}:create", model_slug=slug)
        payload = request.get_json(silent=True)
        if not isinstance(payload, Mapping):
            return jsonify({"error": "Expected JSON object body."}), 400

        reason = str(payload.get("_reason", "")).strip()[:500]
        sess = deck.get_session(view.bind_key)
        obj = view.model()
        try:
            form_md = build_multidict_from_json(deck, view, payload, user=user, mode="create")
            apply_json_mutation(deck, sess, view, obj, form_md, user=user, mode="create")
            sess.add(obj)
            sess.flush()
            needs_approval = deck.approval_store is not None and view.requires_approval(
                user, "create", payload=dict(payload)
            )
            if needs_approval and deck.approval_store is not None:
                safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
                diff = compute_diff(
                    {},
                    view.extract_snapshot(obj),
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                sess.rollback()
                req = make_approval_request(
                    model_slug=slug,
                    model_label=view.label,
                    operation="create",
                    record_pk="pending",
                    record_repr=safe_repr,
                    payload={
                        "form_items": [[k, v] for k, v in form_md.items(multi=True)],
                        "_actor_roles": list(user.roles) if user else [],
                        "_actor_superuser": bool(user.is_superuser) if user else False,
                    },
                    diff=diff,
                    reason=reason,
                    requester_id=user.id if user else "system",
                    requester_name=user.label if user else "System",
                    actor_type="api_key",
                )
                saved = deck.approval_store.create(req)
                deck._emit_event(
                    "approval.requested",
                    model_slug=slug,
                    record_pk=saved.id,
                    payload={"approval_id": saved.id, "operation": "create", "source": "rest_api"},
                )
                return (
                    jsonify(
                        {
                            "status": "pending_approval",
                            "approval_id": saved.id,
                            "diff": saved.diff,
                            "review_url": url_for(f"{bp_name}.approvals_list"),
                        }
                    ),
                    202,
                )
            sess.commit()
        except ValidationError as exc:
            sess.rollback()
            return jsonify({"error": "Validation failed", "details": exc.errors}), 422
        except IntegrityError as exc:
            sess.rollback()
            return jsonify({"error": f"Integrity error: {exc.orig}"}), 409
        except SQLAlchemyError as exc:
            sess.rollback()
            return jsonify({"error": f"Database error: {exc.__class__.__name__}"}), 400

        pk_str = encode_pk(extract_pk(obj, view.meta))
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        diff = compute_diff(
            {},
            view.extract_snapshot(obj),
            sensitive_fields=view.meta.sensitive_fields,
            extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
        )
        deck._record_audit(
            action_name="create",
            view=view,
            record_pk=pk_str,
            record_repr=safe_repr,
            changes=diff,
            metadata=_actor_meta(deck, "rest_api"),
        )
        deck._emit_event(
            "record.created",
            model_slug=slug,
            record_pk=pk_str,
            payload={"repr": safe_repr, "source": "rest_api"},
        )
        rec_json = serialize_record_for_api(deck, view, obj, user)
        resp = jsonify(rec_json)
        resp.headers["ETag"] = f'"{rec_json["_version"]}"'
        return resp, 201

    @bp.route("/_api/v1/<slug>/<raw_pk>", methods=["GET", "PATCH", "DELETE"])
    def rest_v1_item(slug: str, raw_pk: str) -> tuple[Response, int] | Response:
        view = deck.get_view(slug)
        if not view.can_view:
            return jsonify({"error": "Model is disabled."}), 404
        user = deck._current_user()
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        pk_str = encode_pk(pk_vals)

        if request.method == "GET":
            deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
            if not view.can_view_record(obj, user):
                return jsonify({"error": f"Not authorized to view this {view.label}."}), 403
            rec_json = serialize_record_for_api(deck, view, obj, user)
            resp = jsonify(rec_json)
            resp.headers["ETag"] = f'"{rec_json["_version"]}"'
            return resp, 200

        if request.method == "PATCH":
            if not view.can_edit:
                return jsonify({"error": "Editing is disabled for this model."}), 403
            deck._require_perm(f"{slug}:edit", model_slug=slug, obj=obj)
            if not view.can_edit_record(obj, user):
                return jsonify({"error": f"Not authorized to edit this {view.label}."}), 403
            if deck._is_soft_deleted(view, obj):
                return jsonify({"error": "Record is soft-deleted."}), 409
            payload = request.get_json(silent=True)
            if not isinstance(payload, Mapping):
                return jsonify({"error": "Expected JSON object body."}), 400

            current_ver = view.compute_version_token(obj, auth=deck.auth, user=user)
            if_match = (request.headers.get("If-Match") or "").strip().strip('"')
            body_ver = str(payload.get("_version", "")).strip()
            expected_ver = if_match or body_ver
            if expected_ver and expected_ver != current_ver:
                return (
                    jsonify(
                        {
                            "error": "Concurrent modification detected (version mismatch).",
                            "current_version": current_ver,
                        }
                    ),
                    409,
                )

            reason = str(payload.get("_reason", "")).strip()[:500]
            sess = deck.get_session(view.bind_key)
            before_snap = view.extract_snapshot(obj)
            try:
                form_md = build_multidict_from_json(
                    deck, view, payload, user=user, mode="edit", obj=obj
                )
                needs_approval = deck.approval_store is not None and view.requires_approval(
                    user, "edit", obj=obj, payload=dict(payload)
                )
                apply_json_mutation(
                    deck,
                    sess,
                    view,
                    obj,
                    form_md,
                    user=user,
                    mode="edit",
                    run_hooks=not needs_approval,
                )
                if not needs_approval and view.version_column:
                    vf = view.meta.fields_by_name.get(view.version_column)
                    if vf is not None and vf.field_type == "integer":
                        setattr(
                            obj,
                            view.version_column,
                            int(before_snap.get(view.version_column) or 0) + 1,
                        )
                sess.flush()
                diff = compute_diff(
                    before_snap,
                    view.extract_snapshot(obj),
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                if needs_approval and deck.approval_store is not None:
                    safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
                    sess.rollback()
                    req = make_approval_request(
                        model_slug=slug,
                        model_label=view.label,
                        operation="edit",
                        record_pk=pk_str,
                        record_repr=safe_repr,
                        payload={
                            "form_items": [[k, v] for k, v in form_md.items(multi=True)],
                            "partial": True,
                            "utc_passthrough": True,
                            "expected_version": current_ver,
                            "_actor_roles": list(user.roles) if user else [],
                            "_actor_superuser": bool(user.is_superuser) if user else False,
                        },
                        diff=diff,
                        reason=reason,
                        requester_id=user.id if user else "system",
                        requester_name=user.label if user else "System",
                        actor_type="api_key",
                    )
                    saved = deck.approval_store.create(req)
                    deck._emit_event(
                        "approval.requested",
                        model_slug=slug,
                        record_pk=pk_str,
                        payload={"approval_id": saved.id, "operation": "edit", "source": "rest_api"},
                    )
                    return (
                        jsonify(
                            {
                                "status": "pending_approval",
                                "approval_id": saved.id,
                                "diff": saved.diff,
                            }
                        ),
                        202,
                    )
                sess.commit()
            except ValidationError as exc:
                sess.rollback()
                return jsonify({"error": "Validation failed", "details": exc.errors}), 422
            except IntegrityError as exc:
                sess.rollback()
                return jsonify({"error": f"Integrity error: {exc.orig}"}), 409
            except SQLAlchemyError as exc:
                sess.rollback()
                return jsonify({"error": f"Database error: {exc.__class__.__name__}"}), 400

            safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            if diff:
                deck._record_audit(
                    action_name="update",
                    view=view,
                    record_pk=pk_str,
                    record_repr=safe_repr,
                    changes=diff,
                    metadata=_actor_meta(deck, "rest_api"),
                )
                deck._emit_event(
                    "record.updated",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"fields": sorted(diff.keys()), "source": "rest_api"},
                )
            rec_json = serialize_record_for_api(deck, view, obj, user)
            resp = jsonify(rec_json)
            resp.headers["ETag"] = f'"{rec_json["_version"]}"'
            return resp, 200

        # DELETE
        if not view.can_delete:
            return jsonify({"error": "Deletion is disabled for this model."}), 403
        deck._require_perm(f"{slug}:delete", model_slug=slug, obj=obj)
        if not view.can_delete_record(obj, user):
            return jsonify({"error": f"Not authorized to delete this {view.label}."}), 403
        payload_del = request.get_json(silent=True) or {}
        force = (
            request.args.get("force") == "1"
            or (isinstance(payload_del, Mapping) and bool(payload_del.get("force")))
        )
        if view.soft_delete_column and force:
            deck._require_perm(f"{slug}:force_delete", model_slug=slug, obj=obj)
        before_snap = view.extract_snapshot(obj)
        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
        sess = deck.get_session(view.bind_key)

        if deck.approval_store is not None and view.requires_approval(
            user, "delete", obj=obj, payload={"force": force}
        ):
            del_diff = (
                {
                    view.soft_delete_column: {
                        "old": before_snap.get(view.soft_delete_column),
                        "new": "trashed",
                    }
                }
                if view.soft_delete_column and not force
                else compute_diff(
                    before_snap,
                    {},
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
            )
            sess.rollback()
            req = make_approval_request(
                model_slug=slug,
                model_label=view.label,
                operation="delete",
                record_pk=pk_str,
                record_repr=safe_repr,
                payload={
                    "force": force,
                    "_actor_roles": list(user.roles) if user else [],
                    "_actor_superuser": bool(user.is_superuser) if user else False,
                },
                diff=del_diff,
                reason=str(payload_del.get("_reason", "") if isinstance(payload_del, Mapping) else "").strip(),
                requester_id=user.id if user else "system",
                requester_name=user.label if user else "System",
                actor_type="api_key",
            )
            saved = deck.approval_store.create(req)
            deck._emit_event(
                "approval.requested",
                model_slug=slug,
                record_pk=pk_str,
                payload={"approval_id": saved.id, "operation": "delete", "source": "rest_api"},
            )
            return jsonify({"status": "pending_approval", "approval_id": saved.id}), 202

        if view.soft_delete_column and not force:
            fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
            if fmeta is not None:
                from datetime import timezone as _tz

                view.on_model_delete(obj, user=user)
                setattr(
                    obj,
                    view.soft_delete_column,
                    True if fmeta.field_type == "boolean" else datetime.now(_tz.utc),
                )
                sess.commit()
                deck._record_audit(
                    action_name="soft_delete",
                    view=view,
                    record_pk=pk_str,
                    record_repr=safe_repr,
                    metadata=_actor_meta(deck, "rest_api"),
                )
                deck._emit_event(
                    "record.deleted",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"soft": True, "source": "rest_api"},
                )
                return jsonify({"ok": True, "deleted": pk_str, "soft": True}), 200

        orphans = deck._collect_orphan_files(view, obj)
        try:
            view.on_model_delete(obj, user=user)
            sess.delete(obj)
            sess.commit()
        except IntegrityError as exc:
            sess.rollback()
            return jsonify({"error": f"Cannot delete record: {exc.orig}"}), 409
        deck._delete_orphan_files_best_effort(orphans)
        deck._record_audit(
            action_name="delete",
            view=view,
            record_pk=pk_str,
            record_repr=safe_repr,
            changes=compute_diff(
                before_snap,
                {},
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            ),
            metadata=_actor_meta(deck, "rest_api"),
        )
        deck._emit_event(
            "record.deleted",
            model_slug=slug,
            record_pk=pk_str,
            payload={"soft": False, "source": "rest_api"},
        )
        return jsonify({"ok": True, "deleted": pk_str, "soft": False}), 200

    @bp.route("/_api/v1/<slug>/actions/<action_name>", methods=["POST"])
    def rest_v1_action(slug: str, action_name: str) -> tuple[Response, int]:
        view = deck.get_view(slug)
        user = deck._current_user()
        resolved_act = deck._resolve_action_spec_and_handler(view, action_name, user)
        if resolved_act is None:
            return jsonify({"error": f"Unknown action '{action_name}'."}), 404
        spec, handler = resolved_act
        perm = spec.permission or f"{slug}:action:{action_name}"
        deck._require_perm(perm, model_slug=slug)

        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, Mapping):
            return jsonify({"error": "Expected JSON object body."}), 400
        raw_pks = [str(p) for p in payload.get("pks", [])]
        if not raw_pks:
            return jsonify({"error": "No target 'pks' provided."}), 422
        decoded = [decode_pk(p, view.meta) for p in raw_pks]
        sess = deck.get_session(view.bind_key)
        stmt = view.scope_query(sa.select(view.model), user)
        sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
        if sd_pred is not None:
            stmt = stmt.where(sd_pred)
        if len(view.meta.primary_keys) == 1:
            col = getattr(view.model, view.meta.primary_keys[0].name)
            stmt = stmt.where(col.in_([p[0] for p in decoded]))
        else:
            cols = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
            stmt = stmt.where(sa.tuple_(*cols).in_(decoded))
        records = list(sess.scalars(stmt).all())
        if not records:
            return jsonify({"error": "No matching authorized records found."}), 404
        for rec in records:
            deck._require_perm(perm, model_slug=slug, obj=rec)

        raw_params = payload.get("params") or {}
        if not isinstance(raw_params, Mapping):
            return jsonify({"error": "'params' must be an object."}), 422
        form_md = MultiDict([(str(k), str(v)) for k, v in raw_params.items()])
        for af in spec.fields:
            rv = form_md.get(af.name, "").strip()
            if af.required and not rv:
                return jsonify({"error": f"Action '{spec.label}' requires '{af.display_label}'."}), 422
            if rv and af.choices and rv not in {str(c[0]) for c in af.choices}:
                return jsonify({"error": f"Invalid choice for '{af.display_label}'."}), 422

        if deck.approval_store is not None and (
            spec.require_approval
            or view.requires_approval(user, "action", payload={"action_name": action_name, "pks": raw_pks, **raw_params})
        ):
            sess.rollback()
            req = make_approval_request(
                model_slug=slug,
                model_label=view.label,
                operation="action",
                record_pk=",".join(raw_pks[:10]),
                record_repr=f"{spec.label} ({len(records)} {view.plural_label})",
                payload={
                    "action_name": action_name,
                    "pks": raw_pks,
                    "form_items": [[k, v] for k, v in form_md.items(multi=True)],
                    "_actor_roles": list(user.roles) if user else [],
                    "_actor_superuser": bool(user.is_superuser) if user else False,
                },
                diff={"action": {"old": None, "new": f"{spec.label} ({len(records)} {view.plural_label})"}},
                reason=str(payload.get("_reason", "")).strip(),
                requester_id=user.id if user else "system",
                requester_name=user.label if user else "System",
                actor_type="api_key",
            )
            saved = deck.approval_store.create(req)
            deck._emit_event(
                "approval.requested",
                model_slug=slug,
                record_pk=saved.id,
                payload={"approval_id": saved.id, "operation": "action", "action": action_name, "source": "rest_api"},
            )
            return jsonify({"status": "pending_approval", "approval_id": saved.id}), 202

        try:
            msg = handler(records, form_md, user)
            sess.commit()
        except (ValueError, ValidationError, SQLAlchemyError) as exc:
            sess.rollback()
            return jsonify({"error": str(exc)}), 422
        msg_str = spec.label if isinstance(msg, Response) else str(msg or "Done")
        meta = _actor_meta(deck, "rest_api")
        meta.update({"action": action_name, "count": len(records)})
        deck._record_audit(
            action_name="bulk_action",
            view=view,
            record_pk=",".join(raw_pks[:10]),
            record_repr=msg_str,
            metadata=meta,
        )
        deck._emit_event(
            "action.executed",
            model_slug=slug,
            record_pk=",".join(raw_pks[:10]),
            payload={"action": action_name, "count": len(records), "source": "rest_api"},
        )
        return jsonify({"ok": True, "message": msg_str, "count": len(records)}), 200

    @bp.route("/_api/v1/approvals")
    def rest_v1_approvals() -> tuple[Response, int]:
        if deck.approval_store is None:
            return jsonify({"error": "Approval workflow disabled."}), 404
        user = deck._current_user()
        can_view = user is not None and (
            deck._has_perm(user, "approvals:view") or deck._has_perm(user, "approvals:review")
        )
        if not can_view:
            raise PermissionDeniedError("Missing permission: approvals:view")
        status_f = request.args.get("status", "").strip() or None
        model_f = request.args.get("model", "").strip() or None
        reqs = deck.approval_store.list_requests(status=status_f, model_slug=model_f, limit=100)
        return (
            jsonify(
                {
                    "items": [
                        {
                            "id": r.id,
                            "model_slug": r.model_slug,
                            "operation": r.operation,
                            "record_pk": r.record_pk,
                            "record_repr": r.record_repr,
                            "status": r.status,
                            "actor_type": r.actor_type,
                            "requester_id": r.requester_id,
                            "requester_name": r.requester_name,
                            "reviewer_id": r.reviewer_id,
                            "reviewer_name": r.reviewer_name,
                            "review_note": r.review_note,
                            "diff": r.diff,
                            "created_at": r.created_at.isoformat(),
                            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
                        }
                        for r in reqs
                    ]
                }
            ),
            200,
        )

    @bp.route("/_api/v1/approvals/<approval_id>")
    def rest_v1_approval_detail(approval_id: str) -> tuple[Response, int]:
        if deck.approval_store is None:
            return jsonify({"error": "Approval workflow disabled."}), 404
        req = deck.approval_store.get(approval_id)
        if req is None:
            return jsonify({"error": "Approval request not found."}), 404
        user = deck._current_user()
        allowed = user is not None and (
            deck._has_perm(user, "approvals:view")
            or deck._has_perm(user, "approvals:review")
            or req.requester_id == user.id
        )
        if not allowed:
            raise PermissionDeniedError("Missing permission: approvals:view")
        return (
            jsonify(
                {
                    "id": req.id,
                    "model_slug": req.model_slug,
                    "operation": req.operation,
                    "record_pk": req.record_pk,
                    "record_repr": req.record_repr,
                    "status": req.status,
                    "actor_type": req.actor_type,
                    "requester_id": req.requester_id,
                    "requester_name": req.requester_name,
                    "reviewer_id": req.reviewer_id,
                    "reviewer_name": req.reviewer_name,
                    "review_note": req.review_note,
                    "diff": req.diff,
                    "created_at": req.created_at.isoformat(),
                    "reviewed_at": req.reviewed_at.isoformat() if req.reviewed_at else None,
                }
            ),
            200,
        )
