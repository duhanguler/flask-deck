from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, TextIO
from urllib.parse import urlsplit

import sqlalchemy as sa
from flask import Blueprint, Response, jsonify, request
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.datastructures import MultiDict

from flask_deck._version import __version__
from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk, extract_pk
from flask_deck.approvals import make_approval_request
from flask_deck.audit import compute_diff
from flask_deck.auth import DeckUser
from flask_deck.exceptions import PermissionDeniedError, ValidationError
from flask_deck.query import execute_list_query, soft_delete_predicate
from flask_deck.rest_api import (
    apply_json_mutation,
    build_multidict_from_json,
    serialize_record_for_api,
)
from flask_deck.sql_console import execute_readonly_sql

if TYPE_CHECKING:
    from flask_deck.api_keys import APIKeyRecord
    from flask_deck.deck import Deck

MCP_PROTOCOL_VERSION = "2025-03-26"


def _tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "list_models",
            "description": "List all models accessible to the caller along with permissions and actions.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "describe_model",
            "description": "Describe columns, types, choices, relationships, and approval rules for a model.",
            "inputSchema": {
                "type": "object",
                "properties": {"slug": {"type": "string"}},
                "required": ["slug"],
            },
        },
        {
            "name": "query_records",
            "description": "Query filtered, sorted, paginated records obeying RBAC row/field scoping and PII masking.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "q": {"type": "string"},
                    "filters": {"type": "object"},
                    "sort": {"type": "string"},
                    "dir": {"type": "string", "enum": ["asc", "desc"]},
                    "page": {"type": "integer"},
                    "page_size": {"type": "integer"},
                },
                "required": ["slug"],
            },
        },
        {
            "name": "get_record",
            "description": "Fetch a single record by primary key with RBAC and PII redaction.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "pk": {"type": "string"},
                },
                "required": ["slug", "pk"],
            },
        },
        {
            "name": "get_audit_log",
            "description": "Query recent audit entries (respects RBAC model exclusions and sensitive redaction).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "model_slug": {"type": "string"},
                    "action": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        },
        {
            "name": "run_readonly_sql",
            "description": "Execute a validated read-only SELECT/WITH SQL query with PII column masking.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string"},
                    "bind_key": {"type": "string"},
                },
                "required": ["sql"],
            },
        },
        {
            "name": "get_approval_status",
            "description": "Inspect status of a Maker-Checker approval request.",
            "inputSchema": {
                "type": "object",
                "properties": {"approval_id": {"type": "string"}},
                "required": ["approval_id"],
            },
        },
        {
            "name": "propose_create",
            "description": "Validate via DB savepoint and propose creating a record (queued for human approval when required).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "values": {"type": "object"},
                    "reason": {"type": "string"},
                },
                "required": ["slug", "values"],
            },
        },
        {
            "name": "propose_update",
            "description": "Validate via DB savepoint and propose updating an existing record (queued for human approval when required).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "pk": {"type": "string"},
                    "values": {"type": "object"},
                    "expected_version": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["slug", "pk", "values"],
            },
        },
        {
            "name": "propose_delete",
            "description": "Propose deleting a record (queued for human approval when required).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "pk": {"type": "string"},
                    "force": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["slug", "pk"],
            },
        },
        {
            "name": "propose_action",
            "description": "Propose invoking a registered @action on one or more records.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "action_name": {"type": "string"},
                    "pks": {"type": "array", "items": {"type": "string"}},
                    "params": {"type": "object"},
                    "reason": {"type": "string"},
                },
                "required": ["slug", "action_name", "pks"],
            },
        },
    ]


class DeckMCPServer:
    """Zero-dependency JSON-RPC 2.0 MCP Server with SAVEPOINT validation & HITL queueing."""

    def __init__(self, deck: Deck) -> None:
        self.deck = deck

    def _perm_check(
        self,
        user: DeckUser | None,
        api_key: APIKeyRecord | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        from flask_deck.api_keys import api_key_allows

        if not self.deck.auth.has_permission(user, permission, model_slug=model_slug, obj=obj):
            return False
        return api_key is None or api_key_allows(api_key, permission)

    def _require(
        self,
        user: DeckUser | None,
        api_key: APIKeyRecord | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> None:
        if not self._perm_check(user, api_key, permission, model_slug=model_slug, obj=obj):
            raise PermissionDeniedError(f"Missing permission: {permission}")

    def _fetch_record(
        self, view: Any, raw_pk: str, user: DeckUser | None
    ) -> tuple[Any, tuple[Any, ...]]:
        pk_vals = decode_pk(raw_pk, view.meta)
        stmt = view.scope_query(sa.select(view.model), user)
        for pk_f, val in zip(view.meta.primary_keys, pk_vals, strict=True):
            stmt = stmt.where(getattr(view.model, pk_f.name) == val)
        obj = self.deck.get_session(view.bind_key).scalars(stmt).unique().first()
        if obj is None:
            raise LookupError(f"Record '{raw_pk}' not found or out of scope.")
        return obj, pk_vals

    def _get_view_checked(self, slug: str) -> Any:
        view = self.deck.views.get(slug)
        if view is None:
            raise LookupError(f"Unknown model slug: '{slug}'")
        return view

    def _call_tool(
        self,
        name: str,
        args: Mapping[str, Any],
        *,
        user: DeckUser | None,
        api_key: APIKeyRecord | None,
    ) -> dict[str, Any]:
        deck = self.deck
        if deck.config.demo_safe_mode and name in {
            "propose_create",
            "propose_update",
            "propose_delete",
            "propose_action",
        }:
            raise PermissionDeniedError("Mutating MCP tools are disabled in public Demo Safe Mode.")
        if name == "list_models":
            models = []
            for slug, view in deck.views.items():
                if not view.can_view or not self._perm_check(
                    user, api_key, f"{slug}:view", model_slug=slug
                ):
                    continue
                models.append(
                    {
                        "slug": slug,
                        "name": view.meta.name,
                        "label": view.label,
                        "plural_label": view.plural_label,
                        "approval_required": bool(
                            deck.config.mcp_require_approval
                            or view.requires_approval(user, "create")
                            or view.requires_approval(user, "edit")
                            or view.requires_approval(user, "delete")
                        ),
                        "actions": list(view.get_actions(user).keys()),
                    }
                )
            return {"models": models}

        if name == "describe_model":
            slug = str(args.get("slug", "")).strip()
            view = self._get_view_checked(slug)
            self._require(user, api_key, f"{slug}:view", model_slug=slug)
            hidden = deck.auth.hidden_fields_for(user, slug)
            return {
                "slug": slug,
                "name": view.meta.name,
                "label": view.label,
                "mcp_require_approval": deck.config.mcp_require_approval,
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
                "searchable": list(deck._allowed_query_fields(view, user)[0]),
                "filterable": sorted(deck._allowed_query_fields(view, user)[1]),
                "sortable": sorted(deck._allowed_query_fields(view, user)[2]),
                "actions": [
                    {"name": s.name, "label": s.label, "require_approval": s.require_approval}
                    for s in view.get_actions(user).values()
                ],
            }

        if name == "query_records":
            slug = str(args.get("slug", "")).strip()
            view = self._get_view_checked(slug)
            self._require(user, api_key, f"{slug}:view", model_slug=slug)
            visible_cols = view.visible_list_columns(deck.auth, user)
            allowed_s, allowed_f, allowed_sort = deck._allowed_query_fields(view, user)
            raw_filters = args.get("filters") or {}
            filter_pairs = [
                (str(k), str(v))
                for k, v in (raw_filters.items() if isinstance(raw_filters, Mapping) else ())
                if str(v).strip()
            ]
            page = max(1, int(args.get("page", 1)))
            page_size = min(100, max(1, int(args.get("page_size", 25))))
            res = execute_list_query(
                deck.get_session(view.bind_key),
                view.meta,
                base_stmt=view.scope_query(sa.select(view.model), user),
                displayed_columns=visible_cols,
                searchable_columns=allowed_s,
                filterable_columns=allowed_f,
                sortable_columns=allowed_sort,
                quick_tabs=view.quick_tabs,
                active_tab_key=None,
                search_term=str(args.get("q", "")).strip(),
                filter_params=filter_pairs,
                sort_by=str(args.get("sort", "")).strip() or None,
                sort_dir=str(args.get("dir", "desc")).strip(),
                default_sort=view.default_sort,
                page=page,
                page_size=page_size,
                max_page_size=deck.config.max_page_size,
                pagination_mode="offset",
                count_mode=view.count_mode,
                cursor_secret=deck._cursor_secret(),
                soft_delete_column=view.soft_delete_column,
                show_full_result_count=False,
                trashed=False,
            )
            return {
                "items": [serialize_record_for_api(deck, view, it, user) for it in res.items],
                "total": res.total,
                "page": res.page,
                "pages": res.pages,
            }

        if name == "get_record":
            slug = str(args.get("slug", "")).strip()
            pk_raw = str(args.get("pk", "")).strip()
            view = self._get_view_checked(slug)
            self._require(user, api_key, f"{slug}:view", model_slug=slug)
            obj, _ = self._fetch_record(view, pk_raw, user)
            self._require(user, api_key, f"{slug}:view", model_slug=slug, obj=obj)
            return {"record": serialize_record_for_api(deck, view, obj, user)}

        if name == "get_audit_log":
            if deck.audit_store is None:
                return {"entries": []}
            self._require(user, api_key, "audit:view")
            excluded = deck._excluded_audit_models(user)
            entries, total = deck.audit_store.list_entries(
                model_slug=str(args.get("model_slug", "")).strip() or None,
                action=str(args.get("action", "")).strip() or None,
                excluded_models=excluded,
                search_changes=not deck._user_has_field_restrictions(user),
                limit=min(100, max(1, int(args.get("limit", 25)))),
            )
            safe = [deck._sanitize_audit_entry(e, user) for e in entries]
            return {
                "total": total,
                "entries": [
                    {
                        "id": e.id,
                        "timestamp": e.timestamp.isoformat(),
                        "actor_name": e.actor_name,
                        "action": e.action,
                        "model_slug": e.model_slug,
                        "record_pk": e.record_pk,
                        "record_repr": e.record_repr,
                        "changes": e.changes,
                        "metadata": e.metadata,
                    }
                    for e in safe
                ],
            }

        if name == "run_readonly_sql":
            self._require(user, api_key, "sql:query")
            sql_text = str(args.get("sql", "")).strip()
            bind_key = str(args.get("bind_key", "")).strip() or None
            assert deck.adapter is not None
            if bind_key:
                eng = deck.adapter.get_engines().get(bind_key)
                if eng is None:
                    raise LookupError(f"Unknown bind key: '{bind_key}'")
            else:
                eng = deck.adapter.get_engine()
            q_res = execute_readonly_sql(
                eng,
                sql_text,
                max_rows=deck.config.sql_console_max_rows,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            )
            if q_res.error:
                raise ValueError(q_res.error)
            return {
                "columns": list(q_res.columns),
                "rows": [list(r) for r in q_res.rows],
                "row_count": q_res.row_count,
                "truncated": q_res.truncated,
                "redacted_columns": list(q_res.redacted_columns),
            }

        if name == "get_approval_status":
            if deck.approval_store is None:
                raise ValueError("Approval queue is disabled.")
            app_id = str(args.get("approval_id", "")).strip()
            req = deck.approval_store.get(app_id)
            if req is None:
                raise LookupError(f"Approval '{app_id}' not found.")
            allowed = (
                self._perm_check(user, api_key, "approvals:view")
                or self._perm_check(user, api_key, "approvals:review")
                or (user is not None and req.requester_id == user.id)
            )
            if not allowed:
                raise PermissionDeniedError("Missing permission: approvals:view")
            return {
                "id": req.id,
                "status": req.status,
                "model_slug": req.model_slug,
                "operation": req.operation,
                "record_pk": req.record_pk,
                "actor_type": req.actor_type,
                "requester_id": req.requester_id,
                "reviewer_name": req.reviewer_name,
                "review_note": req.review_note,
                "diff": req.diff,
            }

        if name in {"propose_create", "propose_update", "propose_delete", "propose_action"}:
            if deck.config.read_only:
                raise PermissionDeniedError("Flask-Deck is running in read-only mode.")
            return self._handle_propose(name, args, user=user, api_key=api_key)

        raise LookupError(f"Unknown MCP tool: '{name}'")

    def _handle_propose(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        user: DeckUser | None,
        api_key: APIKeyRecord | None,
    ) -> dict[str, Any]:
        deck = self.deck
        slug = str(args.get("slug", "")).strip()
        view = self._get_view_checked(slug)
        reason = str(args.get("reason", "")).strip()[:500]
        sess = deck.get_session(view.bind_key)

        def _need_approval(op: str, *, obj: Any = None, payload: Mapping[str, Any] | None = None, spec_req: bool = False) -> bool:
            if deck.approval_store is None:
                return False
            if deck.config.mcp_require_approval or spec_req:
                return True
            return bool(view.requires_approval(user, op, obj=obj, payload=payload))

        if tool_name == "propose_create":
            if not view.can_create:
                raise PermissionDeniedError("Creation is disabled on this model.")
            self._require(user, api_key, f"{slug}:create", model_slug=slug)
            values = args.get("values")
            if not isinstance(values, Mapping):
                raise ValueError("'values' must be a JSON object.")
            obj = view.model()
            need_create_app = _need_approval("create", payload=values)
            try:
                form_md = build_multidict_from_json(deck, view, values, user=user, mode="create")
                apply_json_mutation(
                    deck,
                    sess,
                    view,
                    obj,
                    form_md,
                    user=user,
                    mode="create",
                    run_hooks=not need_create_app,
                )
                sess.add(obj)
                sess.flush()
                diff = compute_diff(
                    {},
                    view.extract_snapshot(obj),
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            except (ValidationError, IntegrityError, SQLAlchemyError) as exc:
                sess.rollback()
                raise ValueError(f"Savepoint validation failed: {exc}") from exc

            if need_create_app:
                sess.rollback()
                assert deck.approval_store is not None
                saved = deck.approval_store.create(
                    make_approval_request(
                        model_slug=slug,
                        model_label=view.label,
                        operation="create",
                        record_pk="pending",
                        record_repr=safe_repr,
                        payload={
                            "form_items": [[k, v] for k, v in form_md.items(multi=True)],
                            "utc_passthrough": True,
                            "_actor_roles": list(user.roles) if user else [],
                            "_actor_superuser": bool(user.is_superuser) if user else False,
                        },
                        diff=diff,
                        reason=reason,
                        requester_id=user.id if user else "mcp-agent",
                        requester_name=user.label if user else "MCP Agent",
                        actor_type="mcp_agent",
                    )
                )
                deck._emit_event(
                    "approval.requested",
                    model_slug=slug,
                    record_pk=saved.id,
                    payload={"approval_id": saved.id, "operation": "create", "actor_type": "mcp_agent"},
                )
                return {
                    "status": "pending_approval",
                    "approval_id": saved.id,
                    "actor_type": "mcp_agent",
                    "diff": saved.diff,
                }

            sess.commit()
            pk_str = encode_pk(extract_pk(obj, view.meta))
            deck._record_audit(
                action_name="create",
                view=view,
                record_pk=pk_str,
                record_repr=safe_repr,
                changes=diff,
                metadata={"source": "mcp", "actor_type": "mcp_agent"},
                actor=user,
            )
            return {
                "status": "executed",
                "record": serialize_record_for_api(deck, view, obj, user),
            }

        if tool_name == "propose_update":
            if not view.can_edit:
                raise PermissionDeniedError("Editing is disabled on this model.")
            pk_raw = str(args.get("pk", "")).strip()
            obj, pk_vals = self._fetch_record(view, pk_raw, user)
            pk_str = encode_pk(pk_vals)
            self._require(user, api_key, f"{slug}:edit", model_slug=slug, obj=obj)
            if not view.can_edit_record(obj, user):
                raise PermissionDeniedError(f"Not authorized to edit this {view.label}.")
            if deck._is_soft_deleted(view, obj):
                raise ValueError("Cannot update a soft-deleted record.")
            expected_ver = str(args.get("expected_version", "")).strip()
            current_ver = view.compute_version_token(obj, auth=deck.auth, user=user)
            if expected_ver and expected_ver != current_ver:
                raise ValueError(f"OCC version mismatch: expected {expected_ver}, current {current_ver}")
            values = args.get("values")
            if not isinstance(values, Mapping):
                raise ValueError("'values' must be a JSON object.")
            before_snap = view.extract_snapshot(obj)
            need_app = _need_approval("edit", obj=obj, payload=values)
            try:
                form_md = build_multidict_from_json(
                    deck, view, values, user=user, mode="edit", obj=obj
                )
                apply_json_mutation(
                    deck,
                    sess,
                    view,
                    obj,
                    form_md,
                    user=user,
                    mode="edit",
                    run_hooks=not need_app,
                )
                if not need_app and view.version_column:
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
                safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            except (ValidationError, IntegrityError, SQLAlchemyError) as exc:
                sess.rollback()
                raise ValueError(f"Savepoint validation failed: {exc}") from exc

            if need_app:
                sess.rollback()
                assert deck.approval_store is not None
                saved = deck.approval_store.create(
                    make_approval_request(
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
                        requester_id=user.id if user else "mcp-agent",
                        requester_name=user.label if user else "MCP Agent",
                        actor_type="mcp_agent",
                    )
                )
                deck._emit_event(
                    "approval.requested",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"approval_id": saved.id, "operation": "edit", "actor_type": "mcp_agent"},
                )
                return {
                    "status": "pending_approval",
                    "approval_id": saved.id,
                    "actor_type": "mcp_agent",
                    "diff": saved.diff,
                }

            sess.commit()
            if diff:
                deck._record_audit(
                    action_name="update",
                    view=view,
                    record_pk=pk_str,
                    record_repr=safe_repr,
                    changes=diff,
                    metadata={"source": "mcp", "actor_type": "mcp_agent"},
                    actor=user,
                )
            return {
                "status": "executed",
                "record": serialize_record_for_api(deck, view, obj, user),
            }

        if tool_name == "propose_delete":
            if not view.can_delete:
                raise PermissionDeniedError("Deletion is disabled on this model.")
            pk_raw = str(args.get("pk", "")).strip()
            obj, pk_vals = self._fetch_record(view, pk_raw, user)
            pk_str = encode_pk(pk_vals)
            self._require(user, api_key, f"{slug}:delete", model_slug=slug, obj=obj)
            if not view.can_delete_record(obj, user):
                raise PermissionDeniedError(f"Not authorized to delete this {view.label}.")
            force = bool(args.get("force", False))
            if view.soft_delete_column and force:
                self._require(user, api_key, f"{slug}:force_delete", model_slug=slug, obj=obj)
            before_snap = view.extract_snapshot(obj)
            safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            if _need_approval("delete", obj=obj, payload={"force": force}):
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
                assert deck.approval_store is not None
                saved = deck.approval_store.create(
                    make_approval_request(
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
                        reason=reason,
                        requester_id=user.id if user else "mcp-agent",
                        requester_name=user.label if user else "MCP Agent",
                        actor_type="mcp_agent",
                    )
                )
                deck._emit_event(
                    "approval.requested",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"approval_id": saved.id, "operation": "delete", "actor_type": "mcp_agent"},
                )
                return {
                    "status": "pending_approval",
                    "approval_id": saved.id,
                    "actor_type": "mcp_agent",
                    "diff": saved.diff,
                }
            if view.soft_delete_column and not force:
                fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
                if fmeta is not None:
                    view.on_model_delete(obj, user=user)
                    setattr(
                        obj,
                        view.soft_delete_column,
                        True if fmeta.field_type == "boolean" else datetime.now(timezone.utc),
                    )
                    sess.commit()
                    return {"status": "executed", "deleted": pk_str, "soft": True}
            orphans = deck._collect_orphan_files(view, obj)
            view.on_model_delete(obj, user=user)
            sess.delete(obj)
            sess.commit()
            deck._delete_orphan_files_best_effort(orphans)
            return {"status": "executed", "deleted": pk_str, "soft": False}

        # propose_action
        action_name = str(args.get("action_name", "")).strip()
        resolved_act = deck._resolve_action_spec_and_handler(view, action_name, user)
        if resolved_act is None:
            raise LookupError(f"Unknown action '{action_name}' on model '{slug}'.")
        spec, handler = resolved_act
        perm = spec.permission or f"{slug}:action:{action_name}"
        self._require(user, api_key, perm, model_slug=slug)
        raw_pks = [str(p) for p in (args.get("pks") or [])]
        if not raw_pks:
            raise ValueError("Action requires at least one primary key in 'pks'.")
        decoded = [decode_pk(p, view.meta) for p in raw_pks]
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
            raise LookupError("No matching authorized records found.")
        for rec in records:
            self._require(user, api_key, perm, model_slug=slug, obj=rec)

        raw_params = args.get("params") or {}
        form_md = MultiDict(
            [(str(k), str(v)) for k, v in (raw_params.items() if isinstance(raw_params, Mapping) else ())]
        )
        for af in spec.fields:
            rv = form_md.get(af.name, "").strip()
            if af.required and not rv:
                raise ValueError(f"Action '{spec.label}' requires '{af.display_label}'.")

        if _need_approval("action", payload={"action_name": action_name, "pks": raw_pks}, spec_req=spec.require_approval):
            sess.rollback()
            assert deck.approval_store is not None
            saved = deck.approval_store.create(
                make_approval_request(
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
                    diff={"action": {"old": None, "new": f"{spec.label} ({len(records)} records)"}},
                    reason=reason,
                    requester_id=user.id if user else "mcp-agent",
                    requester_name=user.label if user else "MCP Agent",
                    actor_type="mcp_agent",
                )
            )
            deck._emit_event(
                "approval.requested",
                model_slug=slug,
                record_pk=saved.id,
                payload={"approval_id": saved.id, "operation": "action", "action": action_name, "actor_type": "mcp_agent"},
            )
            return {
                "status": "pending_approval",
                "approval_id": saved.id,
                "actor_type": "mcp_agent",
                "diff": saved.diff,
            }

        msg = handler(records, form_md, user)
        sess.commit()
        msg_str = "Done" if isinstance(msg, Response) else str(msg or "Done")
        return {"status": "executed", "message": msg_str, "count": len(records)}

    def handle_message(
        self,
        message: Mapping[str, Any],
        *,
        user: DeckUser | None,
        api_key: APIKeyRecord | None = None,
    ) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 MCP request; return None for notifications."""
        msg_id = message.get("id")
        method = str(message.get("method", "")).strip()
        params = message.get("params")
        param_map: Mapping[str, Any] = params if isinstance(params, Mapping) else {}

        if msg_id is None and method.startswith("notifications/"):
            return None

        def _ok(res: Any) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": msg_id, "result": res}

        def _err(code: int, text: str) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": text}}

        if method == "initialize":
            return _ok(
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}, "resources": {}},
                    "serverInfo": {
                        "name": f"{self.deck.config.name}-mcp",
                        "version": __version__,
                    },
                }
            )
        if method == "ping":
            return _ok({})
        if method == "tools/list":
            return _ok({"tools": _tool_definitions()})
        if method == "resources/list":
            resources = [
                {
                    "uri": f"deck://models/{slug}",
                    "name": view.plural_label,
                    "mimeType": "application/json",
                }
                for slug, view in self.deck.views.items()
                if view.can_view and self._perm_check(user, api_key, f"{slug}:view", model_slug=slug)
            ]
            return _ok({"resources": resources})
        if method == "resources/read":
            uri = str(param_map.get("uri", "")).strip()
            prefix = "deck://models/"
            if not uri.startswith(prefix):
                return _err(-32602, f"Unsupported resource URI: {uri}")
            slug = uri[len(prefix) :].strip("/")
            try:
                data = self._call_tool("describe_model", {"slug": slug}, user=user, api_key=api_key)
                return _ok(
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(data, default=str),
                            }
                        ]
                    }
                )
            except (PermissionDeniedError, LookupError, ValueError) as exc:
                return _err(-32000, str(exc))
        if method == "tools/call":
            tool_name = str(param_map.get("name", "")).strip()
            raw_args = param_map.get("arguments")
            tool_args: Mapping[str, Any] = raw_args if isinstance(raw_args, Mapping) else {}
            try:
                out = self._call_tool(tool_name, tool_args, user=user, api_key=api_key)
                return _ok(
                    {
                        "content": [{"type": "text", "text": json.dumps(out, default=str)}],
                        "structuredContent": out,
                        "isError": False,
                    }
                )
            except (PermissionDeniedError, LookupError, ValueError) as exc:
                err_out = {"error": str(exc)}
                return _ok(
                    {
                        "content": [{"type": "text", "text": json.dumps(err_out)}],
                        "structuredContent": err_out,
                        "isError": True,
                    }
                )
        return _err(-32601, f"Method not found: '{method}'")


def run_mcp_stdio(
    deck: Deck,
    *,
    api_key_token: str | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run JSON-RPC 2.0 MCP server over newline-delimited stdio."""
    from flask_deck.api_keys import api_key_to_user

    in_stream = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    user: DeckUser | None = None
    key_rec: APIKeyRecord | None = None
    if api_key_token and deck.api_key_store is not None:
        key_rec = deck.api_key_store.verify_token(api_key_token.strip())
        if key_rec is None:
            raise PermissionDeniedError("Invalid, expired, or revoked API key.")
        user = api_key_to_user(key_rec)
    elif deck.config.allow_insecure_open:
        user = deck.auth.get_current_user()

    server = DeckMCPServer(deck)
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp: dict[str, Any] | None = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
        else:
            if not isinstance(msg, Mapping):
                resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"},
                }
            else:
                resp = server.handle_message(msg, user=user, api_key=key_rec)
        if resp is not None:
            out_stream.write(json.dumps(resp, default=str) + "\n")
            out_stream.flush()
    return 0


def register_mcp_routes(bp: Blueprint, deck: Deck) -> None:
    """Register Streamable HTTP MCP JSON-RPC endpoint (``POST /_mcp``)."""
    server = DeckMCPServer(deck)

    @bp.route("/_mcp", methods=["POST"])
    def mcp_endpoint() -> tuple[Response, int] | Response:
        origin = (request.headers.get("Origin") or "").strip()
        if origin:
            parsed = urlsplit(origin)
            if parsed.netloc and parsed.netloc != request.host:
                return jsonify({"error": "Cross-origin MCP request rejected (DNS rebinding guard)."}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, Mapping):
            return (
                jsonify(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Invalid JSON-RPC request"},
                    }
                ),
                400,
            )
        from flask import g

        user = deck._current_user()
        api_key = getattr(g, "_deck_api_key", None)
        res = server.handle_message(payload, user=user, api_key=api_key)
        if res is None:
            return Response(status=204)
        return jsonify(res), 200
