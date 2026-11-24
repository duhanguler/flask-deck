from __future__ import annotations

import csv
import enum
import io
import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from flask import Response, stream_with_context
from sqlalchemy.orm import Session

from flask_deck.adapters.sqlalchemy import extract_pk
from flask_deck.auth import AuthProvider, DeckUser
from flask_deck.introspection import introspect_model
from flask_deck.model_view import ModelView
from flask_deck.query import (
    _apply_filter_params,
    build_filter_condition,
    build_search_clause,
    parse_filter_key,
    parse_search_column_spec,
    soft_delete_predicate,
)
from flask_deck.security import is_sensitive_field, sanitize_csv_cell

_XLSX_INVALID_TITLE_RE = re.compile(r"[/\\?*\[\]:]")


def _serialize_export_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (Decimal, UUID)):
        return str(value)
    if isinstance(value, (dict, list)):
        return value
    return str(value)


def _build_export_statement(
    view: ModelView,
    *,
    auth: AuthProvider,
    user: DeckUser | None,
    search_term: str,
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]],
    active_tab_key: str | None,
    selected_pks: Sequence[tuple[Any, ...]] = (),
    dialect_name: str = "",
    trashed: bool = False,
    searchable_columns: Sequence[str] | None = None,
    views_by_model: Mapping[type[Any], ModelView] | None = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    custom_filter_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
) -> tuple[sa.Select[Any], bool]:
    meta = view.meta
    stmt = view.scope_query(sa.select(view.model), user)
    sd_pred = soft_delete_predicate(meta, view.soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        stmt = stmt.where(sd_pred)

    restricted = auth.hidden_fields_for(user, meta.slug) | auth.masked_fields_for(user, meta.slug)
    if searchable_columns is not None:
        allowed_searchable = tuple(searchable_columns)
    else:
        allowed_items: list[str] = []
        for col_spec in view.resolved_searchable:
            col_path, _ = parse_search_column_spec(col_spec)
            if "." in col_path:
                rel_name, target_col = col_path.split(".", 1)
                if rel_name in restricted or is_sensitive_field(target_col):
                    continue
                rel_meta = meta.relationships_by_name.get(rel_name)
                if rel_meta is not None:
                    t_view = views_by_model.get(rel_meta.target_model) if views_by_model else None
                    if t_view is not None:
                        t_restricted = auth.hidden_fields_for(user, t_view.meta.slug) | auth.masked_fields_for(
                            user, t_view.meta.slug
                        )
                        if target_col in t_restricted or target_col in t_view.meta.sensitive_fields:
                            continue
                    else:
                        t_meta = introspect_model(rel_meta.target_model)
                        t_restricted = auth.hidden_fields_for(user, t_meta.slug) | auth.masked_fields_for(
                            user, t_meta.slug
                        )
                        if target_col in t_restricted or target_col in t_meta.sensitive_fields:
                            continue
                allowed_items.append(col_spec)
            elif col_path not in restricted and not is_sensitive_field(col_path):
                allowed_items.append(col_spec)
        allowed_searchable = tuple(allowed_items)
    allowed_filterable = view.resolved_filterable - restricted
    known_fields = frozenset(meta.fields_by_name.keys())

    search_joins: list[Any] = []
    search_may_dup = False
    if search_term:
        if view.has_custom_search_results():
            stmt, search_may_dup = view.get_search_results(stmt, search_term, user)
        else:
            search_clause, search_joins = build_search_clause(
                meta, allowed_searchable, search_term, dialect_name=dialect_name
            )
            for rel_attr in search_joins:
                stmt = stmt.outerjoin(rel_attr)
            if search_clause is not None:
                stmt = stmt.where(search_clause)

    if active_tab_key and not trashed:
        for tab in view.quick_tabs:
            if tab.key == active_tab_key:
                for raw_fname, fval in tab.filters.items():
                    fname, fop = parse_filter_key(raw_fname, known_fields)
                    cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
                    if cond is not None:
                        stmt = stmt.where(cond)
                break

    where_clauses: list[sa.ColumnElement[bool]] = []
    extra_joins: list[Any] = []
    seen_joins: set[Any] = {getattr(j, "key", id(j)) for j in search_joins}
    _apply_filter_params(
        meta,
        filter_params,
        allowed_filterable,
        dialect_name=dialect_name,
        where_clauses=where_clauses,
        joins=extra_joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
    )
    for rel_attr in extra_joins:
        stmt = stmt.outerjoin(rel_attr)
    if where_clauses:
        stmt = stmt.where(*where_clauses)

    if selected_pks:
        if len(meta.primary_keys) == 1:
            pk_col = getattr(view.model, meta.primary_keys[0].name)
            stmt = stmt.where(pk_col.in_([pk[0] for pk in selected_pks]))
        else:
            pk_cols = [getattr(view.model, pk.name) for pk in meta.primary_keys]
            stmt = stmt.where(sa.tuple_(*pk_cols).in_(selected_pks))
    if extra_where:
        stmt = stmt.where(*extra_where)
    for applier in custom_filter_appliers:
        stmt = applier(stmt)

    pk_orders = [getattr(view.model, pk.name).asc() for pk in meta.primary_keys]
    return stmt.order_by(*pk_orders), bool(search_joins or extra_joins or search_may_dup)


def export_columns_for_user(
    view: ModelView,
    auth: AuthProvider,
    user: DeckUser | None,
) -> tuple[str, ...]:
    hidden = auth.hidden_fields_for(user, view.meta.slug)
    return tuple(
        col
        for col in view.resolved_export_columns
        if col not in hidden and col not in view.meta.sensitive_fields
    )


def iter_export_chunks(
    session: Session,
    view: ModelView,
    *,
    fmt: str,
    auth: AuthProvider,
    user: DeckUser | None,
    search_term: str = "",
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]] = (),
    active_tab_key: str | None = None,
    selected_pks: Sequence[tuple[Any, ...]] = (),
    sanitize_csv: bool = True,
    chunk_size: int = 500,
    trashed: bool = False,
    searchable_columns: Sequence[str] | None = None,
    views_by_model: Mapping[type[Any], ModelView] | None = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    custom_filter_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
) -> tuple[Iterator[Any], str, str]:
    """Yield formatted export chunks in O(1) memory without requiring a Flask request context."""
    cols = export_columns_for_user(view, auth, user)
    masked = auth.masked_fields_for(user, view.meta.slug)
    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""
    stmt, has_joins = _build_export_statement(
        view,
        auth=auth,
        user=user,
        search_term=search_term,
        filter_params=filter_params,
        active_tab_key=active_tab_key,
        selected_pks=selected_pks,
        dialect_name=dialect_name,
        trashed=trashed,
        searchable_columns=searchable_columns,
        views_by_model=views_by_model,
        extra_where=extra_where,
        custom_filter_appliers=custom_filter_appliers,
    )

    def _iter_objects() -> Iterator[Any]:
        last_pk: tuple[Any, ...] | None = None
        for obj in session.scalars(stmt).yield_per(chunk_size):
            if has_joins:
                pk = extract_pk(obj, view.meta)
                if pk == last_pk:
                    continue
                last_pk = pk
            yield obj

    def _row_dict(obj: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for col in cols:
            val = getattr(obj, col, None)
            if col in masked:
                val = auth.mask_field_value(user, view.meta.slug, col, val)
            out[col] = _serialize_export_value(val)
        return out

    fmt_clean = fmt.lower()
    if fmt_clean == "xlsx":
        try:
            import openpyxl  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "XLSX export requires openpyxl. Install with: pip install 'flask-deck[excel]'"
            ) from exc

        def _gen_xlsx() -> Iterator[bytes]:
            wb = openpyxl.Workbook(write_only=True)
            try:
                safe_title = _XLSX_INVALID_TITLE_RE.sub("_", view.plural_label).strip()[:31] or "Export"
                ws = wb.create_sheet(title=safe_title)
                ws.append([sanitize_csv_cell(c, enabled=sanitize_csv) for c in cols])
                for obj in _iter_objects():
                    row_data = _row_dict(obj)
                    ws.append(
                        [
                            sanitize_csv_cell(
                                json.dumps(row_data[c], separators=(",", ":"))
                                if isinstance(row_data[c], (dict, list))
                                else row_data[c],
                                enabled=sanitize_csv,
                            )
                            for c in cols
                        ]
                    )
                buf = io.BytesIO()
                wb.save(buf)
                yield buf.getvalue()
            finally:
                close_fn = getattr(wb, "close", None)
                if callable(close_fn):
                    close_fn()

        return (
            _gen_xlsx(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            f"{view.meta.slug}.xlsx",
        )

    if fmt_clean == "csv":

        def _gen_csv() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(cols)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            for obj in _iter_objects():
                row_data = _row_dict(obj)
                cells = [
                    sanitize_csv_cell(
                        json.dumps(row_data[c], separators=(",", ":"))
                        if isinstance(row_data[c], (dict, list))
                        else row_data[c],
                        enabled=sanitize_csv,
                    )
                    for c in cols
                ]
                writer.writerow(cells)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        return _gen_csv(), "text/csv; charset=utf-8", f"{view.meta.slug}.csv"

    if fmt_clean == "jsonl":

        def _gen_jsonl() -> Iterator[str]:
            for obj in _iter_objects():
                yield json.dumps(_row_dict(obj), separators=(",", ":")) + "\n"

        return _gen_jsonl(), "application/x-ndjson; charset=utf-8", f"{view.meta.slug}.jsonl"

    def _gen_json() -> Iterator[str]:
        yield "[\n"
        first = True
        for obj in _iter_objects():
            prefix = "" if first else ",\n"
            first = False
            yield prefix + "  " + json.dumps(_row_dict(obj), separators=(",", ":"))
        yield "\n]\n"

    return _gen_json(), "application/json; charset=utf-8", f"{view.meta.slug}.json"


def stream_export_response(
    session: Session,
    view: ModelView,
    *,
    fmt: str,
    auth: AuthProvider,
    user: DeckUser | None,
    search_term: str = "",
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]] = (),
    active_tab_key: str | None = None,
    selected_pks: Sequence[tuple[Any, ...]] = (),
    sanitize_csv: bool = True,
    chunk_size: int = 500,
    trashed: bool = False,
    searchable_columns: Sequence[str] | None = None,
    views_by_model: Mapping[type[Any], ModelView] | None = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    custom_filter_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
) -> Response:
    """Stream filtered model records in O(1) memory as CSV, JSON, or JSONL."""
    gen, mimetype, filename = iter_export_chunks(
        session,
        view,
        fmt=fmt,
        auth=auth,
        user=user,
        search_term=search_term,
        filter_params=filter_params,
        active_tab_key=active_tab_key,
        selected_pks=selected_pks,
        sanitize_csv=sanitize_csv,
        chunk_size=chunk_size,
        trashed=trashed,
        searchable_columns=searchable_columns,
        views_by_model=views_by_model,
        extra_where=extra_where,
        custom_filter_appliers=custom_filter_appliers,
    )
    resp = Response(stream_with_context(gen), mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
