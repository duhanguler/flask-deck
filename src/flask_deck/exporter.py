from __future__ import annotations

import csv
import enum
import io
import json
from collections.abc import Iterator, Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from flask import Response, stream_with_context
from sqlalchemy.orm import Session

from flask_deck.auth import AuthProvider, DeckUser
from flask_deck.model_view import ModelView
from flask_deck.query import (
    build_filter_condition,
    build_search_clause,
    iter_filter_items,
    parse_filter_key,
    soft_delete_predicate,
)
from flask_deck.security import sanitize_csv_cell


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
) -> sa.Select[Any]:
    meta = view.meta
    stmt = view.scope_query(sa.select(view.model), user)
    sd_pred = soft_delete_predicate(meta, view.soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        stmt = stmt.where(sd_pred)

    restricted = auth.hidden_fields_for(user, meta.slug) | auth.masked_fields_for(user, meta.slug)
    allowed_searchable = tuple(
        c for c in view.resolved_searchable if c.split(".", 1)[0] not in restricted
    )
    allowed_filterable = view.resolved_filterable - restricted
    known_fields = frozenset(meta.fields_by_name.keys())

    search_clause, search_joins = build_search_clause(meta, allowed_searchable, search_term)
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

    for raw_key, raw_val in iter_filter_items(filter_params):
        if not raw_val:
            continue
        fname, op = parse_filter_key(raw_key, known_fields)
        if fname not in allowed_filterable:
            continue
        cond = build_filter_condition(meta, fname, raw_val, op=op, dialect_name=dialect_name)
        if cond is not None:
            stmt = stmt.where(cond)

    if selected_pks:
        if len(meta.primary_keys) == 1:
            pk_col = getattr(view.model, meta.primary_keys[0].name)
            stmt = stmt.where(pk_col.in_([pk[0] for pk in selected_pks]))
        else:
            pk_cols = [getattr(view.model, pk.name) for pk in meta.primary_keys]
            stmt = stmt.where(sa.tuple_(*pk_cols).in_(selected_pks))

    return stmt.order_by(getattr(view.model, meta.primary_keys[0].name).asc())


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
) -> tuple[Iterator[str], str, str]:
    """Yield formatted export chunks in O(1) memory without requiring a Flask request context."""
    cols = export_columns_for_user(view, auth, user)
    masked = auth.masked_fields_for(user, view.meta.slug)
    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""
    stmt = _build_export_statement(
        view,
        auth=auth,
        user=user,
        search_term=search_term,
        filter_params=filter_params,
        active_tab_key=active_tab_key,
        selected_pks=selected_pks,
        dialect_name=dialect_name,
        trashed=trashed,
    )

    def _row_dict(obj: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for col in cols:
            val = getattr(obj, col, None)
            if col in masked:
                val = auth.mask_field_value(user, view.meta.slug, col, val)
            out[col] = _serialize_export_value(val)
        return out

    fmt_clean = fmt.lower()
    if fmt_clean == "csv":

        def _gen_csv() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(cols)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            for obj in session.scalars(stmt).yield_per(chunk_size):
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
            for obj in session.scalars(stmt).yield_per(chunk_size):
                yield json.dumps(_row_dict(obj), separators=(",", ":")) + "\n"

        return _gen_jsonl(), "application/x-ndjson; charset=utf-8", f"{view.meta.slug}.jsonl"

    def _gen_json() -> Iterator[str]:
        yield "[\n"
        first = True
        for obj in session.scalars(stmt).yield_per(chunk_size):
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
    )
    resp = Response(stream_with_context(gen), mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
