from __future__ import annotations

import base64
import contextlib
import enum
import hashlib
import hmac
import json
import re
import time
import uuid
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from datetime import time as dt_time
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

import sqlalchemy as sa
from flask import g, has_request_context
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, defer, joinedload, selectinload

from flask_deck.formatters import normalize_tone
from flask_deck.introspection import FieldMeta, ModelMeta
from flask_deck.security import check_json_depth, escape_like

_TELEMETRY_G_KEY = "_flask_deck_sql_telemetry"
_INSTRUMENTED_ENGINES: weakref.WeakSet[Engine] = weakref.WeakSet()

_JSON_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){0,4}$")

PaginationMode = Literal["offset", "cursor"]
CountMode = Literal["exact", "estimated", "none"]

_FILTER_OP_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("__array_contains", "array_contains"),
    ("__json_contains", "json_contains"),
    ("__startswith", "startswith"),
    ("__array_any", "array_any"),
    ("__contains", "contains"),
    ("__has_key", "has_key"),
    ("__preset", "preset"),
    ("__null", "null"),
    ("__path", "path"),
    ("__neq", "neq"),
    ("__gte", "gte"),
    ("__lte", "lte"),
    ("__gt", "gt"),
    ("__lt", "lt"),
)


@dataclass(slots=True)
class RequestSQLTelemetry:
    """Request-scoped SQL query count and execution duration tracker."""

    query_count: int = 0
    sql_ms: float = 0.0
    started_at: float = field(default_factory=time.perf_counter)

    @property
    def total_ms(self) -> float:
        return (time.perf_counter() - self.started_at) * 1000.0


def begin_request_telemetry() -> RequestSQLTelemetry:
    tel = RequestSQLTelemetry()
    setattr(g, _TELEMETRY_G_KEY, tel)
    return tel


def get_request_telemetry() -> RequestSQLTelemetry | None:
    if not has_request_context():
        return None
    tel: RequestSQLTelemetry | None = getattr(g, _TELEMETRY_G_KEY, None)
    return tel


def attach_sql_telemetry(engine: Engine) -> None:
    """Attach a lightweight zero-overhead SQL listener once per SQLAlchemy Engine."""
    if engine in _INSTRUMENTED_ENGINES:
        return

    @sa.event.listens_for(engine, "before_cursor_execute")
    def _before_cursor_execute(
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if has_request_context() and getattr(g, _TELEMETRY_G_KEY, None) is not None:
            context._deck_q_start = time.perf_counter()

    @sa.event.listens_for(engine, "after_cursor_execute")
    def _after_cursor_execute(
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if not has_request_context():
            return
        tel: RequestSQLTelemetry | None = getattr(g, _TELEMETRY_G_KEY, None)
        if tel is None:
            return
        tel.query_count += 1
        q_start = getattr(context, "_deck_q_start", None)
        if q_start is not None:
            tel.sql_ms += (time.perf_counter() - q_start) * 1000.0

    _INSTRUMENTED_ENGINES.add(engine)


@dataclass(frozen=True, slots=True)
class QuickTab:
    """Declarative quick-filter tab displayed above model list grids."""

    key: str
    label: str
    filters: Mapping[str, Any] = field(default_factory=dict)
    tone: str = "neutral"

    @property
    def normalized_tone(self) -> str:
        return normalize_tone(self.tone)


@dataclass(frozen=True, slots=True)
class PageResult:
    """Paginated query result supporting both Offset and HMAC Keyset Cursor modes."""

    items: list[Any]
    total: int
    page: int
    page_size: int
    pages: int
    tab_counts: dict[str, int]
    active_filters: dict[str, str]
    pagination_mode: PaginationMode = "offset"
    next_cursor: str | None = None
    prev_cursor: str | None = None
    has_next: bool = False
    has_prev: bool = False
    total_is_estimated: bool = False
    total_known: bool = True
    trashed_count: int = 0


def iter_filter_items(
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Normalize filter parameters (single-value Mapping or multi-value pairs) into pairs."""
    if isinstance(filter_params, Mapping):
        return [(str(k), str(v)) for k, v in filter_params.items()]
    return [(str(k), str(v)) for k, v in filter_params]


def parse_filter_key(
    raw_key: str,
    known_fields: frozenset[str] | set[str] | None = None,
) -> tuple[str, str]:
    """Split a query filter key like `price__gte` into `(field_name, op)`."""
    if known_fields is not None and raw_key in known_fields:
        return raw_key, "eq"
    for suffix, op in _FILTER_OP_SUFFIXES:
        if raw_key.endswith(suffix):
            base = raw_key[: -len(suffix)]
            if known_fields is None or base in known_fields:
                return base, op
    return raw_key, "eq"


def _serialize_cursor_val(val: Any) -> Any:
    if val is None or isinstance(val, (int, float, bool, str)):
        return val
    if isinstance(val, enum.Enum):
        return val.value
    if isinstance(val, (datetime, date, dt_time)):
        return val.isoformat()
    if isinstance(val, (Decimal, uuid.UUID)):
        return str(val)
    return str(val)


def encode_cursor(payload: Mapping[str, Any], *, secret: bytes) -> str:
    """Encode and HMAC-SHA256 sign an opaque keyset pagination cursor."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    b64 = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    sig = hmac.new(secret or b"flask-deck-cursor", body, hashlib.sha256).hexdigest()[:24]
    return f"{b64}.{sig}"


def decode_cursor(token: str | None, *, secret: bytes) -> dict[str, Any] | None:
    """Verify HMAC signature and decode an opaque cursor token (fail-closed -> None)."""
    if not token or "." not in token or len(token) > 4096:
        return None
    b64_part, provided_sig = token.rsplit(".", 1)
    pad = "=" * (-len(b64_part) % 4)
    try:
        body = base64.urlsafe_b64decode(b64_part + pad)
    except Exception:
        return None
    expected_sig = hmac.new(secret or b"flask-deck-cursor", body, hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _coerce_filter_value(
    raw: Any,
    fmeta: FieldMeta,
    *,
    allow_empty_string: bool = False,
) -> Any:
    if raw is None:
        return None
    if raw == "":
        if allow_empty_string and fmeta.field_type in {"string", "text", "email", "url"}:
            return ""
        return None
    if fmeta.enum_class is not None:
        if isinstance(raw, fmeta.enum_class):
            return raw
        text = str(raw)
        for member in fmeta.enum_class:
            if str(member.value) == text or member.name == text:
                return member
        return None
    if fmeta.field_type == "boolean":
        if isinstance(raw, bool):
            return raw
        lower = str(raw).strip().lower()
        if lower in {"1", "true", "yes", "on"}:
            return True
        if lower in {"0", "false", "no", "off"}:
            return False
        return None
    if fmeta.field_type == "integer":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    if fmeta.field_type == "float":
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None
    if fmeta.field_type == "decimal":
        try:
            return Decimal(str(raw))
        except (InvalidOperation, ValueError):
            return None
    if fmeta.field_type == "uuid":
        try:
            return raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(raw))
        except (TypeError, ValueError):
            return None
    if fmeta.field_type == "date":
        if isinstance(raw, date) and not isinstance(raw, datetime):
            return raw
        try:
            return date.fromisoformat(str(raw)[:10])
        except ValueError:
            return None
    if fmeta.field_type == "time":
        if isinstance(raw, dt_time):
            return raw
        try:
            return dt_time.fromisoformat(str(raw))
        except ValueError:
            return None
    if fmeta.field_type == "datetime":
        if isinstance(raw, datetime):
            return raw
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            return dt
        except ValueError:
            try:
                d = date.fromisoformat(str(raw)[:10])
                return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
            except ValueError:
                return None
    return str(raw)


def _coerce_array_item(raw: str, item_type: str | None) -> Any:
    text = raw.strip()
    if item_type == "integer":
        try:
            return int(text)
        except ValueError:
            return None
    if item_type == "float":
        try:
            return float(text)
        except ValueError:
            return None
    if item_type == "boolean":
        lower = text.lower()
        if lower in {"1", "true", "yes"}:
            return True
        if lower in {"0", "false", "no"}:
            return False
        return None
    return text


def _pg_json_text_accessor(col: Any, parts: list[str]) -> Any:
    """Return text accessor compatible with both postgresql.JSONB (.astext) and generic sa.JSON (.as_string)."""
    indexed = col[parts] if len(parts) > 1 else col[parts[0]]
    return indexed.astext if hasattr(indexed, "astext") else indexed.as_string()


def _build_json_path_condition(
    col: Any,
    fmeta: FieldMeta,
    raw_value: str,
    *,
    dialect_name: str,
) -> sa.ColumnElement[bool] | None:
    if "=" not in raw_value:
        return None
    raw_path, expected = raw_value.split("=", 1)
    clean_path = raw_path.strip()
    if not _JSON_PATH_RE.fullmatch(clean_path):
        return None
    parts = clean_path.split(".")
    target = expected.strip()
    if dialect_name == "postgresql":
        accessor = _pg_json_text_accessor(col, parts)
        expr: sa.ColumnElement[bool] = accessor == target
        return expr
    # SQLite / MySQL / generic JSON extract
    json_path = f"$.{clean_path}"
    extracted = sa.func.json_extract(col, json_path)
    if dialect_name in {"mysql", "mariadb"}:
        mysql_expr: sa.ColumnElement[bool] = sa.func.json_unquote(extracted) == target
        return mysql_expr
    # Handle JSON string vs numeric/boolean scalar matching cleanly in SQLite
    sqlite_expr: sa.ColumnElement[bool] = sa.cast(extracted, sa.String) == target
    if target.lower() in {"true", "false"}:
        bool_int = 1 if target.lower() == "true" else 0
        return sa.or_(sqlite_expr, extracted == bool_int)
    return sqlite_expr


def _build_json_has_key_condition(
    col: Any,
    fmeta: FieldMeta,
    raw_key: str,
    *,
    dialect_name: str,
) -> sa.ColumnElement[bool] | None:
    clean_key = raw_key.strip()
    if not _JSON_PATH_RE.fullmatch(clean_key):
        return None
    if dialect_name == "postgresql" and fmeta.is_jsonb and "." not in clean_key and hasattr(col, "has_key"):
        pg_expr: sa.ColumnElement[bool] = col.has_key(clean_key)
        return pg_expr
    if dialect_name == "postgresql":
        parts = clean_key.split(".")
        accessor = _pg_json_text_accessor(col, parts)
        pg_null_expr: sa.ColumnElement[bool] = accessor.is_not(None)
        return pg_null_expr
    if dialect_name in {"mysql", "mariadb"}:
        mysql_expr: sa.ColumnElement[bool] = sa.func.json_contains_path(col, "one", f"$.{clean_key}") == 1
        return mysql_expr
    # SQLite json_type returns NULL when path does not exist, non-NULL even if JSON value is null!
    sqlite_expr: sa.ColumnElement[bool] = sa.func.json_type(col, f"$.{clean_key}").is_not(None)
    return sqlite_expr


def _flatten_json_contains(
    prefix: str,
    mapping: Mapping[str, Any],
    out: list[tuple[str, Any]],
) -> bool:
    for k, v in mapping.items():
        if not isinstance(k, str) or not _JSON_PATH_RE.fullmatch(k):
            return False
        path = f"{prefix}.{k}" if prefix else k
        if not _JSON_PATH_RE.fullmatch(path):
            return False
        if isinstance(v, dict):
            if not v or not _flatten_json_contains(path, v, out):
                return False
        elif isinstance(v, list):
            return False
        else:
            out.append((path, v))
    return True


def _build_json_contains_condition(
    col: Any,
    fmeta: FieldMeta,
    raw_json: str,
    *,
    dialect_name: str,
) -> sa.ColumnElement[bool] | None:
    try:
        parsed = json.loads(raw_json)
    except Exception:
        return None
    if not check_json_depth(parsed, max_depth=4):
        return None
    if dialect_name == "postgresql" and fmeta.is_jsonb and hasattr(col, "contains"):
        pg_expr: sa.ColumnElement[bool] = col.contains(parsed)
        return pg_expr
    if isinstance(parsed, dict) and parsed:
        flat_pairs: list[tuple[str, Any]] = []
        if not _flatten_json_contains("", parsed, flat_pairs):
            return None
        preds: list[sa.ColumnElement[bool]] = []
        for path, v in flat_pairs:
            if v is None:
                if dialect_name == "postgresql":
                    preds.append(
                        sa.and_(
                            _build_json_has_key_condition(col, fmeta, path, dialect_name=dialect_name)
                            or sa.true(),
                            _pg_json_text_accessor(col, path.split(".")).is_(None),
                        )
                    )
                else:
                    preds.append(sa.func.json_type(col, f"$.{path}") == "null")
                continue
            val_str = "true" if v is True else ("false" if v is False else str(v))
            sub = _build_json_path_condition(col, fmeta, f"{path}={val_str}", dialect_name=dialect_name)
            if sub is not None:
                preds.append(sub)
        if preds:
            return sa.and_(*preds) if len(preds) > 1 else preds[0]
    return None


def build_filter_condition(
    meta: ModelMeta,
    field_name: str,
    raw_value: Any,
    *,
    op: str = "eq",
    dialect_name: str = "",
) -> sa.ColumnElement[bool] | None:
    """Build a safe parameterized SQLAlchemy filter expression for a single field."""
    fmeta = meta.fields_by_name.get(field_name)
    if fmeta is None:
        return None
    col: Any = getattr(meta.model, field_name)

    if op == "null":
        if str(raw_value).lower() in {"1", "true", "null"}:
            return col.is_(None)  # type: ignore[no-any-return]
        if str(raw_value).lower() in {"0", "false", "notnull"}:
            return col.is_not(None)  # type: ignore[no-any-return]
        return None

    # JSON / JSONB operators
    if fmeta.field_type == "json":
        text_val = str(raw_value).strip()
        if not text_val:
            return None
        if op == "has_key":
            return _build_json_has_key_condition(col, fmeta, text_val, dialect_name=dialect_name)
        if op == "path":
            return _build_json_path_condition(col, fmeta, text_val, dialect_name=dialect_name)
        if op == "json_contains":
            return _build_json_contains_condition(col, fmeta, text_val, dialect_name=dialect_name)
        if op == "contains":
            escaped = f"%{escape_like(text_val)}%"
            return sa.cast(col, sa.String).ilike(escaped, escape="\\")
        return None

    # PostgreSQL ARRAY operators (compatible with both postgresql.ARRAY and generic sa.ARRAY)
    if fmeta.field_type == "array":
        raw_text = str(raw_value).strip()
        if not raw_text:
            return None
        if op in {"array_contains", "contains", "eq"}:
            item = _coerce_array_item(raw_text, fmeta.array_item_type)
            if item is None:
                return None
            if dialect_name == "postgresql":
                if hasattr(col, "contains"):
                    try:
                        pg_arr: sa.ColumnElement[bool] = col.contains([item])
                        return pg_arr
                    except NotImplementedError:
                        pass
                pg_any: sa.ColumnElement[bool] = sa.any_(col) == item
                return pg_any
            return sa.cast(col, sa.String).ilike(f"%{escape_like(str(item))}%", escape="\\")
        if op == "array_any":
            items = [
                coerced
                for part in raw_text.split(",")
                if part.strip()
                and (coerced := _coerce_array_item(part, fmeta.array_item_type)) is not None
            ]
            if not items:
                return None
            if dialect_name == "postgresql":
                if hasattr(col, "overlap"):
                    try:
                        pg_ov: sa.ColumnElement[bool] = col.overlap(items)
                        return pg_ov
                    except NotImplementedError:
                        pass
                return sa.or_(*(sa.any_(col) == it for it in items))
            return sa.or_(
                *(sa.cast(col, sa.String).ilike(f"%{escape_like(str(it))}%", escape="\\") for it in items)
            )
        return None

    if op == "preset" and fmeta.field_type in {"datetime", "date"}:
        now = datetime.now(timezone.utc)
        preset = str(raw_value).lower()
        start_dt: datetime | None = None
        if preset == "today":
            start_dt = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        elif preset == "7d":
            start_dt = now - timedelta(days=7)
        elif preset == "30d":
            start_dt = now - timedelta(days=30)
        elif preset == "month":
            start_dt = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        if start_dt is None:
            return None
        bound: datetime | date = start_dt.date() if fmeta.field_type == "date" else start_dt
        preset_expr: sa.ColumnElement[bool] = col >= bound
        return preset_expr

    if op in {"contains", "startswith"}:
        clean_term = str(raw_value).strip()
        if not clean_term:
            return None
        escaped = f"%{escape_like(clean_term)}%" if op == "contains" else f"{escape_like(clean_term)}%"
        target_col = col if fmeta.field_type in {"string", "text", "email", "url"} else sa.cast(col, sa.String)
        like_expr: sa.ColumnElement[bool] = target_col.ilike(escaped, escape="\\")
        return like_expr

    if op in {"gt", "gte", "lt", "lte"}:
        coerced = _coerce_filter_value(raw_value, fmeta)
        if coerced is None:
            return None
        if op == "lte" and fmeta.field_type == "datetime" and isinstance(raw_value, str) and len(raw_value) <= 10:
            coerced = coerced + timedelta(days=1) - timedelta(microseconds=1)
        if op == "gt":
            gt_expr: sa.ColumnElement[bool] = col > coerced
            return gt_expr
        if op == "gte":
            gte_expr: sa.ColumnElement[bool] = col >= coerced
            return gte_expr
        if op == "lt":
            lt_expr: sa.ColumnElement[bool] = col < coerced
            return lt_expr
        lte_expr: sa.ColumnElement[bool] = col <= coerced
        return lte_expr

    if op == "neq":
        coerced = _coerce_filter_value(raw_value, fmeta)
        if coerced is None:
            return None
        neq_expr: sa.ColumnElement[bool] = col != coerced
        return neq_expr

    # Comma-separated multi-select support for enum/string/integer equality
    if isinstance(raw_value, str) and "," in raw_value and fmeta.field_type in {"enum", "string", "integer"}:
        parts = [_coerce_filter_value(p.strip(), fmeta) for p in raw_value.split(",")]
        valid = [p for p in parts if p is not None]
        if not valid:
            return None
        in_expr: sa.ColumnElement[bool] = col.in_(valid)
        return in_expr

    coerced = _coerce_filter_value(raw_value, fmeta)
    if coerced is None:
        return None
    eq_expr: sa.ColumnElement[bool] = col == coerced
    return eq_expr


def build_search_clause(
    meta: ModelMeta,
    searchable_columns: Sequence[str],
    term: str,
) -> tuple[sa.ColumnElement[bool] | None, list[Any]]:
    """Build safe escaped LIKE search clause across scalar and dotted FK columns."""
    clean = term.strip()
    if not clean or not searchable_columns:
        return None, []

    escaped = f"%{escape_like(clean)}%"
    predicates: list[sa.ColumnElement[bool]] = []
    joins: list[Any] = []
    seen_joins: set[str] = set()

    for col_spec in searchable_columns:
        if "." in col_spec:
            rel_name, target_col_name = col_spec.split(".", 1)
            rel_meta = meta.relationships_by_name.get(rel_name)
            if rel_meta is None or rel_meta.direction != "MANYTOONE":
                continue
            target_col = getattr(rel_meta.target_model, target_col_name, None)
            if target_col is None:
                continue
            if rel_name not in seen_joins:
                joins.append(getattr(meta.model, rel_name))
                seen_joins.add(rel_name)
            predicates.append(sa.cast(target_col, sa.String).ilike(escaped, escape="\\"))
            continue

        fmeta = meta.fields_by_name.get(col_spec)
        if fmeta is None or fmeta.is_sensitive:
            continue
        col = getattr(meta.model, col_spec)
        if fmeta.field_type in {"string", "text", "email", "url"}:
            predicates.append(col.ilike(escaped, escape="\\"))
        elif fmeta.field_type == "integer":
            with contextlib.suppress(ValueError):
                predicates.append(col == int(clean))
        elif fmeta.field_type == "uuid":
            try:
                predicates.append(col == uuid.UUID(clean))
            except ValueError:
                predicates.append(sa.cast(col, sa.String).ilike(escaped, escape="\\"))
        elif fmeta.field_type == "enum":
            predicates.append(sa.cast(col, sa.String).ilike(escaped, escape="\\"))

    if not predicates:
        return None, []
    return sa.or_(*predicates), joins


def apply_list_load_options(
    stmt: sa.Select[Any],
    meta: ModelMeta,
    displayed_columns: Sequence[str],
    *,
    defer_unshown_heavy: bool = True,
) -> sa.Select[Any]:
    """Attach automatic joinedload/selectinload for displayed relations and defer heavy unshown blobs."""
    shown_set = set(displayed_columns)
    options: list[Any] = []
    loaded_rels: set[str] = set()

    for col_name in displayed_columns:
        rel_meta = meta.relationships_by_name.get(col_name)
        if rel_meta is None:
            rel_meta = meta.fk_column_to_rel.get(col_name)
        if rel_meta is None or rel_meta.name in loaded_rels:
            continue
        rel_attr = getattr(meta.model, rel_meta.name)
        if rel_meta.direction == "MANYTOONE":
            options.append(joinedload(rel_attr))
        else:
            options.append(selectinload(rel_attr))
        loaded_rels.add(rel_meta.name)

    if defer_unshown_heavy:
        pk_names = {pk.name for pk in meta.primary_keys}
        for heavy_col in meta.heavy_fields:
            if heavy_col not in shown_set and heavy_col not in pk_names:
                options.append(defer(getattr(meta.model, heavy_col)))

    if options:
        stmt = stmt.options(*options)
    return stmt


def soft_delete_predicate(
    meta: ModelMeta,
    soft_delete_column: str | None,
    *,
    trashed: bool = False,
) -> sa.ColumnElement[bool] | None:
    """Return active (non-deleted) or trashed predicate for a soft-delete column."""
    if not soft_delete_column:
        return None
    fmeta = meta.fields_by_name.get(soft_delete_column)
    if fmeta is None:
        return None
    col: Any = getattr(meta.model, soft_delete_column)
    if fmeta.field_type == "boolean":
        expr: sa.ColumnElement[bool] = col.is_(True) if trashed else sa.or_(col.is_(False), col.is_(None))
        return expr
    expr_dt: sa.ColumnElement[bool] = col.is_not(None) if trashed else col.is_(None)
    return expr_dt


def build_pg_reltuples_statement(table_name: str, *, schema: str | None = None) -> sa.TextClause:
    """Build parameterized O(1) PostgreSQL catalog row-estimate statement (schema-aware)."""
    return sa.text(
        "SELECT CAST(c.reltuples AS BIGINT) "
        "FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relname = :tbl AND n.nspname = COALESCE(:sch, current_schema()) "
        "LIMIT 1"
    ).bindparams(tbl=table_name, sch=schema)


def estimate_table_rows(session: Session, meta: ModelMeta) -> int | None:
    """Return O(1) estimated row count on PostgreSQL via pg_class.reltuples (None if unanalyzed)."""
    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""
    if dialect_name != "postgresql":
        return None
    try:
        with session.begin_nested():
            val = session.execute(
                build_pg_reltuples_statement(meta.table_name, schema=meta.schema)
            ).scalar()
        if val is None:
            return None
        est = int(val)
        # pg_class.reltuples == -1 means table has never been analyzed/vacuumed -> fallback to COUNT(*)
        return est if est >= 0 else None
    except Exception:
        return None


def compute_quick_tab_counts(
    session: Session,
    meta: ModelMeta,
    base_where: Sequence[sa.ColumnElement[bool]],
    quick_tabs: Sequence[QuickTab],
    joins: Sequence[Any] = (),
    *,
    dialect_name: str = "",
    soft_delete_column: str | None = None,
) -> tuple[dict[str, int], int]:
    """Compute badge counts for ALL QuickTabs (plus Trash count) in ONE SQL query."""
    if not quick_tabs and not soft_delete_column:
        return {}, 0

    active_sd = soft_delete_predicate(meta, soft_delete_column, trashed=False)
    trashed_sd = soft_delete_predicate(meta, soft_delete_column, trashed=True)
    known = frozenset(meta.fields_by_name.keys())

    agg_exprs: list[Any] = []
    for tab in quick_tabs:
        tab_conds: list[sa.ColumnElement[bool]] = []
        if active_sd is not None:
            tab_conds.append(active_sd)
        for raw_fname, fval in tab.filters.items():
            fname, fop = parse_filter_key(raw_fname, known)
            cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
            if cond is not None:
                tab_conds.append(cond)
        if tab_conds:
            combined = sa.and_(*tab_conds) if len(tab_conds) > 1 else tab_conds[0]
            agg_exprs.append(sa.func.count(sa.case((combined, 1))).label(tab.key))
        else:
            agg_exprs.append(sa.func.count().label(tab.key))

    if trashed_sd is not None:
        agg_exprs.append(sa.func.count(sa.case((trashed_sd, 1))).label("__trashed"))

    stmt = sa.select(*agg_exprs).select_from(meta.model)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    if base_where:
        stmt = stmt.where(*base_where)

    row = session.execute(stmt).first()
    if row is None:
        return {tab.key: 0 for tab in quick_tabs}, 0
    counts = {tab.key: int(row[idx] or 0) for idx, tab in enumerate(quick_tabs)}
    trashed_cnt = int(row[len(quick_tabs)] or 0) if trashed_sd is not None else 0
    return counts, trashed_cnt


def _build_keyset_predicate(
    meta: ModelMeta,
    *,
    sort_field: FieldMeta,
    pk_field: FieldMeta,
    sort_val: Any,
    pk_val: Any,
    effective_dir: str,
) -> sa.ColumnElement[bool]:
    sort_col: Any = getattr(meta.model, sort_field.name)
    pk_col: Any = getattr(meta.model, pk_field.name)
    if sort_field.name == pk_field.name:
        expr_single: sa.ColumnElement[bool] = (
            (pk_col < pk_val) if effective_dir == "desc" else (pk_col > pk_val)
        )
        return expr_single

    if sort_val is None:
        pk_cmp: sa.ColumnElement[bool] = (pk_col < pk_val) if effective_dir == "desc" else (pk_col > pk_val)
        if effective_dir == "desc":
            return sa.and_(sort_col.is_(None), pk_cmp)
        return sa.or_(sort_col.is_not(None), sa.and_(sort_col.is_(None), pk_cmp))

    if effective_dir == "desc":
        return sa.or_(
            sort_col < sort_val,
            sort_col.is_(None),
            sa.and_(sort_col == sort_val, pk_col < pk_val),
        )
    return sa.or_(
        sort_col > sort_val,
        sa.and_(sort_col == sort_val, pk_col > pk_val),
    )


def execute_list_query(
    session: Session,
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    displayed_columns: Sequence[str],
    searchable_columns: Sequence[str],
    filterable_columns: frozenset[str],
    sortable_columns: frozenset[str],
    quick_tabs: Sequence[QuickTab],
    active_tab_key: str | None,
    search_term: str,
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]],
    sort_by: str | None,
    sort_dir: str,
    default_sort: tuple[str, str] | None,
    page: int,
    page_size: int,
    max_page_size: int,
    pagination_mode: PaginationMode = "offset",
    count_mode: CountMode = "exact",
    after_cursor: str | None = None,
    before_cursor: str | None = None,
    cursor_secret: bytes = b"",
    soft_delete_column: str | None = None,
    trashed: bool = False,
) -> PageResult:
    """Execute an optimized, N+1-free, SQLi-safe paginated list query (Offset or Keyset Cursor)."""
    safe_page = max(1, page)
    safe_size = max(1, min(page_size, max_page_size))

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    base_conditions: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    joins: list[Any] = []

    search_clause, search_joins = build_search_clause(meta, searchable_columns, search_term)
    if search_clause is not None:
        base_conditions.append(search_clause)
        joins.extend(search_joins)

    # Single-pass conditional aggregation for ALL quick tabs + optional Trash count (1 SQL query!).
    tab_counts, trashed_count = compute_quick_tab_counts(
        session,
        meta,
        base_conditions,
        quick_tabs,
        joins=joins,
        dialect_name=dialect_name,
        soft_delete_column=soft_delete_column,
    )

    where_clauses: list[sa.ColumnElement[bool]] = list(base_conditions)
    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        where_clauses.append(sd_pred)

    known_fields = frozenset(meta.fields_by_name.keys())
    active_filters: dict[str, str] = {}
    applied_filter_pairs: list[tuple[str, str]] = []
    if active_tab_key and not trashed:
        for tab in quick_tabs:
            if tab.key == active_tab_key:
                for raw_fname, fval in tab.filters.items():
                    fname, fop = parse_filter_key(raw_fname, known_fields)
                    cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
                    if cond is not None:
                        where_clauses.append(cond)
                break

    for raw_key, raw_val in iter_filter_items(filter_params):
        if not raw_val:
            continue
        fname, op = parse_filter_key(raw_key, known_fields)
        if fname not in filterable_columns:
            continue
        cond = build_filter_condition(meta, fname, raw_val, op=op, dialect_name=dialect_name)
        if cond is not None:
            where_clauses.append(cond)
            active_filters[raw_key] = raw_val
            applied_filter_pairs.append((raw_key, raw_val))

    # Strictly allowlisted sorting (zero SQL injection surface).
    chosen_sort = sort_by if (sort_by and sort_by in sortable_columns) else None
    chosen_dir = "desc" if sort_dir.lower() == "desc" else "asc"
    if chosen_sort is None and default_sort is not None:
        cand_col, cand_dir = default_sort
        if cand_col in sortable_columns:
            chosen_sort = cand_col
            chosen_dir = "desc" if cand_dir.lower() == "desc" else "asc"
    if chosen_sort is None:
        chosen_sort = meta.primary_keys[0].name
        chosen_dir = "desc"

    sort_field = meta.fields_by_name[chosen_sort]
    pk_field = meta.primary_keys[0]
    sort_col: Any = getattr(meta.model, chosen_sort)
    pk_col: Any = getattr(meta.model, pk_field.name)

    use_cursor_mode = pagination_mode == "cursor" and len(meta.primary_keys) == 1

    # Resolve row count strategy (only skip COUNT when cursor mode is actually active)
    total = 0
    total_is_estimated = False
    total_known = True

    if use_cursor_mode and count_mode == "none":
        total_known = False
    elif trashed and not active_filters and soft_delete_column:
        total = trashed_count
    elif not trashed and not active_filters and active_tab_key and active_tab_key in tab_counts:
        total = tab_counts[active_tab_key]
    elif (
        not trashed
        and not active_filters
        and not active_tab_key
        and quick_tabs
        and not quick_tabs[0].filters
    ):
        total = tab_counts[quick_tabs[0].key]
    elif count_mode == "estimated" and not where_clauses:
        est = estimate_table_rows(session, meta)
        if est is not None:
            total = est
            total_is_estimated = True
        else:
            count_stmt = sa.select(sa.func.count()).select_from(meta.model)
            total = int(session.execute(count_stmt).scalar_one() or 0)
    else:
        count_stmt = sa.select(sa.func.count()).select_from(meta.model)
        for rel_attr in joins:
            count_stmt = count_stmt.outerjoin(rel_attr)
        if where_clauses:
            count_stmt = count_stmt.where(*where_clauses)
        total = int(session.execute(count_stmt).scalar_one() or 0)

    # Keyset Cursor Mode (zero OFFSET, signed opaque cursors, deterministic PG/SQLite NULL order)
    if use_cursor_mode:
        slice_digest = hashlib.sha256(
            json.dumps(
                [
                    meta.slug,
                    active_tab_key or "",
                    search_term.strip(),
                    sorted(applied_filter_pairs),
                    bool(trashed),
                ],
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:12]

        going_back = bool(before_cursor and not after_cursor)
        raw_token = before_cursor if going_back else after_cursor
        decoded = decode_cursor(raw_token, secret=cursor_secret) if raw_token else None

        cursor_where: list[sa.ColumnElement[bool]] = list(where_clauses)
        has_valid_cursor = False
        effective_dir = chosen_dir
        if (
            decoded is not None
            and decoded.get("m", meta.slug) == meta.slug
            and decoded.get("h", slice_digest) == slice_digest
            and decoded.get("s") == chosen_sort
            and decoded.get("d") == chosen_dir
            and "pk" in decoded
        ):
            pk_val = _coerce_filter_value(decoded.get("pk"), pk_field, allow_empty_string=True)
            raw_sv = decoded.get("val")
            sort_val = (
                None
                if raw_sv is None
                else _coerce_filter_value(raw_sv, sort_field, allow_empty_string=True)
            )
            if pk_val is not None and (raw_sv is None or sort_val is not None):
                effective_dir = ("asc" if chosen_dir == "desc" else "desc") if going_back else chosen_dir
                cursor_where.append(
                    _build_keyset_predicate(
                        meta,
                        sort_field=sort_field,
                        pk_field=pk_field,
                        sort_val=sort_val,
                        pk_val=pk_val,
                        effective_dir=effective_dir,
                    )
                )
                has_valid_cursor = True

        def _run_cursor_fetch(
            clauses: Sequence[sa.ColumnElement[bool]],
            direction: str,
        ) -> list[Any]:
            stmt = sa.select(meta.model)
            for rel_attr in joins:
                stmt = stmt.outerjoin(rel_attr)
            if clauses:
                stmt = stmt.where(*clauses)
            # Explicit NULL placement guarantees SQLite & PostgreSQL match _build_keyset_predicate
            order_clauses: list[Any] = [
                sort_col.desc().nulls_last()
                if direction == "desc"
                else sort_col.asc().nulls_first()
            ]
            if chosen_sort != pk_field.name:
                order_clauses.append(pk_col.desc() if direction == "desc" else pk_col.asc())
            stmt = stmt.order_by(*order_clauses)
            stmt = apply_list_load_options(stmt, meta, displayed_columns)
            stmt = stmt.limit(safe_size + 1)
            return list(session.scalars(stmt).unique().all())

        fetched = _run_cursor_fetch(cursor_where, effective_dir)
        has_more = len(fetched) > safe_size
        items = fetched[:safe_size]

        if going_back and has_valid_cursor:
            if not items:
                # Rows preceding cursor were deleted; fall back cleanly to page 1 so user is never stranded.
                fetched = _run_cursor_fetch(where_clauses, chosen_dir)
                has_more = len(fetched) > safe_size
                items = fetched[:safe_size]
                has_next = has_more
                has_prev = False
            else:
                items.reverse()
                has_prev = has_more
                has_next = True
        else:
            has_next = has_more
            has_prev = has_valid_cursor and bool(items)

        def _make_tok(obj: Any) -> str:
            return encode_cursor(
                {
                    "v": 2,
                    "m": meta.slug,
                    "h": slice_digest,
                    "s": chosen_sort,
                    "d": chosen_dir,
                    "val": _serialize_cursor_val(getattr(obj, chosen_sort, None)),
                    "pk": _serialize_cursor_val(getattr(obj, pk_field.name, None)),
                },
                secret=cursor_secret,
            )

        next_tok = _make_tok(items[-1]) if (items and has_next) else None
        prev_tok = _make_tok(items[0]) if (items and has_prev) else None
        pages = max(1, (total + safe_size - 1) // safe_size) if total_known else 1
        return PageResult(
            items=items,
            total=total,
            page=1,
            page_size=safe_size,
            pages=pages,
            tab_counts=tab_counts,
            active_filters=active_filters,
            pagination_mode="cursor",
            next_cursor=next_tok,
            prev_cursor=prev_tok,
            has_next=has_next,
            has_prev=has_prev,
            total_is_estimated=total_is_estimated,
            total_known=total_known,
            trashed_count=trashed_count,
        )

    # Classic Offset Pagination
    pages = max(1, (total + safe_size - 1) // safe_size)
    if safe_page > pages:
        safe_page = pages

    data_stmt = sa.select(meta.model)
    for rel_attr in joins:
        data_stmt = data_stmt.outerjoin(rel_attr)
    if where_clauses:
        data_stmt = data_stmt.where(*where_clauses)

    order_expr = sort_col.desc() if chosen_dir == "desc" else sort_col.asc()
    offset_orders: list[Any] = [order_expr]
    for pk_f in meta.primary_keys:
        if pk_f.name != chosen_sort:
            pcol = getattr(meta.model, pk_f.name)
            offset_orders.append(pcol.desc() if chosen_dir == "desc" else pcol.asc())
    data_stmt = data_stmt.order_by(*offset_orders)
    data_stmt = apply_list_load_options(data_stmt, meta, displayed_columns)
    data_stmt = data_stmt.limit(safe_size).offset((safe_page - 1) * safe_size)

    items = list(session.scalars(data_stmt).unique().all())
    return PageResult(
        items=items,
        total=total,
        page=safe_page,
        page_size=safe_size,
        pages=pages,
        tab_counts=tab_counts,
        active_filters=active_filters,
        pagination_mode="offset",
        has_next=safe_page < pages,
        has_prev=safe_page > 1,
        total_is_estimated=total_is_estimated,
        total_known=total_known,
        trashed_count=trashed_count,
    )


def compute_page_aggregates(
    items: Sequence[Any],
    column_aggregates: Mapping[str, str],
) -> dict[str, tuple[str, float]]:
    """Compute page-level numeric aggregates (sum, avg, min, max) without extra SQL queries."""
    if not items or not column_aggregates:
        return {}
    out: dict[str, tuple[str, float]] = {}
    for col, raw_op in column_aggregates.items():
        op = raw_op.strip().lower()
        if op not in {"sum", "avg", "min", "max"}:
            continue
        vals: list[float] = []
        for obj in items:
            raw = getattr(obj, col, None)
            if raw is None or isinstance(raw, bool):
                continue
            with contextlib.suppress(TypeError, ValueError):
                vals.append(float(raw))
        if not vals:
            continue
        if op == "sum":
            agg = sum(vals)
        elif op == "avg":
            agg = sum(vals) / len(vals)
        elif op == "min":
            agg = min(vals)
        else:
            agg = max(vals)
        out[col] = (op.upper(), agg)
    return out


def execute_kanban_query(
    session: Session,
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    kanban_column: str,
    card_fields: Sequence[str],
    searchable_columns: Sequence[str],
    filterable_columns: frozenset[str],
    search_term: str,
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]],
    limit: int = 120,
    soft_delete_column: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch bounded, eager-loaded records grouped by enum choices for Kanban Board view."""
    fmeta = meta.fields_by_name.get(kanban_column)
    if fmeta is None or not fmeta.choices:
        return []

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    where_clauses: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=False)
    if sd_pred is not None:
        where_clauses.append(sd_pred)

    joins: list[Any] = []
    search_clause, search_joins = build_search_clause(meta, searchable_columns, search_term)
    if search_clause is not None:
        where_clauses.append(search_clause)
        joins.extend(search_joins)

    known_fields = frozenset(meta.fields_by_name.keys())
    for raw_key, raw_val in iter_filter_items(filter_params):
        if not raw_val:
            continue
        fname, op = parse_filter_key(raw_key, known_fields)
        if fname not in filterable_columns:
            continue
        cond = build_filter_condition(meta, fname, raw_val, op=op, dialect_name=dialect_name)
        if cond is not None:
            where_clauses.append(cond)

    stmt = sa.select(meta.model)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    if where_clauses:
        stmt = stmt.where(*where_clauses)
    stmt = stmt.order_by(getattr(meta.model, meta.primary_keys[0].name).desc())
    stmt = apply_list_load_options(stmt, meta, card_fields)
    stmt = stmt.limit(max(1, min(limit, 250)))
    records = list(session.scalars(stmt).unique().all())

    buckets: dict[str, list[Any]] = {val: [] for val, _ in fmeta.choices}
    for obj in records:
        raw_state = getattr(obj, kanban_column, None)
        key = str(raw_state.value) if isinstance(raw_state, enum.Enum) else str(raw_state or "")
        if key in buckets:
            buckets[key].append(obj)

    return [
        {"key": val, "label": lbl, "records": buckets[val]}
        for val, lbl in fmeta.choices
    ]
