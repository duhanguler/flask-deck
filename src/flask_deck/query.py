from __future__ import annotations

import base64
import calendar
import contextlib
import enum
import hashlib
import hmac
import json
import re
import time
import uuid
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from datetime import time as dt_time
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

import sqlalchemy as sa
from flask import g, has_request_context
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, aliased, defer, joinedload, selectinload

from flask_deck.formatters import normalize_tone
from flask_deck.introspection import FieldMeta, ModelMeta, introspect_model
from flask_deck.security import check_json_depth, escape_like, is_sensitive_field

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
    ("__not_in", "not_in"),
    ("__preset", "preset"),
    ("__null", "null"),
    ("__path", "path"),
    ("__neq", "neq"),
    ("__gte", "gte"),
    ("__lte", "lte"),
    ("__fts", "fts"),
    ("__gt", "gt"),
    ("__lt", "lt"),
    ("__in", "in"),
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
    precomputed_facets: dict[str, dict[str, int]] = field(default_factory=dict)
    full_total: int | None = None
    page_window: tuple[int | None, ...] = ()


def compute_page_window(current: int, total_pages: int) -> tuple[int | None, ...]:
    """Build elided page numbers like ``(1, 2, None, 8, 9, 10, None, 19, 20)``."""
    if total_pages <= 1:
        return ()
    current = max(1, min(total_pages, current))
    if total_pages <= 9:
        return tuple(range(1, total_pages + 1))
    pages_set: set[int] = {1, 2, total_pages - 1, total_pages}
    for p in range(max(1, current - 2), min(total_pages, current + 2) + 1):
        pages_set.add(p)
    sorted_pages = sorted(pages_set)
    out: list[int | None] = []
    prev = 0
    for p in sorted_pages:
        if prev and p - prev > 1:
            out.append(None)
        out.append(p)
        prev = p
    return tuple(out)


def apply_base_stmt_extras(
    stmt: sa.Select[Any],
    base_stmt: sa.Select[Any],
    *,
    include_options: bool = False,
) -> sa.Select[Any]:
    """Preserve explicit ``.join()`` / ``.outerjoin()`` and ``.options()`` added in ``scope_query``."""
    setup_joins = getattr(base_stmt, "_setup_joins", ())
    for entry in setup_joins:
        if isinstance(entry, tuple) and len(entry) >= 4:
            target, onclause, _left, kw = entry[0], entry[1], entry[2], entry[3]
            isouter = bool(kw.get("isouter", False)) if isinstance(kw, Mapping) else False
            full = bool(kw.get("full", False)) if isinstance(kw, Mapping) else False
            stmt = stmt.join(target, onclause, isouter=isouter, full=full)
    if include_options:
        opts = getattr(base_stmt, "_with_options", ())
        if opts:
            stmt = stmt.options(*opts)
    return stmt


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
                    has_key = _build_json_has_key_condition(col, fmeta, path, dialect_name=dialect_name)
                    is_null = _pg_json_text_accessor(col, path.split(".")).is_(None)
                    preds.append(sa.and_(has_key, is_null) if has_key is not None else is_null)
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
    model_override: Any = None,
) -> sa.ColumnElement[bool] | None:
    """Build a safe parameterized SQLAlchemy filter expression for a single field."""
    fmeta = meta.fields_by_name.get(field_name)
    if fmeta is None:
        return None
    col: Any = getattr(model_override or meta.model, field_name)

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
        if preset == "no_date":
            return col.is_(None)  # type: ignore[no-any-return]
        if preset == "has_date":
            return col.is_not(None)  # type: ignore[no-any-return]
        start_dt: datetime | None = None
        if preset == "today":
            start_dt = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        elif preset == "7d":
            start_dt = now - timedelta(days=7)
        elif preset == "30d":
            start_dt = now - timedelta(days=30)
        elif preset == "month":
            start_dt = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        elif preset == "year":
            start_dt = datetime(now.year, 1, 1, tzinfo=timezone.utc)
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

    if op in {"in", "not_in"}:
        if isinstance(raw_value, (list, tuple, set)):
            raw_parts = [str(p).strip() for p in raw_value if str(p).strip()]
        else:
            raw_parts = [p.strip() for p in str(raw_value).split(",") if p.strip()]
        valid = [_coerce_filter_value(p, fmeta) for p in raw_parts]
        valid = [p for p in valid if p is not None]
        if not valid:
            return None
        if op == "not_in":
            not_in_expr: sa.ColumnElement[bool] = sa.or_(col.is_(None), col.notin_(valid))
            return not_in_expr
        in_op_expr: sa.ColumnElement[bool] = col.in_(valid)
        return in_op_expr

    if op == "fts":
        clean = str(raw_value or "").strip()
        if not clean:
            return None
        if dialect_name == "postgresql":
            fts_expr: sa.ColumnElement[bool] = sa.func.to_tsvector(
                "english", sa.cast(col, sa.Text)
            ).op("@@")(sa.func.plainto_tsquery("english", clean))
            return fts_expr
        tokens = [tok for tok in clean.split() if tok][:8]
        if not tokens:
            return None
        if len(tokens) == 1:
            return sa.cast(col, sa.String).ilike(f"%{escape_like(tokens[0])}%", escape="\\")
        return sa.and_(
            *(
                sa.cast(col, sa.String).ilike(f"%{escape_like(tok)}%", escape="\\")
                for tok in tokens
            )
        )

    if op == "neq":
        coerced = _coerce_filter_value(raw_value, fmeta)
        if coerced is None:
            return None
        neq_expr: sa.ColumnElement[bool] = col != coerced
        return neq_expr

    if op == "eq" and str(raw_value) == "__null__":
        return col.is_(None)  # type: ignore[no-any-return]

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


def build_dotted_filter_condition(
    meta: ModelMeta,
    dotted_field: str,
    raw_value: Any,
    *,
    op: str = "eq",
    dialect_name: str = "",
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    alias_cache: dict[str, Any] | None = None,
) -> tuple[sa.ColumnElement[bool] | None, Any | None]:
    """Build a safe filter condition across a MANYTOONE dotted relation path like ``org.tier``."""
    if "." not in dotted_field:
        return build_filter_condition(meta, dotted_field, raw_value, op=op, dialect_name=dialect_name), None
    rel_name, target_col_name = dotted_field.split(".", 1)
    rel_meta = meta.relationships_by_name.get(rel_name)
    if rel_meta is None or rel_meta.direction != "MANYTOONE":
        return None, None

    if auth is not None and views_by_model is not None:
        p_restricted = auth.hidden_fields_for(user, meta.slug) | auth.masked_fields_for(
            user, meta.slug
        )
        if rel_name in p_restricted:
            return None, None
        t_view = views_by_model.get(rel_meta.target_model)
        if t_view is not None:
            t_restricted = auth.hidden_fields_for(user, t_view.meta.slug) | auth.masked_fields_for(
                user, t_view.meta.slug
            )
            if target_col_name in t_restricted or target_col_name in t_view.meta.sensitive_fields:
                return None, None
            target_meta = t_view.meta
        else:
            target_meta = introspect_model(rel_meta.target_model)
    else:
        target_meta = introspect_model(rel_meta.target_model)

    target_fmeta = target_meta.fields_by_name.get(target_col_name)
    if (
        target_fmeta is None
        or target_fmeta.is_sensitive
        or is_sensitive_field(target_col_name)
    ):
        return None, None

    if alias_cache is not None:
        rel_alias = alias_cache.get(rel_name)
        if rel_alias is None:
            rel_alias = aliased(rel_meta.target_model, name=f"_dk_{rel_name}")
            alias_cache[rel_name] = rel_alias
    else:
        rel_alias = aliased(rel_meta.target_model, name=f"_dk_{rel_name}")

    cond = build_filter_condition(
        target_meta,
        target_col_name,
        raw_value,
        op=op,
        dialect_name=dialect_name,
        model_override=rel_alias,
    )
    if cond is None:
        return None, None
    return cond, getattr(meta.model, rel_name).of_type(rel_alias)


def parse_search_column_spec(col_spec: str) -> tuple[str, str]:
    """Parse optional Django-style search prefix (``^`` startswith, ``=`` exact, ``@`` fts)."""
    clean = col_spec.strip()
    if clean.startswith("^"):
        return clean[1:].strip(), "startswith"
    if clean.startswith("="):
        return clean[1:].strip(), "exact"
    if clean.startswith("@"):
        return clean[1:].strip(), "fts"
    return clean, "contains"


def tokenize_search_query(
    term: str,
    *,
    max_tokens: int = 8,
    max_len: int = 200,
) -> list[str]:
    """O(N) ReDoS-safe search tokenizer supporting whitespace words and ``"quoted phrases"``."""
    raw = (term or "").strip()[: max(1, max_len)]
    if not raw:
        return []
    tokens: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in raw:
        if ch == '"':
            if in_quotes:
                tok = "".join(buf).strip()
                if tok:
                    tokens.append(tok)
                    if len(tokens) >= max_tokens:
                        return tokens
                buf.clear()
                in_quotes = False
            else:
                if buf:
                    tok = "".join(buf).strip()
                    if tok:
                        tokens.append(tok)
                        if len(tokens) >= max_tokens:
                            return tokens
                    buf.clear()
                in_quotes = True
        elif ch.isspace() and not in_quotes:
            if buf:
                tok = "".join(buf).strip()
                if tok:
                    tokens.append(tok)
                    if len(tokens) >= max_tokens:
                        return tokens
                buf.clear()
        else:
            buf.append(ch)
    if buf and len(tokens) < max_tokens:
        tok = "".join(buf).strip()
        if tok:
            tokens.append(tok)
    return tokens


def _build_scalar_search_pred(
    model: type[Any],
    fmeta: FieldMeta,
    col_name: str,
    token: str,
    *,
    mode: str,
    dialect_name: str = "",
) -> sa.ColumnElement[bool] | None:
    if fmeta.is_sensitive:
        return None
    col: Any = getattr(model, col_name, None)
    if col is None:
        return None
    escaped = escape_like(token)

    if fmeta.field_type == "integer":
        try:
            int_val = int(token)
        except ValueError:
            return None
        eq_int: sa.ColumnElement[bool] = col == int_val
        return eq_int

    if fmeta.field_type == "boolean":
        low = token.strip().lower()
        if low in {"true", "1", "yes"}:
            return col.is_(True)  # type: ignore[no-any-return]
        if low in {"false", "0", "no"}:
            return col.is_(False)  # type: ignore[no-any-return]
        return None

    if fmeta.field_type == "uuid":
        try:
            eq_uuid: sa.ColumnElement[bool] = col == uuid.UUID(token)
            return eq_uuid
        except ValueError:
            if mode == "exact":
                return None
            pat = f"{escaped}%" if mode == "startswith" else f"%{escaped}%"
            uuid_like: sa.ColumnElement[bool] = sa.cast(col, sa.String).ilike(pat, escape="\\")
            if dialect_name == "sqlite" and "-" in token:
                esc_no_dash = escape_like(token.replace("-", ""))
                pat_nd = f"{esc_no_dash}%" if mode == "startswith" else f"%{esc_no_dash}%"
                return sa.or_(uuid_like, sa.cast(col, sa.String).ilike(pat_nd, escape="\\"))
            return uuid_like

    if fmeta.field_type == "enum":
        if fmeta.enum_class is not None:
            t_low = token.lower()
            matched_members: list[Any] = []
            for m in fmeta.enum_class:
                n_low, v_low = m.name.lower(), str(m.value).lower()
                if (
                    (mode == "exact" and t_low in (n_low, v_low))
                    or (mode == "startswith" and (n_low.startswith(t_low) or v_low.startswith(t_low)))
                    or (mode not in {"exact", "startswith"} and (t_low in n_low or t_low in v_low))
                ):
                    matched_members.append(m)
            if matched_members:
                enum_in: sa.ColumnElement[bool] = col.in_(matched_members)
                return enum_in
        if mode == "exact":
            enum_eq: sa.ColumnElement[bool] = sa.func.lower(sa.cast(col, sa.String)) == token.lower()
            return enum_eq
        pat = f"{escaped}%" if mode == "startswith" else f"%{escaped}%"
        enum_like: sa.ColumnElement[bool] = sa.cast(col, sa.String).ilike(pat, escape="\\")
        return enum_like

    if fmeta.field_type in {"string", "text", "email", "url"}:
        if mode == "exact":
            str_eq: sa.ColumnElement[bool] = sa.func.lower(col) == token.lower()
            return str_eq
        if mode == "startswith":
            sw_expr: sa.ColumnElement[bool] = col.ilike(f"{escaped}%", escape="\\")
            return sw_expr
        if mode == "fts" and dialect_name == "postgresql":
            fts_expr: sa.ColumnElement[bool] = sa.func.to_tsvector(
                "english", sa.cast(col, sa.Text)
            ).op("@@")(sa.func.plainto_tsquery("english", token))
            return fts_expr
        like_expr: sa.ColumnElement[bool] = col.ilike(f"%{escaped}%", escape="\\")
        return like_expr

    if mode == "exact":
        gen_eq: sa.ColumnElement[bool] = sa.func.lower(sa.cast(col, sa.String)) == token.lower()
        return gen_eq
    pat = f"{escaped}%" if mode == "startswith" else f"%{escaped}%"
    gen_like: sa.ColumnElement[bool] = sa.cast(col, sa.String).ilike(pat, escape="\\")
    return gen_like


def _build_rel_search_pred(
    meta: ModelMeta,
    parts: list[str],
    token: str,
    *,
    mode: str,
    dialect_name: str = "",
    max_hops: int = 2,
) -> sa.ColumnElement[bool] | None:
    """Build correlated SQL EXISTS search predicate across 1..max_hops MANYTOONE/TO-MANY relations."""
    if len(parts) < 2 or (len(parts) - 1) > max_hops:
        return None
    rel_name = parts[0]
    rel_meta = meta.relationships_by_name.get(rel_name)
    if rel_meta is None or rel_name in meta.sensitive_fields:
        return None
    rel_attr: Any = getattr(meta.model, rel_name, None)
    if rel_attr is None:
        return None
    target_meta = introspect_model(rel_meta.target_model)
    if len(parts) == 2:
        col_name = parts[1]
        target_fmeta = target_meta.fields_by_name.get(col_name)
        if target_fmeta is None or target_fmeta.is_sensitive or is_sensitive_field(col_name):
            return None
        inner = _build_scalar_search_pred(
            target_meta.model, target_fmeta, col_name, token, mode=mode, dialect_name=dialect_name
        )
    else:
        inner = _build_rel_search_pred(
            target_meta, parts[1:], token, mode=mode, dialect_name=dialect_name, max_hops=max_hops - 1
        )
    if inner is None:
        return None
    exists_expr: sa.ColumnElement[bool] = rel_attr.any(inner) if rel_meta.uselist else rel_attr.has(inner)
    return exists_expr


def build_search_clause(
    meta: ModelMeta,
    searchable_columns: Sequence[str],
    term: str,
    *,
    dialect_name: str = "",
    max_tokens: int = 8,
    max_len: int = 200,
) -> tuple[sa.ColumnElement[bool] | None, list[Any]]:
    """Build safe tokenized/quoted AND-across-tokens search clause with ``^``/``=``/``@`` prefixes and EXISTS joins."""
    tokens = tokenize_search_query(term, max_tokens=max_tokens, max_len=max_len)
    if not tokens or not searchable_columns:
        return None, []

    parsed_cols = [parse_search_column_spec(c) for c in searchable_columns]
    token_clauses: list[sa.ColumnElement[bool]] = []
    for token in tokens:
        preds: list[sa.ColumnElement[bool]] = []
        for col_path, mode in parsed_cols:
            if not col_path:
                continue
            if "." in col_path:
                parts = [p.strip() for p in col_path.split(".") if p.strip()]
                rel_pred = _build_rel_search_pred(
                    meta, parts, token, mode=mode, dialect_name=dialect_name, max_hops=2
                )
                if rel_pred is not None:
                    preds.append(rel_pred)
                continue
            fmeta = meta.fields_by_name.get(col_path)
            if fmeta is None or fmeta.is_sensitive:
                continue
            sc_pred = _build_scalar_search_pred(
                meta.model, fmeta, col_path, token, mode=mode, dialect_name=dialect_name
            )
            if sc_pred is not None:
                preds.append(sc_pred)
        if preds:
            token_clauses.append(sa.or_(*preds) if len(preds) > 1 else preds[0])
        else:
            # Token matched no eligible typed column (e.g. non-numeric token on integer-only search) -> empty result
            token_clauses.append(sa.false())

    if not token_clauses:
        return None, []
    combined: sa.ColumnElement[bool] = (
        sa.and_(*token_clauses) if len(token_clauses) > 1 else token_clauses[0]
    )
    return combined, []


def _is_eager_loadable_rel(model: type[Any], rel_name: str) -> bool:
    """Return False for lazy='dynamic' / WriteOnlyMapped relationships where eager loading raises."""
    mapper = sa.inspect(model)
    prop = mapper.relationships.get(rel_name)
    if prop is None:
        return False
    return str(getattr(prop, "lazy", "")) not in {"dynamic", "write_only"}


def apply_list_load_options(
    stmt: sa.Select[Any],
    meta: ModelMeta,
    displayed_columns: Sequence[str],
    *,
    defer_unshown_heavy: bool = True,
    extra_select_related: Sequence[str] = (),
) -> sa.Select[Any]:
    """Attach automatic joinedload/selectinload for displayed relations, extra chains, and defer heavy blobs."""
    shown_set = set(displayed_columns)
    options: list[Any] = []
    loaded_rels: set[str] = set()

    for col_name in displayed_columns:
        rel_meta = meta.relationships_by_name.get(col_name)
        if rel_meta is None:
            rel_meta = meta.fk_column_to_rel.get(col_name)
        if rel_meta is None or rel_meta.name in loaded_rels:
            continue
        if not _is_eager_loadable_rel(meta.model, rel_meta.name):
            continue
        rel_attr = getattr(meta.model, rel_meta.name)
        if rel_meta.direction == "MANYTOONE":
            options.append(joinedload(rel_attr))
        else:
            options.append(selectinload(rel_attr))
        loaded_rels.add(rel_meta.name)

    for rel_path in extra_select_related:
        parts = [p.strip() for p in rel_path.split(".") if p.strip()]
        if not parts or len(parts) > 3:
            continue
        cur_meta = meta
        chain_opt: Any = None
        valid = True
        for part in parts:
            rm = cur_meta.relationships_by_name.get(part)
            if rm is None or not _is_eager_loadable_rel(cur_meta.model, rm.name):
                valid = False
                break
            attr = getattr(cur_meta.model, rm.name)
            if chain_opt is None:
                chain_opt = joinedload(attr) if rm.direction == "MANYTOONE" else selectinload(attr)
            else:
                chain_opt = (
                    chain_opt.joinedload(attr)
                    if rm.direction == "MANYTOONE"
                    else chain_opt.selectinload(attr)
                )
            cur_meta = introspect_model(rm.target_model)
        if valid and chain_opt is not None:
            options.append(chain_opt)

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


def _compute_quick_tab_and_facet_counts(
    session: Session,
    meta: ModelMeta,
    base_where: Sequence[sa.ColumnElement[bool]],
    quick_tabs: Sequence[QuickTab],
    joins: Sequence[Any] = (),
    *,
    dialect_name: str = "",
    soft_delete_column: str | None = None,
    extra_facet_exprs: Sequence[tuple[str, str, sa.ColumnElement[bool]]] = (),
    base_stmt: sa.Select[Any] | None = None,
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
) -> tuple[dict[str, int], int, dict[str, dict[str, int]]]:
    """Compute QuickTab + Trash counts plus optional foldable shared facet counts in ONE SQL query."""
    if not quick_tabs and not soft_delete_column:
        return {}, 0, {}

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

    xf_offset = len(agg_exprs)
    for idx_f, (_, _, pred) in enumerate(extra_facet_exprs):
        eff_pred = sa.and_(active_sd, pred) if active_sd is not None else pred
        agg_exprs.append(sa.func.count(sa.case((eff_pred, 1))).label(f"_xf_{idx_f}"))

    stmt = sa.select(*agg_exprs).select_from(meta.model)
    if base_stmt is not None:
        stmt = apply_base_stmt_extras(stmt, base_stmt, include_options=False)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    if base_where:
        stmt = stmt.where(*base_where)
    if search_applier is not None:
        stmt = search_applier(stmt)

    row = session.execute(stmt).first()
    if row is None:
        return {tab.key: 0 for tab in quick_tabs}, 0, {}
    counts = {tab.key: int(row[idx] or 0) for idx, tab in enumerate(quick_tabs)}
    trashed_cnt = int(row[len(quick_tabs)] or 0) if trashed_sd is not None else 0
    facets_out: dict[str, dict[str, int]] = {}
    for idx_f, (gk, opt_val, _) in enumerate(extra_facet_exprs):
        facets_out.setdefault(gk, {})[opt_val] = int(row[xf_offset + idx_f] or 0)
    return counts, trashed_cnt, facets_out


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
    counts, trashed_cnt, _ = _compute_quick_tab_and_facet_counts(
        session,
        meta,
        base_where,
        quick_tabs,
        joins=joins,
        dialect_name=dialect_name,
        soft_delete_column=soft_delete_column,
    )
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


def parse_sort_specs(
    raw_sort: str | None,
    raw_dir: str | None = None,
    *,
    allowed_sortable: frozenset[str],
    max_levels: int = 3,
) -> list[tuple[str, str]]:
    """Parse single or comma-separated multi-column sort expressions (``col1:asc,col2:desc``)."""
    specs: list[tuple[str, str]] = []
    seen: set[str] = set()
    clean_sort = (raw_sort or "").strip()
    if clean_sort:
        fallback_dir = "asc" if (raw_dir or "desc").strip().lower() == "asc" else "desc"
        for token in clean_sort.split(","):
            part = token.strip()
            if not part:
                continue
            if ":" in part:
                col_name, d_raw = part.split(":", 1)
                col_name = col_name.strip()
                dir_val = "asc" if d_raw.strip().lower() == "asc" else "desc"
            else:
                col_name = part
                dir_val = fallback_dir
            if col_name in allowed_sortable and col_name not in seen:
                specs.append((col_name, dir_val))
                seen.add(col_name)
                if len(specs) >= max_levels:
                    break
    return specs


def _resolve_sort_column(
    meta: ModelMeta,
    col_name: str,
    *,
    display_fields: Mapping[str, Any] | None = None,
    joins: list[Any],
    seen_joins: set[Any],
    alias_cache: dict[str, Any] | None = None,
) -> Any | None:
    """Resolve scalar, dotted FK, or @display.ordering SQLAlchemy order expression safely."""
    d_spec = display_fields.get(col_name) if display_fields is not None else None
    target_spec: Any = d_spec.ordering if (d_spec is not None and d_spec.ordering is not None) else col_name
    if callable(target_spec):
        try:
            return target_spec(meta.model)
        except Exception:
            return None
    if isinstance(target_spec, str):
        if "." in target_spec:
            rel_name, target_col = target_spec.split(".", 1)
            rel_meta = meta.relationships_by_name.get(rel_name)
            if rel_meta is None or rel_meta.direction != "MANYTOONE":
                return None
            if not hasattr(rel_meta.target_model, target_col):
                return None
            if alias_cache is not None:
                rel_alias = alias_cache.get(rel_name)
                if rel_alias is None:
                    rel_alias = aliased(rel_meta.target_model, name=f"_dk_{rel_name}")
                    alias_cache[rel_name] = rel_alias
            else:
                rel_alias = aliased(rel_meta.target_model, name=f"_dk_{rel_name}")
            col_expr = getattr(rel_alias, target_col, None)
            if col_expr is None:
                return None
            jkey = f"rel:{rel_name}"
            if jkey not in seen_joins:
                joins.append(getattr(meta.model, rel_name).of_type(rel_alias))
                seen_joins.add(jkey)
            return col_expr
        if target_spec in meta.fields_by_name:
            return getattr(meta.model, target_spec)
    return None


def _apply_filter_params(
    meta: ModelMeta,
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]],
    filterable_columns: frozenset[str],
    *,
    dialect_name: str,
    where_clauses: list[sa.ColumnElement[bool]],
    joins: list[Any],
    seen_joins: set[Any],
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    where_by_field: dict[str, list[sa.ColumnElement[bool]]] | None = None,
    alias_cache: dict[str, Any] | None = None,
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    known_fields = frozenset(meta.fields_by_name.keys()) | set(filterable_columns)
    active_filters: dict[str, str] = {}
    applied_filter_pairs: list[tuple[str, str]] = []
    local_aliases = alias_cache if alias_cache is not None else {}
    for raw_key, raw_val in iter_filter_items(filter_params):
        if not raw_val:
            continue
        fname, op = parse_filter_key(raw_key, known_fields)
        if fname not in filterable_columns:
            continue
        if "." in fname:
            rel_name = fname.split(".", 1)[0]
            cond, join_attr = build_dotted_filter_condition(
                meta,
                fname,
                raw_val,
                op=op,
                dialect_name=dialect_name,
                views_by_model=views_by_model,
                user=user,
                auth=auth,
                alias_cache=local_aliases,
            )
            if cond is not None and join_attr is not None:
                where_clauses.append(cond)
                if where_by_field is not None:
                    where_by_field.setdefault(fname, []).append(cond)
                jkey = f"rel:{rel_name}"
                if jkey not in seen_joins:
                    joins.append(join_attr)
                    seen_joins.add(jkey)
                active_filters[raw_key] = raw_val
                applied_filter_pairs.append((raw_key, raw_val))
            continue
        cond = build_filter_condition(meta, fname, raw_val, op=op, dialect_name=dialect_name)
        if cond is not None:
            where_clauses.append(cond)
            if where_by_field is not None:
                where_by_field.setdefault(fname, []).append(cond)
            active_filters[raw_key] = raw_val
            applied_filter_pairs.append((raw_key, raw_val))
    return active_filters, applied_filter_pairs


def prepare_scoped_clauses(
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    searchable_columns: Sequence[str] = (),
    filterable_columns: frozenset[str] = frozenset(),
    quick_tabs: Sequence[QuickTab] = (),
    active_tab_key: str | None = None,
    search_term: str = "",
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]] = (),
    soft_delete_column: str | None = None,
    trashed: bool = False,
    dialect_name: str = "",
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    max_search_tokens: int = 8,
    max_search_length: int = 200,
    use_default_search: bool = True,
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
) -> tuple[
    list[sa.ColumnElement[bool]],
    list[sa.ColumnElement[bool]],
    dict[str, list[sa.ColumnElement[bool]]],
    list[Any],
]:
    """Build deterministic ``(non_filter_where, all_where, filter_where_by_field, joins)``."""
    non_filter_where: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    joins: list[Any] = []
    seen_joins: set[Any] = set()

    if use_default_search and search_applier is None:
        search_clause, search_joins = build_search_clause(
            meta,
            searchable_columns,
            search_term,
            dialect_name=dialect_name,
            max_tokens=max_search_tokens,
            max_len=max_search_length,
        )
        if search_clause is not None:
            non_filter_where.append(search_clause)
            for j in search_joins:
                jkey = getattr(j, "key", id(j))
                if jkey not in seen_joins:
                    joins.append(j)
                    seen_joins.add(jkey)

    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        non_filter_where.append(sd_pred)
    if extra_where:
        non_filter_where.extend(extra_where)

    known_fields = frozenset(meta.fields_by_name.keys())
    if active_tab_key and not trashed:
        for tab in quick_tabs:
            if tab.key == active_tab_key:
                for raw_fname, fval in tab.filters.items():
                    fname, fop = parse_filter_key(raw_fname, known_fields)
                    cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
                    if cond is not None:
                        non_filter_where.append(cond)
                break

    all_where = list(non_filter_where)
    where_by_field: dict[str, list[sa.ColumnElement[bool]]] = {}
    _apply_filter_params(
        meta,
        filter_params,
        filterable_columns,
        dialect_name=dialect_name,
        where_clauses=all_where,
        joins=joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
        where_by_field=where_by_field,
    )
    return non_filter_where, all_where, where_by_field, joins


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
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    sort_specs: Sequence[tuple[str, str]] = (),
    display_fields: Mapping[str, Any] | None = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    custom_filter_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
    extra_facet_exprs: Sequence[tuple[str, str, sa.ColumnElement[bool]]] = (),
    extra_select_related: Sequence[str] = (),
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
    show_full_result_count: bool = True,
    max_search_tokens: int = 8,
    max_search_length: int = 200,
) -> PageResult:
    """Execute an optimized, N+1-free, SQLi-safe paginated list query (Offset or Keyset Cursor)."""
    safe_page = max(1, page)
    safe_size = max(1, min(page_size, max_page_size))

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    scope_where: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    base_conditions: list[sa.ColumnElement[bool]] = list(scope_where)
    joins: list[Any] = []
    seen_joins: set[Any] = set()

    has_search = bool((search_term or "").strip())
    if search_applier is None:
        search_clause, search_joins = build_search_clause(
            meta,
            searchable_columns,
            search_term,
            dialect_name=dialect_name,
            max_tokens=max_search_tokens,
            max_len=max_search_length,
        )
        if search_clause is not None:
            base_conditions.append(search_clause)
            for j in search_joins:
                jkey = getattr(j, "key", id(j))
                if jkey not in seen_joins:
                    joins.append(j)
                    seen_joins.add(jkey)

    # Skip expensive quick-tab full-table scan when count_mode == "none".
    if count_mode == "none":
        tab_counts: dict[str, int] = {}
        trashed_count = 0
        precomputed_facets: dict[str, dict[str, int]] = {}
    else:
        # Single-pass conditional aggregation for ALL quick tabs + optional Trash + folded facets (1 SQL query!).
        tab_counts, trashed_count, precomputed_facets = _compute_quick_tab_and_facet_counts(
            session,
            meta,
            base_conditions,
            quick_tabs,
            joins=joins,
            dialect_name=dialect_name,
            soft_delete_column=soft_delete_column,
            extra_facet_exprs=extra_facet_exprs,
            base_stmt=base_stmt,
            search_applier=search_applier,
        )

    where_clauses: list[sa.ColumnElement[bool]] = list(base_conditions)
    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        where_clauses.append(sd_pred)
    if extra_where:
        where_clauses.extend(extra_where)

    known_fields = frozenset(meta.fields_by_name.keys())
    if active_tab_key and not trashed:
        for tab in quick_tabs:
            if tab.key == active_tab_key:
                for raw_fname, fval in tab.filters.items():
                    fname, fop = parse_filter_key(raw_fname, known_fields)
                    cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
                    if cond is not None:
                        where_clauses.append(cond)
                break

    alias_cache: dict[str, Any] = {}
    active_filters, applied_filter_pairs = _apply_filter_params(
        meta,
        filter_params,
        filterable_columns,
        dialect_name=dialect_name,
        where_clauses=where_clauses,
        joins=joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
        alias_cache=alias_cache,
    )

    # Strictly allowlisted sorting supporting up to 3 multi-sort levels, dotted FKs & @display.ordering.
    effective_sorts: list[tuple[str, str]] = [
        (c, "asc" if d.lower() == "asc" else "desc")
        for c, d in sort_specs
        if c in sortable_columns
    ][:3]
    if not effective_sorts and sort_by and sort_by in sortable_columns:
        effective_sorts = [(sort_by, "desc" if sort_dir.lower() == "desc" else "asc")]
    if not effective_sorts and default_sort is not None:
        cand_col, cand_dir = default_sort
        if cand_col in sortable_columns:
            effective_sorts = [(cand_col, "desc" if cand_dir.lower() == "desc" else "asc")]
    if not effective_sorts:
        effective_sorts = [(meta.primary_keys[0].name, "desc")]

    resolved_sorts: list[tuple[str, str, Any]] = []
    for s_col_name, s_dir in effective_sorts:
        s_expr = _resolve_sort_column(
            meta,
            s_col_name,
            display_fields=display_fields,
            joins=joins,
            seen_joins=seen_joins,
            alias_cache=alias_cache,
        )
        if s_expr is not None:
            resolved_sorts.append((s_col_name, s_dir, s_expr))
    if not resolved_sorts:
        pk0 = meta.primary_keys[0].name
        resolved_sorts = [(pk0, "desc", getattr(meta.model, pk0))]

    chosen_sort, chosen_dir, sort_col = resolved_sorts[0]
    pk_field = meta.primary_keys[0]
    pk_col: Any = getattr(meta.model, pk_field.name)

    use_cursor_mode = (
        pagination_mode == "cursor"
        and len(meta.primary_keys) == 1
        and len(resolved_sorts) == 1
        and chosen_sort in meta.fields_by_name
        and not custom_filter_appliers
        and search_applier is None
    )

    # Resolve row count strategy (only skip COUNT when cursor mode is actually active)
    total = 0
    total_is_estimated = False
    total_known = True

    has_active_tab_filter = bool(
        active_tab_key
        and not trashed
        and any(t.key == active_tab_key and t.filters for t in quick_tabs)
    )
    has_unscoped_only = (
        not base_conditions
        and not getattr(base_stmt, "_setup_joins", ())
        and not soft_delete_column
        and not active_filters
        and not has_active_tab_filter
        and not extra_where
        and not custom_filter_appliers
        and search_applier is None
        and not trashed
    )

    if use_cursor_mode and count_mode == "none":
        total_known = False
    elif count_mode == "estimated" and has_unscoped_only:
        est = estimate_table_rows(session, meta)
        if est is not None:
            total = est
            total_is_estimated = True
        elif trashed and not active_filters and not extra_where and not custom_filter_appliers and soft_delete_column:
            total = trashed_count
        elif not trashed and not active_filters and not extra_where and not custom_filter_appliers and active_tab_key and active_tab_key in tab_counts:
            total = tab_counts[active_tab_key]
        elif (
            not trashed
            and not active_filters
            and not extra_where
            and not custom_filter_appliers
            and not active_tab_key
            and quick_tabs
            and not quick_tabs[0].filters
            and quick_tabs[0].key in tab_counts
        ):
            total = tab_counts[quick_tabs[0].key]
        else:
            count_stmt = apply_base_stmt_extras(
                sa.select(sa.func.count()).select_from(meta.model), base_stmt
            )
            if where_clauses:
                count_stmt = count_stmt.where(*where_clauses)
            if search_applier is not None:
                count_stmt = search_applier(count_stmt)
            for applier in custom_filter_appliers:
                count_stmt = applier(count_stmt)
            total = int(session.execute(count_stmt).scalar_one() or 0)
    elif trashed and not active_filters and not extra_where and not custom_filter_appliers and soft_delete_column and count_mode != "none":
        total = trashed_count
    elif not trashed and not active_filters and not extra_where and not custom_filter_appliers and active_tab_key and active_tab_key in tab_counts:
        total = tab_counts[active_tab_key]
    elif (
        not trashed
        and not active_filters
        and not extra_where
        and not custom_filter_appliers
        and not active_tab_key
        and quick_tabs
        and not quick_tabs[0].filters
        and quick_tabs[0].key in tab_counts
    ):
        total = tab_counts[quick_tabs[0].key]
    else:
        count_stmt = apply_base_stmt_extras(
            sa.select(sa.func.count()).select_from(meta.model), base_stmt
        )
        for rel_attr in joins:
            count_stmt = count_stmt.outerjoin(rel_attr)
        if where_clauses:
            count_stmt = count_stmt.where(*where_clauses)
        if search_applier is not None:
            count_stmt = search_applier(count_stmt)
        for applier in custom_filter_appliers:
            count_stmt = applier(count_stmt)
        total = int(session.execute(count_stmt).scalar_one() or 0)

    # Optional unfiltered total ("X matching of Y total") — zero extra SQL when QuickTab("all") already computed it!
    is_narrowed = bool(
        has_search or active_filters or has_active_tab_filter or extra_where or custom_filter_appliers
    )
    full_total: int | None = None
    if show_full_result_count and is_narrowed and total_known and count_mode != "none":
        if not has_search and not trashed:
            for tab in quick_tabs:
                if not tab.filters and tab.key in tab_counts:
                    full_total = tab_counts[tab.key]
                    break
        if (
            full_total is None
            and count_mode == "estimated"
            and not scope_where
            and sd_pred is None
            and not getattr(base_stmt, "_setup_joins", ())
        ):
            est_full = estimate_table_rows(session, meta)
            if est_full is not None:
                full_total = est_full
        if full_total is None:
            ft_stmt = apply_base_stmt_extras(
                sa.select(sa.func.count()).select_from(meta.model), base_stmt
            )
            ft_where = list(scope_where)
            if sd_pred is not None:
                ft_where.append(sd_pred)
            if ft_where:
                ft_stmt = ft_stmt.where(*ft_where)
            full_total = int(session.execute(ft_stmt).scalar_one() or 0)

    # Keyset Cursor Mode (zero OFFSET, signed opaque cursors, deterministic PG/SQLite NULL order)
    if use_cursor_mode:
        sort_field = meta.fields_by_name[chosen_sort]
        slice_digest = hashlib.sha256(
            json.dumps(
                [
                    meta.slug,
                    active_tab_key or "",
                    search_term.strip(),
                    sorted(applied_filter_pairs),
                    bool(trashed),
                    [str(ew) for ew in extra_where],
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
            stmt = apply_base_stmt_extras(sa.select(meta.model), base_stmt, include_options=True)
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
            stmt = apply_list_load_options(
                stmt, meta, displayed_columns, extra_select_related=extra_select_related
            )
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
            precomputed_facets=precomputed_facets,
            full_total=full_total,
        )

    # Classic Offset Pagination
    pages = max(1, (total + safe_size - 1) // safe_size)
    if safe_page > pages:
        safe_page = pages

    data_stmt = apply_base_stmt_extras(sa.select(meta.model), base_stmt, include_options=True)
    for rel_attr in joins:
        data_stmt = data_stmt.outerjoin(rel_attr)
    if where_clauses:
        data_stmt = data_stmt.where(*where_clauses)
    if search_applier is not None:
        data_stmt = search_applier(data_stmt)
    for applier in custom_filter_appliers:
        data_stmt = applier(data_stmt)

    offset_orders: list[Any] = [
        (s_expr.desc() if s_dir == "desc" else s_expr.asc())
        for _, s_dir, s_expr in resolved_sorts
    ]
    used_order_cols = {s_name for s_name, _, _ in resolved_sorts}
    for pk_f in meta.primary_keys:
        if pk_f.name not in used_order_cols:
            pcol = getattr(meta.model, pk_f.name)
            offset_orders.append(pcol.desc() if chosen_dir == "desc" else pcol.asc())
    data_stmt = data_stmt.order_by(*offset_orders)
    data_stmt = apply_list_load_options(
        data_stmt, meta, displayed_columns, extra_select_related=extra_select_related
    )
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
        precomputed_facets=precomputed_facets,
        full_total=full_total,
        page_window=compute_page_window(safe_page, pages),
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


def compute_all_aggregates(
    session: Session,
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    column_aggregates: Mapping[str, str],
    searchable_columns: Sequence[str] = (),
    filterable_columns: frozenset[str] = frozenset(),
    quick_tabs: Sequence[QuickTab] = (),
    active_tab_key: str | None = None,
    search_term: str = "",
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]] = (),
    soft_delete_column: str | None = None,
    trashed: bool = False,
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    extra_where: Sequence[sa.ColumnElement[bool]] = (),
    custom_filter_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
    max_search_tokens: int = 8,
    max_search_length: int = 200,
) -> dict[str, tuple[str, float]]:
    """Compute SQL aggregates (sum, avg, min, max) over the entire filtered dataset in 1 query."""
    if not column_aggregates:
        return {}
    agg_exprs: list[Any] = []
    agg_keys: list[tuple[str, str]] = []
    for col, raw_op in column_aggregates.items():
        op = raw_op.strip().lower()
        if op not in {"sum", "avg", "min", "max"} or col not in meta.fields_by_name:
            continue
        col_attr: Any = getattr(meta.model, col)
        agg_col_expr: Any
        if op == "sum":
            agg_col_expr = sa.func.sum(col_attr)
        elif op == "avg":
            agg_col_expr = sa.func.avg(col_attr)
        elif op == "min":
            agg_col_expr = sa.func.min(col_attr)
        else:
            agg_col_expr = sa.func.max(col_attr)
        agg_exprs.append(agg_col_expr.label(f"agg_{col}_{op}"))
        agg_keys.append((col, op.upper()))
    if not agg_exprs:
        return {}

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""
    where_clauses: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    joins: list[Any] = []
    seen_joins: set[Any] = set()

    if search_applier is None:
        search_clause, search_joins = build_search_clause(
            meta,
            searchable_columns,
            search_term,
            dialect_name=dialect_name,
            max_tokens=max_search_tokens,
            max_len=max_search_length,
        )
        if search_clause is not None:
            where_clauses.append(search_clause)
            for j in search_joins:
                jkey = getattr(j, "key", id(j))
                if jkey not in seen_joins:
                    joins.append(j)
                    seen_joins.add(jkey)

    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=trashed)
    if sd_pred is not None:
        where_clauses.append(sd_pred)
    if extra_where:
        where_clauses.extend(extra_where)

    known_fields = frozenset(meta.fields_by_name.keys())
    if active_tab_key and not trashed:
        for tab in quick_tabs:
            if tab.key == active_tab_key:
                for raw_fname, fval in tab.filters.items():
                    fname, fop = parse_filter_key(raw_fname, known_fields)
                    cond = build_filter_condition(meta, fname, fval, op=fop, dialect_name=dialect_name)
                    if cond is not None:
                        where_clauses.append(cond)
                break

    _apply_filter_params(
        meta,
        filter_params,
        filterable_columns,
        dialect_name=dialect_name,
        where_clauses=where_clauses,
        joins=joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
    )

    stmt = apply_base_stmt_extras(sa.select(*agg_exprs).select_from(meta.model), base_stmt)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    if where_clauses:
        stmt = stmt.where(*where_clauses)
    if search_applier is not None:
        stmt = search_applier(stmt)
    for applier in custom_filter_appliers:
        stmt = applier(stmt)
    row = session.execute(stmt).first()
    if row is None:
        return {}
    out: dict[str, tuple[str, float]] = {}
    for idx, (col, op_upper) in enumerate(agg_keys):
        val = row[idx]
        if val is None:
            continue
        with contextlib.suppress(TypeError, ValueError):
            out[col] = (op_upper, float(val))
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
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
    max_search_tokens: int = 8,
    max_search_length: int = 200,
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
    seen_joins: set[Any] = set()
    if search_applier is None:
        search_clause, search_joins = build_search_clause(
            meta,
            searchable_columns,
            search_term,
            dialect_name=dialect_name,
            max_tokens=max_search_tokens,
            max_len=max_search_length,
        )
        if search_clause is not None:
            where_clauses.append(search_clause)
            for j in search_joins:
                jkey = getattr(j, "key", id(j))
                if jkey not in seen_joins:
                    joins.append(j)
                    seen_joins.add(jkey)

    _apply_filter_params(
        meta,
        filter_params,
        filterable_columns,
        dialect_name=dialect_name,
        where_clauses=where_clauses,
        joins=joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
    )

    stmt = apply_base_stmt_extras(sa.select(meta.model), base_stmt, include_options=True)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    if where_clauses:
        stmt = stmt.where(*where_clauses)
    if search_applier is not None:
        stmt = search_applier(stmt)
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


def execute_calendar_query(
    session: Session,
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    date_field: str,
    month_str: str = "",
    searchable_columns: Sequence[str] = (),
    filterable_columns: frozenset[str] = frozenset(),
    search_term: str = "",
    filter_params: Mapping[str, str] | Sequence[tuple[str, str]] = (),
    soft_delete_column: str | None = None,
    limit: int = 300,
    views_by_model: Mapping[type[Any], Any] | None = None,
    user: Any = None,
    auth: Any = None,
    search_applier: Callable[[sa.Select[Any]], sa.Select[Any]] | None = None,
    max_search_tokens: int = 8,
    max_search_length: int = 200,
) -> dict[str, Any]:
    """Fetch bounded records for a YYYY-MM month and bucket them into 7-day calendar weeks."""
    today = datetime.now(timezone.utc).date()
    year, month = today.year, today.month
    if month_str and re.fullmatch(r"\d{4}-\d{2}", month_str.strip()):
        y_s, m_s = month_str.strip().split("-", 1)
        y_val, m_val = int(y_s), int(m_s)
        if 1 <= m_val <= 12 and 1900 <= y_val <= 2200:
            year, month = y_val, m_val

    prev_year, prev_m = (year - 1, 12) if month == 1 else (year, month - 1)
    next_year, next_m = (year + 1, 1) if month == 12 else (year, month + 1)
    month_start = date(year, month, 1)
    month_end = date(next_year, next_m, 1)

    fmeta = meta.fields_by_name.get(date_field)
    if fmeta is None or fmeta.field_type not in {"date", "datetime"}:
        return {
            "year": year,
            "month": month,
            "month_key": f"{year:04d}-{month:02d}",
            "month_label": month_start.strftime("%B %Y"),
            "prev_month": f"{prev_year:04d}-{prev_m:02d}",
            "next_month": f"{next_year:04d}-{next_m:02d}",
            "weeks": [],
        }

    bind = session.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""
    where_clauses: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=False)
    if sd_pred is not None:
        where_clauses.append(sd_pred)

    joins: list[Any] = []
    seen_joins: set[Any] = set()
    if search_applier is None:
        search_clause, search_joins = build_search_clause(
            meta,
            searchable_columns,
            search_term,
            dialect_name=dialect_name,
            max_tokens=max_search_tokens,
            max_len=max_search_length,
        )
        if search_clause is not None:
            where_clauses.append(search_clause)
            for j in search_joins:
                jkey = getattr(j, "key", id(j))
                if jkey not in seen_joins:
                    joins.append(j)
                    seen_joins.add(jkey)

    _apply_filter_params(
        meta,
        filter_params,
        filterable_columns,
        dialect_name=dialect_name,
        where_clauses=where_clauses,
        joins=joins,
        seen_joins=seen_joins,
        views_by_model=views_by_model,
        user=user,
        auth=auth,
    )

    date_col: Any = getattr(meta.model, date_field)
    if fmeta.field_type == "datetime":
        start_bound: Any = datetime(year, month, 1, 0, 0, 0)
        end_bound: Any = datetime(next_year, next_m, 1, 0, 0, 0)
    else:
        start_bound = month_start
        end_bound = month_end

    stmt = apply_base_stmt_extras(sa.select(meta.model), base_stmt, include_options=True)
    for rel_attr in joins:
        stmt = stmt.outerjoin(rel_attr)
    where_clauses.extend([date_col >= start_bound, date_col < end_bound])
    stmt = stmt.where(*where_clauses)
    if search_applier is not None:
        stmt = search_applier(stmt)
    stmt = stmt.order_by(date_col.asc()).limit(max(1, min(limit, 500)))
    records = list(session.scalars(stmt).unique().all())

    by_iso: dict[str, list[Any]] = {}
    for obj in records:
        raw_val = getattr(obj, date_field, None)
        if isinstance(raw_val, datetime):
            iso = raw_val.date().isoformat()
        elif isinstance(raw_val, date):
            iso = raw_val.isoformat()
        else:
            continue
        by_iso.setdefault(iso, []).append(obj)

    cal = calendar.Calendar(firstweekday=0)
    weeks = [
        [
            {
                "iso": d.isoformat(),
                "day": d.day,
                "in_month": d.month == month,
                "is_today": d == today,
                "items": by_iso.get(d.isoformat(), []),
            }
            for d in week
        ]
        for week in cal.monthdatescalendar(year, month)
    ]
    return {
        "year": year,
        "month": month,
        "month_key": f"{year:04d}-{month:02d}",
        "month_label": month_start.strftime("%B %Y"),
        "prev_month": f"{prev_year:04d}-{prev_m:02d}",
        "next_month": f"{next_year:04d}-{next_m:02d}",
        "weeks": weeks,
    }


def execute_tree_query(
    session: Session,
    meta: ModelMeta,
    *,
    base_stmt: sa.Select[Any],
    parent_field: str,
    displayed_columns: Sequence[str] = (),
    soft_delete_column: str | None = None,
    limit: int = 300,
) -> list[dict[str, Any]]:
    """Build a bounded, cycle-safe depth-first tree node list for self-referential hierarchies."""
    if len(meta.primary_keys) != 1 or parent_field not in meta.fields_by_name:
        return []
    pk_name = meta.primary_keys[0].name
    pk_col: Any = getattr(meta.model, pk_name)

    where_clauses: list[sa.ColumnElement[bool]] = list(base_stmt._where_criteria)
    sd_pred = soft_delete_predicate(meta, soft_delete_column, trashed=False)
    if sd_pred is not None:
        where_clauses.append(sd_pred)

    stmt = apply_base_stmt_extras(sa.select(meta.model), base_stmt, include_options=True)
    if where_clauses:
        stmt = stmt.where(*where_clauses)
    stmt = stmt.order_by(pk_col.asc())
    stmt = apply_list_load_options(stmt, meta, displayed_columns)
    stmt = stmt.limit(max(1, min(limit, 300)))
    records = list(session.scalars(stmt).unique().all())

    by_pk: dict[Any, Any] = {getattr(obj, pk_name): obj for obj in records}
    children_map: dict[Any, list[Any]] = {}
    roots: list[Any] = []
    for obj in records:
        pk_val = getattr(obj, pk_name)
        parent_val = getattr(obj, parent_field, None)
        if parent_val is None or parent_val == pk_val or parent_val not in by_pk:
            roots.append(obj)
        else:
            children_map.setdefault(parent_val, []).append(obj)

    flattened: list[dict[str, Any]] = []
    visited: set[Any] = set()

    def _walk(seed: Any) -> None:
        stack: list[tuple[Any, int]] = [(seed, 0)]
        while stack:
            node, depth = stack.pop()
            node_pk = getattr(node, pk_name)
            if node_pk in visited:
                continue
            visited.add(node_pk)
            kids = children_map.get(node_pk, [])
            flattened.append(
                {
                    "obj": node,
                    "depth": depth,
                    "depth_cls": f"dk-tree-d{min(depth, 5)}",
                    "has_children": bool(kids),
                    "child_count": len(kids),
                }
            )
            for child in reversed(kids):
                child_pk = getattr(child, pk_name)
                if child_pk not in visited:
                    stack.append((child, depth + 1))

    for root in roots:
        _walk(root)
    # Also include pure cycles cleanly without infinite recursion
    for obj in records:
        if getattr(obj, pk_name) not in visited:
            _walk(obj)
    return flattened
