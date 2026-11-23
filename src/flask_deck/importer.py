from __future__ import annotations

import csv
import enum
import io
import json
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from datetime import time as dt_time
from decimal import Decimal
from typing import Any, Literal, Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from flask_deck.adapters.sqlalchemy import extract_pk
from flask_deck.audit import serialize_audit_value
from flask_deck.auth import AuthProvider, DeckUser
from flask_deck.exceptions import ImportLimitError
from flask_deck.model_view import ModelView, coerce_form_value
from flask_deck.query import soft_delete_predicate
from flask_deck.security import check_json_depth, sanitize_csv_cell

RowStatus = Literal["create", "update", "unchanged", "error"]


@dataclass(frozen=True, slots=True)
class RowDiff:
    """Dry-run outcome for a single imported row."""

    row_number: int
    status: RowStatus
    key_display: str
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    coerced_data: dict[str, Any] = field(default_factory=dict)
    existing_pk: Any = None
    raw_row: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DryRunReport:
    """Complete savepoint-verified preview of a pending CSV/JSON import."""

    token: str
    model_slug: str
    filename: str
    format: str
    upsert_key: str | None
    headers: tuple[str, ...]
    mapped_columns: dict[str, str]
    rows: tuple[RowDiff, ...]
    creates: int
    updates: int
    unchanged: int
    errors: int

    @property
    def total_rows(self) -> int:
        return len(self.rows)

    @property
    def applicable_count(self) -> int:
        return self.creates + self.updates


@dataclass(slots=True)
class _CachedPreview:
    report: DryRunReport
    user_id: str
    session_token: str
    created_at: float


@runtime_checkable
class PreviewStore(Protocol):
    """Multi-worker preview token store contract for dry-run import confirmation."""

    def put(self, report: DryRunReport, *, user_id: str, session_token: str) -> None: ...

    def peek(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None: ...

    def consume(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None: ...


def _encode_preview_val(val: Any) -> Any:
    if isinstance(val, enum.Enum):
        return _encode_preview_val(val.value)
    if isinstance(val, Decimal):
        return {"__dk_t__": "decimal", "v": str(val)}
    if isinstance(val, datetime):
        return {"__dk_t__": "datetime", "v": val.isoformat()}
    if isinstance(val, date):
        return {"__dk_t__": "date", "v": val.isoformat()}
    if isinstance(val, dt_time):
        return {"__dk_t__": "time", "v": val.isoformat()}
    if isinstance(val, uuid.UUID):
        return {"__dk_t__": "uuid", "v": str(val)}
    if isinstance(val, tuple):
        return {"__dk_t__": "tuple", "v": [_encode_preview_val(x) for x in val]}
    if isinstance(val, list):
        return [_encode_preview_val(x) for x in val]
    if isinstance(val, dict):
        return {str(k): _encode_preview_val(v) for k, v in val.items()}
    return val


def _decode_preview_val(val: Any) -> Any:
    if isinstance(val, list):
        return [_decode_preview_val(x) for x in val]
    if isinstance(val, dict):
        tag = val.get("__dk_t__")
        if tag == "decimal":
            return Decimal(str(val["v"]))
        if tag == "datetime":
            return datetime.fromisoformat(str(val["v"]))
        if tag == "date":
            return date.fromisoformat(str(val["v"]))
        if tag == "time":
            return dt_time.fromisoformat(str(val["v"]))
        if tag == "uuid":
            return uuid.UUID(str(val["v"]))
        if tag == "tuple":
            return tuple(_decode_preview_val(x) for x in val["v"])
        return {k: _decode_preview_val(v) for k, v in val.items()}
    return val


def serialize_dry_run_report(report: DryRunReport) -> str:
    payload = {
        "token": report.token,
        "model_slug": report.model_slug,
        "filename": report.filename,
        "format": report.format,
        "upsert_key": report.upsert_key,
        "headers": list(report.headers),
        "mapped_columns": dict(report.mapped_columns),
        "creates": report.creates,
        "updates": report.updates,
        "unchanged": report.unchanged,
        "errors": report.errors,
        "rows": [
            {
                "row_number": r.row_number,
                "status": r.status,
                "key_display": r.key_display,
                "changes": {k: [_encode_preview_val(v[0]), _encode_preview_val(v[1])] for k, v in r.changes.items()},
                "errors": list(r.errors),
                "coerced_data": _encode_preview_val(r.coerced_data),
                "existing_pk": _encode_preview_val(r.existing_pk),
                "raw_row": _encode_preview_val(r.raw_row),
            }
            for r in report.rows
        ],
    }
    return json.dumps(payload, separators=(",", ":"))


def deserialize_dry_run_report(raw: str) -> DryRunReport:
    data = json.loads(raw)
    rows: list[RowDiff] = []
    for item in data["rows"]:
        changes = {
            k: (_decode_preview_val(pair[0]), _decode_preview_val(pair[1]))
            for k, pair in item["changes"].items()
        }
        rows.append(
            RowDiff(
                row_number=int(item["row_number"]),
                status=item["status"],
                key_display=str(item["key_display"]),
                changes=changes,
                errors=tuple(str(e) for e in item["errors"]),
                coerced_data=dict(_decode_preview_val(item["coerced_data"])),
                existing_pk=_decode_preview_val(item["existing_pk"]),
                raw_row=dict(_decode_preview_val(item.get("raw_row") or {})),
            )
        )
    return DryRunReport(
        token=str(data["token"]),
        model_slug=str(data["model_slug"]),
        filename=str(data["filename"]),
        format=str(data["format"]),
        upsert_key=data.get("upsert_key"),
        headers=tuple(str(h) for h in data["headers"]),
        mapped_columns=dict(data["mapped_columns"]),
        rows=tuple(rows),
        creates=int(data["creates"]),
        updates=int(data["updates"]),
        unchanged=int(data["unchanged"]),
        errors=int(data["errors"]),
    )


class ImportPreviewStore:
    """Thread-safe bounded, user/session-bound, single-use TTL store for dry-run previews."""

    __slots__ = ("_entries", "_lock", "_max_entries", "_ttl")

    def __init__(self, *, ttl_seconds: int = 900, max_entries: int = 64) -> None:
        self._ttl = max(60, ttl_seconds)
        self._max_entries = max(4, max_entries)
        self._entries: OrderedDict[str, _CachedPreview] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        expired = [k for k, v in self._entries.items() if (now - v.created_at) > self._ttl]
        for k in expired:
            self._entries.pop(k, None)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def put(self, report: DryRunReport, *, user_id: str, session_token: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            self._entries[report.token] = _CachedPreview(
                report=report,
                user_id=user_id,
                session_token=session_token,
                created_at=now,
            )
            self._entries.move_to_end(report.token)
            self._prune(now)

    def peek(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        """Read a cached preview report non-destructively without invalidating its token."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            item = self._entries.get(token)
            if item is None:
                return None
            if (
                item.user_id != user_id
                or item.session_token != session_token
                or item.report.model_slug != model_slug
            ):
                return None
            return item.report

    def consume(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        """Atomically pop a preview token only if user, session, model, and TTL all match."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            item = self._entries.get(token)
            if item is None:
                return None
            if (
                item.user_id != user_id
                or item.session_token != session_token
                or item.report.model_slug != model_slug
            ):
                return None
            self._entries.pop(token, None)
            return item.report


InMemoryPreviewStore = ImportPreviewStore


class SQLAlchemyPreviewStore:
    """Multi-worker SQLAlchemy dry-run import preview store with atomic single-use consumption."""

    def __init__(
        self,
        engine: Engine,
        *,
        ttl_seconds: int = 900,
        max_entries: int = 256,
        table_name: str = "_flask_deck_import_previews",
    ) -> None:
        self._engine = engine
        self._ttl = max(60, int(ttl_seconds))
        self._max_entries = max(4, int(max_entries))
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("token", sa.String(128), primary_key=True),
            sa.Column("user_id", sa.String(128), nullable=False, index=True),
            sa.Column("session_token", sa.String(255), nullable=False),
            sa.Column("model_slug", sa.String(128), nullable=False),
            sa.Column("payload_json", sa.Text, nullable=False),
            sa.Column("expires_at", sa.Float, nullable=False, index=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    def put(self, report: DryRunReport, *, user_id: str, session_token: str) -> None:
        now = time.time()
        payload = serialize_dry_run_report(report)
        with self._engine.begin() as conn:
            conn.execute(self._table.delete().where(self._table.c.expires_at < now))
            conn.execute(self._table.delete().where(self._table.c.token == report.token))
            conn.execute(
                self._table.insert().values(
                    token=report.token,
                    user_id=user_id,
                    session_token=session_token,
                    model_slug=report.model_slug,
                    payload_json=payload,
                    expires_at=now + self._ttl,
                )
            )
            excess = conn.execute(
                sa.select(self._table.c.token)
                .order_by(self._table.c.expires_at.desc())
                .offset(self._max_entries)
            ).scalars().all()
            if excess:
                conn.execute(self._table.delete().where(self._table.c.token.in_(excess)))

    def peek(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(self._table.delete().where(self._table.c.expires_at < now))
            raw = conn.execute(
                sa.select(self._table.c.payload_json).where(
                    sa.and_(
                        self._table.c.token == token,
                        self._table.c.user_id == user_id,
                        self._table.c.session_token == session_token,
                        self._table.c.model_slug == model_slug,
                        self._table.c.expires_at >= now,
                    )
                )
            ).scalar_one_or_none()
            return deserialize_dry_run_report(str(raw)) if raw is not None else None

    def consume(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(self._table.delete().where(self._table.c.expires_at < now))
            raw = conn.execute(
                sa.select(self._table.c.payload_json).where(
                    sa.and_(
                        self._table.c.token == token,
                        self._table.c.user_id == user_id,
                        self._table.c.session_token == session_token,
                        self._table.c.model_slug == model_slug,
                        self._table.c.expires_at >= now,
                    )
                )
            ).scalar_one_or_none()
            if raw is None:
                return None
            del_res = conn.execute(
                self._table.delete().where(
                    sa.and_(
                        self._table.c.token == token,
                        self._table.c.user_id == user_id,
                        self._table.c.session_token == session_token,
                        self._table.c.model_slug == model_slug,
                    )
                )
            )
            if (del_res.rowcount or 0) != 1:
                return None
            return deserialize_dry_run_report(str(raw))


class RedisPreviewStore:
    """Optional Redis multi-worker preview store (requires optional `redis` package or client)."""

    def __init__(
        self,
        redis_url_or_client: str | Any,
        *,
        ttl_seconds: int = 900,
        key_prefix: str = "flask_deck:preview:",
    ) -> None:
        self._ttl = max(60, int(ttl_seconds))
        self._prefix = key_prefix
        if isinstance(redis_url_or_client, str):
            try:
                import redis as redis_lib  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "redis is required for RedisPreviewStore. Install with: pip install 'flask-deck[redis]'"
                ) from exc
            self._client: Any = redis_lib.Redis.from_url(redis_url_or_client, decode_responses=True)
        else:
            self._client = redis_url_or_client

    def put(self, report: DryRunReport, *, user_id: str, session_token: str) -> None:
        envelope = json.dumps(
            {
                "user_id": user_id,
                "session_token": session_token,
                "model_slug": report.model_slug,
                "report": serialize_dry_run_report(report),
            }
        )
        self._client.set(f"{self._prefix}{report.token}", envelope, ex=self._ttl)

    def peek(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        raw = self._client.get(f"{self._prefix}{token}")
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            env = json.loads(raw)
        except Exception:
            return None
        if (
            env.get("user_id") != user_id
            or env.get("session_token") != session_token
            or env.get("model_slug") != model_slug
        ):
            return None
        return deserialize_dry_run_report(str(env["report"]))

    def consume(
        self,
        token: str,
        *,
        user_id: str,
        session_token: str,
        model_slug: str,
    ) -> DryRunReport | None:
        key = f"{self._prefix}{token}"
        raw = self._client.getdel(key) if hasattr(self._client, "getdel") else self._client.get(key)
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            env = json.loads(raw)
        except Exception:
            return None
        if (
            env.get("user_id") != user_id
            or env.get("session_token") != session_token
            or env.get("model_slug") != model_slug
        ):
            return None
        if not hasattr(self._client, "getdel") and int(self._client.delete(key) or 0) != 1:
            return None
        return deserialize_dry_run_report(str(env["report"]))


def parse_import_payload(
    raw_bytes: bytes,
    *,
    filename: str,
    max_bytes: int,
    max_rows: int,
    max_columns: int,
    max_json_depth: int,
) -> tuple[str, tuple[str, ...], list[dict[str, Any]]]:
    """Parse bounded CSV, JSON, or optional XLSX upload into (format, headers, row_dicts)."""
    if len(raw_bytes) > max_bytes:
        raise ImportLimitError(
            f"Upload exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MiB)."
        )
    if not raw_bytes.strip():
        raise ImportLimitError("Uploaded file is empty.")

    lower_name = filename.lower()
    if lower_name.endswith(".xlsx"):
        try:
            import openpyxl  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportLimitError(
                "XLSX import requires openpyxl. Install with: pip install 'flask-deck[excel]'."
            ) from exc
        try:
            wb = openpyxl.load_workbook(io.BytesIO(raw_bytes), read_only=True, data_only=True)
        except Exception as exc:
            raise ImportLimitError(f"Could not parse XLSX workbook: {exc}") from exc
        try:
            sheet = wb.active
            if sheet is None:
                raise ImportLimitError("XLSX workbook contains no sheets.")
            row_iter = sheet.iter_rows(values_only=True)
            header_tuple = next(row_iter, None)
            if not header_tuple:
                raise ImportLimitError("XLSX file is missing a header row.")
            headers = tuple(str(h).strip() for h in header_tuple if h is not None and str(h).strip())
            if not headers:
                raise ImportLimitError("XLSX file header row is empty.")
            if len(headers) > max_columns:
                raise ImportLimitError(f"XLSX exceeds maximum column limit ({max_columns}).")
            xlsx_rows: list[dict[str, Any]] = []
            for raw_vals in row_iter:
                if len(xlsx_rows) >= max_rows:
                    raise ImportLimitError(f"XLSX exceeds maximum row limit ({max_rows}).")
                vals = list(raw_vals)
                if not any(v is not None and str(v).strip() != "" for v in vals):
                    continue
                row_dict: dict[str, Any] = {}
                for col_idx, hname in enumerate(headers):
                    cell_v = vals[col_idx] if col_idx < len(vals) else None
                    row_dict[hname] = "" if cell_v is None else cell_v
                xlsx_rows.append(row_dict)
            return "xlsx", headers, xlsx_rows
        finally:
            close_fn = getattr(wb, "close", None)
            if callable(close_fn):
                close_fn()

    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportLimitError("File must be valid UTF-8 text.") from exc

    is_json = lower_name.endswith(".json") or text.lstrip().startswith("[")

    if is_json:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ImportLimitError(f"Invalid JSON syntax: {exc.msg} (line {exc.lineno}).") from exc
        if not isinstance(parsed, list):
            raise ImportLimitError("JSON import root must be an array of objects.")
        if len(parsed) > max_rows:
            raise ImportLimitError(f"Import exceeds maximum row limit ({max_rows}).")
        if not check_json_depth(parsed, max_json_depth):
            raise ImportLimitError(f"JSON nesting exceeds maximum depth ({max_json_depth}).")

        headers_order: list[str] = []
        seen_headers: set[str] = set()
        rows: list[dict[str, Any]] = []
        for idx, item in enumerate(parsed, start=1):
            if not isinstance(item, dict):
                raise ImportLimitError(f"JSON item #{idx} must be an object.")
            for k in item:
                ks = str(k)
                if ks not in seen_headers:
                    seen_headers.add(ks)
                    headers_order.append(ks)
                    if len(headers_order) > max_columns:
                        raise ImportLimitError(
                            f"Import exceeds maximum column limit ({max_columns})."
                        )
            rows.append({str(k): v for k, v in item.items()})
        return "json", tuple(headers_order), rows

    # CSV parsing with safe delimiter sniffing (, ; \t)
    sample = text[:4096]
    delimiter = ","
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise ImportLimitError("CSV file is missing a header row.")
    headers = tuple(h.strip() for h in reader.fieldnames if h is not None)
    if len(headers) > max_columns:
        raise ImportLimitError(f"CSV exceeds maximum column limit ({max_columns}).")

    rows = []
    for raw_row in reader:
        if len(rows) >= max_rows:
            raise ImportLimitError(f"CSV exceeds maximum row limit ({max_rows}).")
        clean_row = {
            (k.strip() if k is not None else ""): v for k, v in raw_row.items() if k is not None
        }
        if any(str(v or "").strip() != "" for v in clean_row.values()):
            rows.append(clean_row)
    return "csv", headers, rows


def auto_map_headers(
    headers: Sequence[str],
    allowed_fields: Sequence[str],
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Map uploaded column headers to strictly allowed writable model fields."""
    allowed_set = set(allowed_fields)
    norm_lookup = {f.lower().replace("_", ""): f for f in allowed_fields}
    mapping: dict[str, str] = {}
    for header in headers:
        if overrides and header in overrides:
            chosen = overrides[header].strip()
            if chosen in allowed_set:
                mapping[header] = chosen
            continue
        if header in allowed_set:
            mapping[header] = header
            continue
        norm = header.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
        if norm in norm_lookup:
            mapping[header] = norm_lookup[norm]
    return mapping


def _batch_load_existing(
    session: Session,
    view: ModelView,
    user: DeckUser | None,
    key_col: str,
    typed_keys: Sequence[Any],
    *,
    batch_size: int = 500,
) -> dict[Any, Any]:
    """Preload active matching records in chunked IN(...) batches to eliminate O(N) lookups."""
    if not typed_keys:
        return {}
    col_attr = getattr(view.model, key_col)
    unique_keys = list(dict.fromkeys(typed_keys))
    sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
    found: dict[Any, Any] = {}
    for start in range(0, len(unique_keys), batch_size):
        chunk = unique_keys[start : start + batch_size]
        stmt = view.scope_query(sa.select(view.model), user).where(col_attr.in_(chunk))
        if sd_pred is not None:
            stmt = stmt.where(sd_pred)
        for obj in session.scalars(stmt).all():
            found[getattr(obj, key_col)] = obj
    return found


def _batch_load_by_pk_tuples(
    session: Session,
    view: ModelView,
    user: DeckUser | None,
    pk_tuples: Sequence[tuple[Any, ...]],
    *,
    batch_size: int = 500,
) -> dict[tuple[Any, ...], Any]:
    """Preload active records by single or composite primary key tuples."""
    if not pk_tuples:
        return {}
    unique_pks = list(dict.fromkeys(pk_tuples))
    sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
    pk_cols = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
    found: dict[tuple[Any, ...], Any] = {}
    for start in range(0, len(unique_pks), batch_size):
        chunk = unique_pks[start : start + batch_size]
        stmt = view.scope_query(sa.select(view.model), user)
        if sd_pred is not None:
            stmt = stmt.where(sd_pred)
        if len(pk_cols) == 1:
            stmt = stmt.where(pk_cols[0].in_([t[0] for t in chunk]))
        else:
            stmt = stmt.where(sa.tuple_(*pk_cols).in_(chunk))
        for obj in session.scalars(stmt).all():
            found[extract_pk(obj, view.meta)] = obj
    return found


def run_dry_run_import(
    session: Session,
    view: ModelView,
    *,
    raw_bytes: bytes,
    filename: str,
    auth: AuthProvider,
    user: DeckUser | None,
    upsert_key: str | None = None,
    column_overrides: Mapping[str, str] | None = None,
    max_bytes: int = 5 * 1024 * 1024,
    max_rows: int = 5000,
    max_columns: int = 100,
    max_json_depth: int = 12,
) -> DryRunReport:
    """Validate and diff an import inside a guaranteed-rollback SQLAlchemy SAVEPOINT."""
    fmt, headers, raw_rows = parse_import_payload(
        raw_bytes,
        filename=filename,
        max_bytes=max_bytes,
        max_rows=max_rows,
        max_columns=max_columns,
        max_json_depth=max_json_depth,
    )

    hidden = auth.hidden_fields_for(user, view.meta.slug)
    readonly = auth.readonly_fields_for(user, view.meta.slug)
    masked = auth.masked_fields_for(user, view.meta.slug)
    writable_fields = tuple(
        c
        for c in view.resolved_import_columns
        if c not in hidden and c not in readonly and c not in masked and c not in view.meta.sensitive_fields
    )
    # Allow matching upsert_key even on PK or unique columns if not hidden/masked/sensitive.
    all_importable = list(writable_fields)
    if (
        upsert_key
        and upsert_key in view.meta.fields_by_name
        and upsert_key not in hidden
        and upsert_key not in masked
        and upsert_key not in view.meta.sensitive_fields
    ):
        if upsert_key not in all_importable:
            all_importable.append(upsert_key)
    else:
        upsert_key = None

    create_writable = set(writable_fields)
    if upsert_key:
        uf = view.meta.fields_by_name[upsert_key]
        if not uf.autoincrement:
            create_writable.add(upsert_key)

    mapped = auto_map_headers(headers, all_importable, overrides=column_overrides)
    if not mapped:
        raise ImportLimitError("No uploaded columns matched any writable fields on this model.")

    # Coerce rows first & collect upsert lookup keys for batched DB preload.
    parsed_entries: list[tuple[int, dict[str, Any], list[str], Any, dict[str, Any]]] = []
    lookup_keys: list[Any] = []
    for idx, raw_row in enumerate(raw_rows, start=1):
        row_data: dict[str, Any] = {}
        row_errors: list[str] = []
        for src_header, dst_field in mapped.items():
            fmeta = view.meta.fields_by_name[dst_field]
            raw_val = raw_row.get(src_header)
            try:
                coerced = coerce_form_value(raw_val, fmeta, max_json_depth=max_json_depth)
                row_data[dst_field] = coerced
            except ValueError as exc:
                row_errors.append(f"{dst_field}: {exc}")

        key_val = row_data.get(upsert_key) if upsert_key else None
        if upsert_key and key_val is not None:
            lookup_keys.append(key_val)
        parsed_entries.append((idx, row_data, row_errors, key_val, raw_row))

    existing_map = (
        _batch_load_existing(session, view, user, upsert_key, lookup_keys)
        if upsert_key
        else {}
    )

    validator_fn = view.get_form_validator()
    diffs: list[RowDiff] = []
    creates = updates = unchanged = error_count = 0

    # Outer savepoint guarantees ZERO mutations persist during dry-run even on exceptions!
    outer_sp = session.begin_nested()
    try:
        for row_num, row_data, row_errors, key_val, orig_raw in parsed_entries:
            key_display = str(key_val) if key_val is not None else f"Row #{row_num}"
            if row_errors:
                error_count += 1
                diffs.append(
                    RowDiff(
                        row_number=row_num,
                        status="error",
                        key_display=key_display,
                        errors=tuple(row_errors),
                        raw_row=dict(orig_raw),
                    )
                )
                continue

            existing_obj = existing_map.get(key_val) if (upsert_key and key_val is not None) else None

            if existing_obj is not None:
                # Compute field-level diff against existing record.
                changes: dict[str, tuple[Any, Any]] = {}
                for fname, new_val in row_data.items():
                    if fname not in writable_fields:
                        continue
                    old_val = getattr(existing_obj, fname, None)
                    if serialize_audit_value(old_val) != serialize_audit_value(new_val):
                        changes[fname] = (
                            serialize_audit_value(old_val),
                            serialize_audit_value(new_val),
                        )

                custom_errs = dict(view.validate(row_data, obj=existing_obj))
                if validator_fn is not None:
                    merged_payload = {**view.extract_snapshot(existing_obj), **row_data}
                    for fk, fmsgs in validator_fn(merged_payload, existing_obj, False).items():
                        custom_errs.setdefault(fk, []).extend(fmsgs)
                if custom_errs:
                    flat = tuple(f"{f}: {', '.join(m)}" for f, m in custom_errs.items())
                    error_count += 1
                    diffs.append(
                        RowDiff(
                            row_number=row_num,
                            status="error",
                            key_display=key_display,
                            errors=flat,
                            raw_row=dict(orig_raw),
                        )
                    )
                    continue

                if not changes:
                    unchanged += 1
                    diffs.append(
                        RowDiff(
                            row_number=row_num,
                            status="unchanged",
                            key_display=key_display,
                            existing_pk=extract_pk(existing_obj, view.meta),
                        )
                    )
                    continue

                # Test update inside inner savepoint (released on success so savepoints never stack!)
                row_sp = session.begin_nested()
                try:
                    for fname in changes:
                        setattr(existing_obj, fname, row_data[fname])
                    session.flush()
                    row_sp.commit()
                    updates += 1
                    diffs.append(
                        RowDiff(
                            row_number=row_num,
                            status="update",
                            key_display=key_display,
                            changes=changes,
                            coerced_data={k: row_data[k] for k in changes},
                            existing_pk=extract_pk(existing_obj, view.meta),
                        )
                    )
                except SQLAlchemyError as exc:
                    row_sp.rollback()
                    error_count += 1
                    diffs.append(
                        RowDiff(
                            row_number=row_num,
                            status="error",
                            key_display=key_display,
                            errors=(f"Database constraint error: {exc.__class__.__name__}",),
                            raw_row=dict(orig_raw),
                        )
                    )
                continue

            # Create path: verify required non-nullable fields without defaults.
            missing_req: list[str] = []
            for fmeta in view.meta.fields:
                if (
                    not fmeta.nullable
                    and not fmeta.has_default
                    and not fmeta.autoincrement
                    and not fmeta.is_sensitive
                    and fmeta.name not in row_data
                ):
                    missing_req.append(f"{fmeta.name}: required column missing.")
            if missing_req:
                error_count += 1
                diffs.append(
                    RowDiff(
                        row_number=row_num,
                        status="error",
                        key_display=key_display,
                        errors=tuple(missing_req),
                        raw_row=dict(orig_raw),
                    )
                )
                continue

            custom_errs = dict(view.validate(row_data, obj=None))
            if validator_fn is not None:
                for fk, fmsgs in validator_fn(row_data, None, True).items():
                    custom_errs.setdefault(fk, []).extend(fmsgs)
            if custom_errs:
                flat = tuple(f"{f}: {', '.join(m)}" for f, m in custom_errs.items())
                error_count += 1
                diffs.append(
                    RowDiff(
                        row_number=row_num,
                        status="error",
                        key_display=key_display,
                        errors=flat,
                        raw_row=dict(orig_raw),
                    )
                )
                continue

            row_sp = session.begin_nested()
            try:
                new_obj = view.model()
                for fname, val in row_data.items():
                    if fname in create_writable:
                        setattr(new_obj, fname, val)
                session.add(new_obj)
                session.flush()
                row_sp.commit()
                creates += 1
                create_changes = {
                    fname: (None, serialize_audit_value(val))
                    for fname, val in row_data.items()
                    if fname in create_writable
                }
                diffs.append(
                    RowDiff(
                        row_number=row_num,
                        status="create",
                        key_display=key_display,
                        changes=create_changes,
                        coerced_data={k: row_data[k] for k in create_changes},
                    )
                )
            except SQLAlchemyError as exc:
                row_sp.rollback()
                error_count += 1
                diffs.append(
                    RowDiff(
                        row_number=row_num,
                        status="error",
                        key_display=key_display,
                        errors=(f"Database constraint error: {exc.__class__.__name__}",),
                        raw_row=dict(orig_raw),
                    )
                )
    finally:
        # Unconditionally roll back the dry-run savepoint so zero changes leak!
        if outer_sp.is_active:
            outer_sp.rollback()
        session.expire_all()

    return DryRunReport(
        token=secrets.token_urlsafe(24),
        model_slug=view.meta.slug,
        filename=filename,
        format=fmt,
        upsert_key=upsert_key,
        headers=headers,
        mapped_columns=mapped,
        rows=tuple(diffs),
        creates=creates,
        updates=updates,
        unchanged=unchanged,
        errors=error_count,
    )


def format_failed_rows_csv(report: DryRunReport, *, sanitize_csv: bool = True) -> str:
    """Serialize all errored rows from a DryRunReport as formula-safe downloadable CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    headers = list(report.headers)
    writer.writerow(["row_number", "key", "errors", *[sanitize_csv_cell(h, enabled=sanitize_csv) for h in headers]])
    for r in report.rows:
        if r.status != "error":
            continue
        cells = [
            r.row_number,
            sanitize_csv_cell(r.key_display, enabled=sanitize_csv),
            sanitize_csv_cell("; ".join(r.errors), enabled=sanitize_csv),
            *[sanitize_csv_cell(r.raw_row.get(h, ""), enabled=sanitize_csv) for h in headers],
        ]
        writer.writerow(cells)
    return buf.getvalue()


def commit_dry_run_import(
    session: Session,
    view: ModelView,
    report: DryRunReport,
    *,
    user: DeckUser | None,
    skip_errors: bool = False,
    row_audit_cb: Callable[[str, str, str, dict[str, dict[str, Any]]], None] | None = None,
) -> tuple[int, int]:
    """Atomically apply a previously validated DryRunReport to the database."""
    if report.errors > 0 and not skip_errors:
        raise ImportLimitError(
            f"Import contains {report.errors} errored row(s). Fix errors or enable 'Skip errored rows'."
        )

    update_pks: list[tuple[Any, ...]] = []
    for r in report.rows:
        if r.status == "update" and r.existing_pk is not None:
            pk_t = r.existing_pk if isinstance(r.existing_pk, tuple) else (r.existing_pk,)
            update_pks.append(pk_t)
    existing_by_pk = _batch_load_by_pk_tuples(session, view, user, update_pks)

    created = 0
    updated = 0
    pending_audits: list[tuple[str, Any, dict[str, dict[str, Any]]]] = []
    for row in report.rows:
        coerced: dict[str, Any] = {}
        for fname, val in row.coerced_data.items():
            fmeta = view.meta.fields_by_name.get(fname)
            if fmeta is not None and fmeta.enum_class is not None and val is not None and not isinstance(val, fmeta.enum_class):
                coerced[fname] = fmeta.enum_class(val)
            else:
                coerced[fname] = val
        if row.status == "create":
            obj = view.model()
            for fname, val in coerced.items():
                setattr(obj, fname, val)
            view.on_model_change(obj, is_created=True, user=user)
            session.add(obj)
            created += 1
            if row_audit_cb is not None:
                diff = {
                    fname: {"old": old_v, "new": new_v}
                    for fname, (old_v, new_v) in row.changes.items()
                }
                pending_audits.append(("create", obj, diff))
        elif row.status == "update" and row.existing_pk is not None:
            pk_key = row.existing_pk if isinstance(row.existing_pk, tuple) else (row.existing_pk,)
            if pk_key in existing_by_pk:
                obj = existing_by_pk[pk_key]
                for fname, val in coerced.items():
                    setattr(obj, fname, val)
                view.on_model_change(obj, is_created=False, user=user)
                updated += 1
                if row_audit_cb is not None and row.changes:
                    diff = {
                        fname: {"old": old_v, "new": new_v}
                        for fname, (old_v, new_v) in row.changes.items()
                    }
                    pending_audits.append(("update", obj, diff))

    session.flush()
    resolved_audits: list[tuple[str, str, str, dict[str, dict[str, Any]]]] = []
    if row_audit_cb is not None:
        from flask_deck.adapters.sqlalchemy import encode_pk

        for op_name, obj, diff in pending_audits:
            pk_str = encode_pk(extract_pk(obj, view.meta))
            repr_str = view.format_record_repr(obj, user=user)
            resolved_audits.append((op_name, pk_str, repr_str, diff))
    session.commit()
    if row_audit_cb is not None:
        for op_name, pk_str, repr_str, diff in resolved_audits:
            row_audit_cb(op_name, pk_str, repr_str, diff)
    return created, updated
