from __future__ import annotations

import contextlib
import csv
import io
import re
import threading
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import sqlalchemy as sa
from markupsafe import Markup
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from flask_deck.charts import render_area_chart, render_bar_chart
from flask_deck.security import is_sensitive_field, sanitize_csv_cell

_ALLOWED_LEADING = frozenset({"SELECT", "WITH", "EXPLAIN"})

# Defense-in-depth denylist of mutating / administrative / side-effect keywords & functions.
_FORBIDDEN_KEYWORDS_RE = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|MERGE|UPSERT|"
    r"GRANT|REVOKE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|COPY|CALL|EXEC|EXECUTE|"
    r"COMMIT|ROLLBACK|BEGIN|SAVEPOINT|RELEASE|SET|RESET|"
    r"LOAD_EXTENSION|INTO\s+OUTFILE|INTO\s+DUMPFILE|"
    r"PG_READ_FILE|PG_READ_BINARY_FILE|PG_WRITE_FILE|PG_LS_DIR|PG_STAT_FILE|"
    r"PG_SLEEP|PG_TERMINATE_BACKEND|PG_CANCEL_BACKEND|PG_RELOAD_CONF|"
    r"SET_CONFIG|DBLINK|DBLINK_EXEC|QUERY_TO_XML|"
    r"LO_IMPORT|LO_EXPORT|LO_FROM_BYTEA|LO_UNLINK)\b",
    re.IGNORECASE,
)

# Internal security & database credential tables that must never be queried via the console.
_FORBIDDEN_TABLES_RE = re.compile(
    r"\b(?:_flask_deck_mfa|_flask_deck_passkeys|_flask_deck_sessions|deck_api_keys|"
    r"pg_authid|pg_shadow|pg_roles|mysql\.user|sqlite_temp_master)\b",
    re.IGNORECASE,
)

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, slots=True)
class SQLQueryResult:
    """Result returned by the read-only SQL Console."""

    sql: str
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    row_count: int
    truncated: bool
    redacted_columns: tuple[str, ...]
    duration_ms: float
    error: str | None = None


def _strip_sql_comments_and_literals(sql: str) -> tuple[str, list[str]]:
    """Single-pass SQL lexer removing comments & replacing string literals without regex order bugs.

    Returns ``(normalized_sql, quoted_identifiers)`` where comments become spaces,
    string literals become ``''``, and double-quoted identifiers remain inspectable.
    Raises ``ValueError`` on unterminated strings or comments.
    """
    out: list[str] = []
    quoted_idents: list[str] = []
    n = len(sql)
    i = 0

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        # Line comment: -- ...
        if ch == "-" and nxt == "-":
            i += 2
            while i < n and sql[i] != "\n":
                i += 1
            out.append(" ")
            continue

        # MySQL line comment: # ...
        if ch == "#":
            i += 1
            while i < n and sql[i] != "\n":
                i += 1
            out.append(" ")
            continue

        # Block comment: /* ... */ (supports PostgreSQL nested block comments)
        if ch == "/" and nxt == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if i + 1 < n and sql[i] == "/" and sql[i + 1] == "*":
                    depth += 1
                    i += 2
                elif i + 1 < n and sql[i] == "*" and sql[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth != 0:
                raise ValueError("Unterminated block comment in SQL query.")
            out.append(" ")
            continue

        # Single-quoted string literal ('...' with '' or \' escapes)
        if ch == "'":
            i += 1
            closed = False
            while i < n:
                if sql[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                raise ValueError("Unterminated string literal in SQL query.")
            out.append(" '' ")
            continue

        # PostgreSQL dollar-quoted string literal ($tag$...$tag$)
        if ch == "$":
            tag_end = i + 1
            while tag_end < n and (sql[tag_end].isalnum() or sql[tag_end] == "_"):
                tag_end += 1
            if tag_end < n and sql[tag_end] == "$":
                tag = sql[i : tag_end + 1]
                close_pos = sql.find(tag, tag_end + 1)
                if close_pos == -1:
                    raise ValueError("Unterminated dollar-quoted string in SQL query.")
                i = close_pos + len(tag)
                out.append(" '' ")
                continue

        # Double-quoted or backtick-quoted identifier — keep identifier text inspectable
        if ch in {'"', "`"}:
            quote_ch = ch
            i += 1
            buf: list[str] = []
            closed = False
            while i < n:
                if sql[i] == quote_ch:
                    if i + 1 < n and sql[i + 1] == quote_ch:
                        buf.append(quote_ch)
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                buf.append(sql[i])
                i += 1
            if not closed:
                raise ValueError("Unterminated quoted identifier in SQL query.")
            ident = "".join(buf)
            quoted_idents.append(ident)
            # Emit space-padded identifier so forbidden table/keyword checks inspect it too
            out.append(f" {ident} ")
            continue

        out.append(ch)
        i += 1

    return "".join(out), quoted_idents


def _split_top_level_select_items(normalized_sql: str) -> list[str]:
    """Extract top-level SELECT projection expressions from a normalized SQL string."""
    upper = normalized_sql.upper()
    m = re.match(r"^\s*SELECT\s+(?:DISTINCT\s+|ALL\s+)?", upper)
    if not m:
        return []
    pos = m.end()
    depth = 0
    items: list[str] = []
    start = pos
    n = len(normalized_sql)
    i = pos
    while i < n:
        ch = normalized_sql[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if ch == ",":
                items.append(normalized_sql[start:i].strip())
                start = i + 1
            elif upper[i:].startswith("FROM") and (
                (i == 0 or not upper[i - 1].isalnum())
                and (i + 4 >= n or not (upper[i + 4].isalnum() or upper[i + 4] == "_"))
            ):
                items.append(normalized_sql[start:i].strip())
                return items
        i += 1
    tail = normalized_sql[start:].strip()
    if tail:
        items.append(tail)
    return items


_WILDCARD_SELECT_ITEM_RE = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?\*$")


def _extract_select_item_alias(expr: str) -> str | None:
    """Best-effort extraction of the output column alias from a normalized SELECT expression."""
    m_as = re.search(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", expr, re.IGNORECASE)
    if m_as is not None:
        return m_as.group(1)
    stripped = expr.strip()
    if re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?[A-Za-z_][A-Za-z0-9_]*", stripped):
        return stripped.rsplit(".", 1)[-1]
    m_implicit = re.search(r"(?:\)|\s)\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", stripped)
    if m_implicit is not None:
        cand = m_implicit.group(1)
        if cand.upper() not in {"NULL", "TRUE", "FALSE", "END", "ASC", "DESC"}:
            return cand
    return None


def _expr_references_sensitive(expr: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(is_sensitive_field(ident, patterns) for ident in _IDENT_RE.findall(expr))


def _find_sensitive_indices_from_sql(
    normalized_sql: str,
    col_names: tuple[str, ...],
    extra_sensitive_patterns: Iterable[re.Pattern[str]],
) -> set[int]:
    """Identify output column positions whose SELECT expressions reference sensitive columns."""
    patterns = tuple(extra_sensitive_patterns)
    indices: set[int] = set()
    for idx, cname in enumerate(col_names):
        if is_sensitive_field(cname, patterns):
            indices.add(idx)

    select_items = _split_top_level_select_items(normalized_sql)
    if not select_items:
        return indices

    wildcard_positions = [
        i for i, item in enumerate(select_items) if _WILDCARD_SELECT_ITEM_RE.fullmatch(item.strip())
    ]

    if not wildcard_positions and len(select_items) == len(col_names):
        for idx, expr in enumerate(select_items):
            if _expr_references_sensitive(expr, patterns):
                indices.add(idx)
        return indices

    if wildcard_positions:
        first_wc = wildcard_positions[0]
        last_wc = wildcard_positions[-1]
        # Prefix expressions before the first wildcard map 1-to-1 to leading output columns.
        for idx in range(min(first_wc, len(col_names))):
            if _expr_references_sensitive(select_items[idx], patterns):
                indices.add(idx)
        # If there is a single wildcard, suffix expressions map 1-to-1 to trailing output columns.
        suffix_items = select_items[last_wc + 1 :]
        if len(wildcard_positions) == 1 and len(col_names) >= first_wc + len(suffix_items):
            if suffix_items:
                start_idx = len(col_names) - len(suffix_items)
                for offset, expr in enumerate(suffix_items):
                    if _expr_references_sensitive(expr, patterns):
                        indices.add(start_idx + offset)
        else:
            # Multiple wildcards or mismatched widths: inspect aliases and fail closed if ambiguous.
            ambiguous_sensitive = False
            for expr in select_items:
                if _WILDCARD_SELECT_ITEM_RE.fullmatch(expr.strip()):
                    continue
                if _expr_references_sensitive(expr, patterns):
                    alias = _extract_select_item_alias(expr)
                    if alias:
                        matched = False
                        for c_idx, cname in enumerate(col_names):
                            if cname.lower() == alias.lower():
                                indices.add(c_idx)
                                matched = True
                        if not matched:
                            ambiguous_sensitive = True
                    else:
                        ambiguous_sensitive = True
            if ambiguous_sensitive:
                return set(range(len(col_names)))
        return indices

    # Non-wildcard mismatch fallback: match aliases or fail closed if unaliased sensitive expr exists.
    ambiguous_sensitive = False
    for expr in select_items:
        if _expr_references_sensitive(expr, patterns):
            alias = _extract_select_item_alias(expr)
            if alias:
                matched = False
                for c_idx, cname in enumerate(col_names):
                    if cname.lower() == alias.lower():
                        indices.add(c_idx)
                        matched = True
                if not matched:
                    ambiguous_sensitive = True
            else:
                ambiguous_sensitive = True
    if ambiguous_sensitive:
        return set(range(len(col_names)))
    return indices


def validate_readonly_sql(
    raw_sql: str,
    *,
    extra_sensitive_patterns: Iterable[re.Pattern[str]] = (),
) -> str:
    """Strictly validate that raw_sql is a single read-only SELECT/WITH/EXPLAIN statement."""
    sql = raw_sql.strip()
    if not sql:
        raise ValueError("Enter a SQL query to run.")
    if len(sql) > 10_000:
        raise ValueError("Query exceeds 10,000-character limit.")

    # Strip trailing single semicolon only
    if sql.endswith(";"):
        sql = sql[:-1].rstrip()

    # Single-pass lexer strips comments & string literals cleanly (blocks '/*' / '--' smuggling)
    normalized, _quoted = _strip_sql_comments_and_literals(sql)

    # Disallow statement stacking (semicolons anywhere outside string literals)
    if ";" in normalized:
        raise ValueError("Multiple SQL statements are not permitted in the read-only console.")

    tokens = normalized.strip().split()
    if not tokens:
        raise ValueError("Enter a SQL query to run.")

    lead = tokens[0].upper().lstrip("(")
    if lead not in _ALLOWED_LEADING:
        raise ValueError(
            f"Only read-only SELECT, WITH, or EXPLAIN queries are permitted (got '{lead}')."
        )

    match = _FORBIDDEN_KEYWORDS_RE.search(normalized)
    if match is not None:
        raise ValueError(
            f"Blocked mutating or privileged SQL keyword: '{match.group(0).upper()}'."
        )

    tbl_match = _FORBIDDEN_TABLES_RE.search(normalized)
    if tbl_match is not None:
        raise ValueError(
            f"Access to internal security table '{tbl_match.group(0)}' is blocked."
        )

    # Block sensitive column references inside CTEs / subqueries so they cannot be aliased away.
    upper_norm = normalized.upper()
    has_cte_or_subquery = lead == "WITH" or len(re.findall(r"\bSELECT\b", upper_norm)) > 1
    if has_cte_or_subquery:
        patterns = tuple(extra_sensitive_patterns)
        for ident in _IDENT_RE.findall(normalized):
            if is_sensitive_field(ident, patterns):
                raise ValueError(
                    f"Referencing sensitive column '{ident}' inside a CTE or subquery is blocked."
                )

    return sql


def execute_readonly_sql(
    engine: Engine,
    raw_sql: str,
    *,
    max_rows: int = 200,
    extra_sensitive_patterns: Iterable[re.Pattern[str]] = (),
    explain: bool = False,
) -> SQLQueryResult:
    """Execute a validated read-only SQL query inside a read-only rolled-back transaction."""
    patterns = tuple(extra_sensitive_patterns)
    try:
        clean_sql = validate_readonly_sql(raw_sql, extra_sensitive_patterns=patterns)
        normalized_sql, _ = _strip_sql_comments_and_literals(clean_sql)
    except ValueError as exc:
        return SQLQueryResult(
            sql=raw_sql,
            columns=(),
            rows=(),
            row_count=0,
            truncated=False,
            redacted_columns=(),
            duration_ms=0.0,
            error=str(exc),
        )

    safe_limit = max(1, min(int(max_rows), 1000))
    t0 = time.perf_counter()
    dialect_name = engine.dialect.name
    exec_sql = clean_sql
    if explain and not normalized_sql.lstrip().upper().startswith("EXPLAIN"):
        exec_sql = (
            f"EXPLAIN QUERY PLAN {clean_sql}"
            if dialect_name == "sqlite"
            else f"EXPLAIN {clean_sql}"
        )
    try:
        with engine.connect() as conn:
            tx = conn.begin()
            sqlite_ro_set = False
            try:
                # Defense-in-depth DB-level read-only enforcement + timeout
                if dialect_name == "sqlite":
                    conn.execute(sa.text("PRAGMA query_only = ON"))
                    sqlite_ro_set = True
                elif dialect_name == "postgresql":
                    conn.execute(sa.text("SET TRANSACTION READ ONLY"))
                    conn.execute(sa.text("SET LOCAL statement_timeout = '5000ms'"))
                elif dialect_name in {"mysql", "mariadb"}:
                    conn.execute(sa.text("SET TRANSACTION READ ONLY"))

                result = conn.execute(sa.text(exec_sql))
                col_names = tuple(map(str, result.keys()))
                raw_rows = result.fetchmany(safe_limit + 1)
            finally:
                # Unconditional rollback guarantees zero persisted side-effects even on SQLite/PG.
                tx.rollback()
                if sqlite_ro_set:
                    # Restore connection state before returning to SQLAlchemy connection pool!
                    with contextlib.suppress(SQLAlchemyError):
                        conn.execute(sa.text("PRAGMA query_only = OFF"))
    except SQLAlchemyError as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        detail = str(getattr(exc, "orig", exc))
        return SQLQueryResult(
            sql=clean_sql,
            columns=(),
            rows=(),
            row_count=0,
            truncated=False,
            redacted_columns=(),
            duration_ms=elapsed,
            error=f"SQL execution error: {detail}",
        )

    elapsed = (time.perf_counter() - t0) * 1000.0
    truncated = len(raw_rows) > safe_limit
    kept = raw_rows[:safe_limit]

    sensitive_indices = _find_sensitive_indices_from_sql(normalized_sql, col_names, patterns)
    redacted_names = [col_names[idx] for idx in sorted(sensitive_indices)]

    sanitized_rows: list[tuple[Any, ...]] = []
    for row in kept:
        cells = tuple(
            "[REDACTED]" if idx in sensitive_indices else val for idx, val in enumerate(row)
        )
        sanitized_rows.append(cells)

    return SQLQueryResult(
        sql=clean_sql,
        columns=col_names,
        rows=tuple(sanitized_rows),
        row_count=len(sanitized_rows),
        truncated=truncated,
        redacted_columns=tuple(redacted_names),
        duration_ms=elapsed,
    )


def format_sql_result_csv(
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    sanitize_csv: bool = True,
) -> str:
    """Serialize SQL Console output to formula-safe CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([sanitize_csv_cell(col, enabled=sanitize_csv) for col in columns])
    for row in rows:
        writer.writerow([sanitize_csv_cell(v, enabled=sanitize_csv) for v in row])
    return buf.getvalue()


def introspect_engine_schema(engine: Engine) -> list[dict[str, Any]]:
    """Return browsable table + column schema metadata excluding internal credential tables."""
    insp = sa.inspect(engine)
    out: list[dict[str, Any]] = []
    for tbl in sorted(insp.get_table_names()):
        if _FORBIDDEN_TABLES_RE.search(tbl):
            continue
        cols: list[dict[str, str]] = []
        with contextlib.suppress(SQLAlchemyError):
            for c in insp.get_columns(tbl)[:40]:
                cols.append({"name": str(c.get("name", "")), "type": str(c.get("type", ""))})
        out.append({"name": tbl, "columns": cols})
    return out


def extract_sql_chart_data(
    result: SQLQueryResult,
) -> tuple[list[str], list[dict[str, Any]]] | None:
    """Detect label + numeric columns from SQLQueryResult to drive pure-SVG charts."""
    if result.error or not result.rows or len(result.columns) < 2:
        return None
    numeric_cols: list[int] = []
    label_col: int | None = None
    for idx in range(len(result.columns)):
        non_null = [r[idx] for r in result.rows[:25] if r[idx] is not None and r[idx] != "[REDACTED]"]
        if not non_null:
            continue
        is_num = True
        for val in non_null:
            if isinstance(val, bool):
                is_num = False
                break
            try:
                float(val)
            except (TypeError, ValueError):
                is_num = False
                break
        if is_num and label_col is not None and len(numeric_cols) < 2:
            numeric_cols.append(idx)
        elif label_col is None and not is_num:
            label_col = idx
        elif is_num and label_col is None:
            # Tentative numeric before a label appears
            numeric_cols.append(idx)
    if label_col is None:
        label_col = 0
        numeric_cols = [i for i in numeric_cols if i != 0][:2]
    if not numeric_cols:
        return None

    labels = [str(row[label_col] if row[label_col] is not None else "—")[:24] for row in result.rows[:24]]
    tones = ("primary", "ok")
    series: list[dict[str, Any]] = []
    for s_idx, col_idx in enumerate(numeric_cols[:2]):
        vals: list[float] = []
        for row in result.rows[:24]:
            v = row[col_idx]
            try:
                vals.append(float(v) if v is not None and not isinstance(v, bool) else 0.0)
            except (TypeError, ValueError):
                vals.append(0.0)
        series.append({"name": result.columns[col_idx], "data": vals, "tone": tones[s_idx % 2]})
    return labels, series


def build_sql_chart_svg(
    result: SQLQueryResult,
    *,
    chart_type: str = "bar",
) -> Markup | None:
    """Render strict-CSP pure SVG Bar or Line/Area chart from a SQLQueryResult."""
    extracted = extract_sql_chart_data(result)
    if extracted is None:
        return None
    labels, series = extracted
    if chart_type == "line":
        return render_area_chart(labels, series, height=220)
    return render_bar_chart(labels, series, height=220)


@dataclass(slots=True)
class SavedQueryRecord:
    """Persisted SQL Workbench 2.0 query and optional Dashboard BI pin."""

    id: str
    name: str
    sql: str
    bind_key: str = ""
    owner_id: str = ""
    owner_name: str = ""
    is_pinned_to_dashboard: bool = False
    chart_type: str = "bar"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _ensure_utc_sql(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@runtime_checkable
class SavedQueryStore(Protocol):
    """Persistence contract for SQL Workbench 2.0 saved/pinned BI queries."""

    def list_queries(
        self, *, pinned_only: bool = False, limit: int = 100
    ) -> list[SavedQueryRecord]: ...

    def get(self, query_id: str) -> SavedQueryRecord | None: ...

    def create(self, rec: SavedQueryRecord) -> SavedQueryRecord: ...

    def toggle_pin(self, query_id: str, *, chart_type: str | None = None) -> SavedQueryRecord | None: ...

    def delete(self, query_id: str, *, actor_id: str, is_superuser: bool = False) -> bool: ...


class InMemorySavedQueryStore:
    """Thread-safe in-memory store for SQL Workbench 2.0 saved & pinned queries."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, SavedQueryRecord] = {}
        self._lock = threading.Lock()

    def list_queries(
        self, *, pinned_only: bool = False, limit: int = 100
    ) -> list[SavedQueryRecord]:
        with self._lock:
            items = [
                replace(r)
                for r in self._records.values()
                if not pinned_only or r.is_pinned_to_dashboard
            ]
        items.sort(key=lambda r: r.created_at, reverse=True)
        return items[: max(1, int(limit))]

    def get(self, query_id: str) -> SavedQueryRecord | None:
        with self._lock:
            r = self._records.get(query_id)
            return replace(r) if r is not None else None

    def create(self, rec: SavedQueryRecord) -> SavedQueryRecord:
        stored = replace(rec, id=rec.id or uuid.uuid4().hex[:16])
        with self._lock:
            self._records[stored.id] = stored
        return replace(stored)

    def toggle_pin(
        self, query_id: str, *, chart_type: str | None = None
    ) -> SavedQueryRecord | None:
        with self._lock:
            r = self._records.get(query_id)
            if r is None:
                return None
            r.is_pinned_to_dashboard = not r.is_pinned_to_dashboard
            if chart_type in {"table", "bar", "line"}:
                r.chart_type = chart_type
            return replace(r)

    def delete(self, query_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        with self._lock:
            r = self._records.get(query_id)
            if r is None:
                return False
            if not is_superuser and r.owner_id != actor_id:
                return False
            self._records.pop(query_id, None)
            return True


class SQLAlchemySavedQueryStore:
    """Multi-worker SQLAlchemy store for saved BI queries (`deck_saved_queries`)."""

    def __init__(self, engine: Engine, *, table_name: str = "deck_saved_queries") -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("sql", sa.Text, nullable=False),
            sa.Column("bind_key", sa.String(64), nullable=False, default=""),
            sa.Column("owner_id", sa.String(128), nullable=False, index=True),
            sa.Column("owner_name", sa.String(128), nullable=False),
            sa.Column("is_pinned_to_dashboard", sa.Boolean, nullable=False, default=False, index=True),
            sa.Column("chart_type", sa.String(16), nullable=False, default="bar"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_rec(row: Any) -> SavedQueryRecord:
        now = datetime.now(timezone.utc)
        return SavedQueryRecord(
            id=str(row.id),
            name=str(row.name),
            sql=str(row.sql),
            bind_key=str(row.bind_key or ""),
            owner_id=str(row.owner_id),
            owner_name=str(row.owner_name),
            is_pinned_to_dashboard=bool(row.is_pinned_to_dashboard),
            chart_type=str(row.chart_type or "bar"),
            created_at=_ensure_utc_sql(row.created_at) or now,
        )

    def list_queries(
        self, *, pinned_only: bool = False, limit: int = 100
    ) -> list[SavedQueryRecord]:
        stmt = sa.select(self._table)
        if pinned_only:
            stmt = stmt.where(self._table.c.is_pinned_to_dashboard.is_(True))
        stmt = stmt.order_by(self._table.c.created_at.desc()).limit(max(1, int(limit)))
        with Session(self._engine) as sess:
            return [self._row_to_rec(r) for r in sess.execute(stmt)]

    def get(self, query_id: str) -> SavedQueryRecord | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == query_id)
            ).first()
            return self._row_to_rec(row) if row is not None else None

    def create(self, rec: SavedQueryRecord) -> SavedQueryRecord:
        now = rec.created_at or datetime.now(timezone.utc)
        qid = rec.id or uuid.uuid4().hex[:16]
        with Session(self._engine) as sess:
            sess.execute(
                self._table.insert().values(
                    id=qid,
                    name=rec.name[:120],
                    sql=rec.sql,
                    bind_key=(rec.bind_key or "")[:64],
                    owner_id=rec.owner_id[:128],
                    owner_name=rec.owner_name[:128],
                    is_pinned_to_dashboard=bool(rec.is_pinned_to_dashboard),
                    chart_type=(rec.chart_type or "bar")[:16],
                    created_at=now,
                )
            )
            sess.commit()
        return replace(rec, id=qid, created_at=now)

    def toggle_pin(
        self, query_id: str, *, chart_type: str | None = None
    ) -> SavedQueryRecord | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == query_id)
            ).first()
            if row is None:
                return None
            next_pinned = not bool(row.is_pinned_to_dashboard)
            upd: dict[str, Any] = {"is_pinned_to_dashboard": next_pinned}
            if chart_type in {"table", "bar", "line"}:
                upd["chart_type"] = chart_type
            sess.execute(
                self._table.update().where(self._table.c.id == query_id).values(**upd)
            )
            sess.commit()
            row2 = sess.execute(
                sa.select(self._table).where(self._table.c.id == query_id)
            ).first()
            return self._row_to_rec(row2) if row2 is not None else None

    def delete(self, query_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        conds: list[Any] = [self._table.c.id == query_id]
        if not is_superuser:
            conds.append(self._table.c.owner_id == actor_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.delete().where(*conds))
            sess.commit()
            return bool((getattr(res, "rowcount", 0) or 0) > 0)
