from __future__ import annotations

import contextlib
import csv
import io
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

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
    r"\b(?:_flask_deck_mfa|pg_authid|pg_shadow|pg_roles|mysql\.user|sqlite_temp_master)\b",
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
    if select_items and len(select_items) == len(col_names):
        for idx, expr in enumerate(select_items):
            for ident in _IDENT_RE.findall(expr):
                if is_sensitive_field(ident, patterns):
                    indices.add(idx)
                    break
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

                result = conn.execute(sa.text(clean_sql))
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
