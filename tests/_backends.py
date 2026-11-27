"""Shared lifecycle helpers for isolated SQLite, PostgreSQL, and Redis test backends."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

_SCHEMA_RE = re.compile(r"^[a-z][a-z0-9_]{1,48}$")


def require_env_url(env_var: str, label: str) -> str:
    """Return URL from ``env_var``; skip locally when unset, fail loudly on CI."""
    url = os.environ.get(env_var, "").strip()
    if url:
        return url
    if os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}:
        pytest.fail(
            f"{env_var} must be configured in CI to run {label} integration tests (fail-closed)."
        )
    pytest.skip(f"{env_var} not set; skipping live {label} test.")


@contextmanager
def sqlite_memory_engine() -> Iterator[Engine]:
    """Yield an isolated in-memory SQLite Engine and dispose it on exit."""
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        yield engine
    finally:
        engine.dispose()


@contextmanager
def isolated_postgres_engine(url: str | None = None) -> Iterator[tuple[Engine, str]]:
    """Yield ``(engine, schema_name)`` bound to an isolated temporary PostgreSQL schema.

    Every test gets its own schema and ``search_path`` so tests never collide and
    can run safely in parallel. The schema is dropped with ``CASCADE`` on teardown.
    """
    pg_url = url or require_env_url("FLASK_DECK_TEST_PG_URL", "PostgreSQL")
    schema = f"dk_t_{uuid.uuid4().hex[:14]}"
    assert _SCHEMA_RE.fullmatch(schema)

    admin_engine = sa.create_engine(pg_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))

        scoped_engine = sa.create_engine(
            pg_url,
            connect_args={"options": f"-c search_path={schema},public"},
            pool_pre_ping=True,
        )
        try:
            yield scoped_engine, schema
        finally:
            scoped_engine.dispose()
    finally:
        try:
            with admin_engine.connect() as conn:
                conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        finally:
            admin_engine.dispose()


@contextmanager
def isolated_redis_client(url: str | None = None) -> Iterator[tuple[Any, str]]:
    """Yield ``(redis_client, key_prefix)`` with guaranteed key cleanup and close()."""
    redis_url = url or require_env_url("FLASK_DECK_TEST_REDIS_URL", "Redis")
    import redis as redis_lib

    prefix = f"dk_t:{uuid.uuid4().hex[:12]}:"
    client = redis_lib.Redis.from_url(redis_url, decode_responses=True)
    try:
        client.ping()
        yield client, prefix
    finally:
        try:
            cursor = 0
            while True:
                cursor, keys = client.scan(cursor=cursor, match=f"{prefix}*", count=200)
                if keys:
                    client.delete(*keys)
                if cursor == 0:
                    break
        finally:
            client.close()
