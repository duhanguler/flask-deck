"""Live Redis 7 integration tests verifying Lua atomicity, concurrency, and TTL invariants."""

from __future__ import annotations

import threading
import time

import pytest

from flask_deck.importer import DryRunReport, RedisPreviewStore, RowDiff
from flask_deck.security import RedisRateLimitStore
from tests._backends import isolated_redis_client

pytestmark = pytest.mark.redis


def test_redis_preview_store_lua_isolation_and_real_ttl() -> None:
    with isolated_redis_client() as (client, prefix):
        store = RedisPreviewStore(client, ttl_seconds=60, key_prefix=f"{prefix}prev:")
        report = DryRunReport(
            token="live-tok-1",
            model_slug="products",
            filename="p.csv",
            format="csv",
            upsert_key="sku",
            headers=("sku",),
            mapped_columns={"sku": "sku"},
            rows=(RowDiff(row_number=2, status="create", key_display="SKU-1", coerced_data={"sku": "SKU-1"}),),
            creates=1,
            updates=0,
            unchanged=0,
            errors=0,
        )
        store.put(report, user_id="owner-1", session_token="sess-1")

        # Concurrent unauthorized consume attempts must NOT evict the owner's key
        errors: list[BaseException] = []

        def _attacker() -> None:
            try:
                res = store.consume(
                    "live-tok-1",
                    user_id="attacker",
                    session_token="sess-1",
                    model_slug="products",
                )
                assert res is None
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_attacker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

        # Owner still succeeds exactly once even under concurrent double-submit race!
        winners: list[DryRunReport] = []
        win_lock = threading.Lock()

        def _owner_submit() -> None:
            got = store.consume(
                "live-tok-1",
                user_id="owner-1",
                session_token="sess-1",
                model_slug="products",
            )
            if got is not None:
                with win_lock:
                    winners.append(got)

        submitters = [threading.Thread(target=_owner_submit) for _ in range(6)]
        for t in submitters:
            t.start()
        for t in submitters:
            t.join()
        assert len(winners) == 1

        # Verify real Redis key TTL expiration works cleanly
        store.put(report, user_id="owner-1", session_token="sess-1")
        client.pexpire(f"{prefix}prev:live-tok-1", 150)
        time.sleep(0.25)
        assert (
            store.peek(
                "live-tok-1",
                user_id="owner-1",
                session_token="sess-1",
                model_slug="products",
            )
            is None
        )


def test_redis_rate_limit_store_concurrent_burst_atomicity() -> None:
    with isolated_redis_client() as (client, prefix):
        rl = RedisRateLimitStore(
            client,
            max_attempts=5,
            window_seconds=60,
            lockout_seconds=30,
            key_prefix=f"{prefix}rl:",
        )
        barrier = threading.Barrier(8)

        def _hammer() -> None:
            barrier.wait()
            rl.record_failure("198.51.100.7", "target-user")

        threads = [threading.Thread(target=_hammer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 8 concurrent increments must be counted atomically -> locked immediately
        locked, retry_after = rl.is_locked("198.51.100.7", "target-user")
        assert locked and retry_after >= 1

        # Clearing user success unlocks user while preserving clean Redis state
        rl.record_success("198.51.100.7", "target-user")
        assert rl.is_locked("198.51.100.7", "target-user")[0] is False
