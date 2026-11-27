"""Protocol-parametrized store contract tests.

Every pluggable store protocol in ``flask_deck`` has ONE canonical contract here,
executed identically across ``InMemory``, ``SQLite``, ``PostgreSQL``, and ``Redis``
implementations so behavioral drift between backends is caught immediately.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import sqlalchemy as sa

from flask_deck.api_keys import InMemoryAPIKeyStore, SQLAlchemyAPIKeyStore, build_api_key_record
from flask_deck.approvals import (
    InMemoryApprovalStore,
    SQLAlchemyApprovalStore,
    make_approval_request,
)
from flask_deck.audit import AuditEntry, InMemoryAuditStore, SQLAlchemyAuditStore
from flask_deck.events import (
    InMemoryWebhookDeliveryStore,
    SQLAlchemyWebhookDeliveryStore,
    WebhookDeliveryRecord,
)
from flask_deck.importer import (
    DryRunReport,
    InMemoryPreviewStore,
    RedisPreviewStore,
    RowDiff,
    SQLAlchemyPreviewStore,
)
from flask_deck.jobs import JobContext, SQLAlchemyJobBackend, ThreadPoolJobBackend
from flask_deck.mfa import (
    InMemoryMFAStore,
    MFAEnrollment,
    SQLAlchemyMFAStore,
    compute_totp,
    generate_totp_secret,
)
from flask_deck.passkeys import InMemoryPasskeyStore, PasskeyCredential, SQLAlchemyPasskeyStore
from flask_deck.saved_views import (
    InMemoryRecordNoteStore,
    InMemorySavedViewStore,
    RecordNote,
    SavedViewRecord,
    SQLAlchemyRecordNoteStore,
    SQLAlchemySavedViewStore,
)
from flask_deck.security import (
    LoginRateLimiter,
    RedisRateLimitStore,
    SQLAlchemyRateLimitStore,
)
from flask_deck.sessions import InMemorySessionStore, SessionRecord, SQLAlchemySessionStore
from flask_deck.sql_console import (
    InMemorySavedQueryStore,
    SavedQueryRecord,
    SQLAlchemySavedQueryStore,
)
from tests._backends import isolated_postgres_engine, isolated_redis_client, sqlite_memory_engine

_SQL_BACKENDS = [
    pytest.param("memory", id="memory"),
    pytest.param("sqlite", id="sqlite"),
    pytest.param("postgres", id="postgres", marks=pytest.mark.postgres),
]

_SQL_AND_REDIS_BACKENDS = [
    *_SQL_BACKENDS,
    pytest.param("redis", id="redis", marks=pytest.mark.redis),
]


@contextmanager
def _backend_engine(kind: str) -> Iterator[sa.Engine | None]:
    if kind == "memory":
        yield None
        return
    if kind == "sqlite":
        with sqlite_memory_engine() as eng:
            yield eng
        return
    if kind == "postgres":
        with isolated_postgres_engine() as (eng, _schema):
            yield eng
        return
    raise AssertionError(f"Unsupported backend: {kind}")


# ---------------------------------------------------------------------------
# 1. AuditStore Contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_audit_store_contract(backend: str) -> None:
    with _backend_engine(backend) as eng:
        store = (
            InMemoryAuditStore(max_entries=100, hash_chain=True)
            if eng is None
            else SQLAlchemyAuditStore(eng, hash_chain=True)
        )
        now = datetime.now(timezone.utc)
        entries = [
            AuditEntry(
                id=f"aud-{i}",
                timestamp=now + timedelta(seconds=i),
                actor_id="u-1",
                actor_name="Alice",
                actor_ip="127.0.0.1",
                action="update" if i % 2 else "create",
                model_slug="orders" if i < 2 else "users",
                model_label="Order" if i < 2 else "User",
                record_pk=str(i),
                record_repr=f"Rec {i}",
                changes={"status": {"old": "draft", "new": "paid"}},
            )
            for i in range(3)
        ]
        for entry in entries:
            saved = store.record(entry)
            assert saved.entry_hash

        ok, bad_id = store.verify_chain()
        assert ok and bad_id is None

        found = store.get_entry("aud-1")
        assert found is not None and found.record_pk == "1"

        orders_only, total_orders = store.list_entries(model_slug="orders", limit=10)
        assert total_orders == 2
        assert all(e.model_slug == "orders" for e in orders_only)


# ---------------------------------------------------------------------------
# 2. SessionStore Contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_session_store_contract(backend: str) -> None:
    with _backend_engine(backend) as eng:
        store = InMemorySessionStore() if eng is None else SQLAlchemySessionStore(eng)
        now = datetime.now(timezone.utc)
        s1 = store.register(
            SessionRecord(
                session_id="sid-1",
                user_id="u-1",
                username="alice",
                ip_address="10.0.0.1",
                user_agent="pytest",
                created_at=now,
                last_seen_at=now,
            )
        )
        s2 = store.register(
            SessionRecord(
                session_id="sid-2",
                user_id="u-1",
                username="alice",
                ip_address="10.0.0.2",
                user_agent="pytest",
                created_at=now + timedelta(seconds=1),
                last_seen_at=now + timedelta(seconds=1),
            )
        )
        assert store.is_active(s1.session_id) and store.is_active(s2.session_id)
        store.touch(s1.session_id)
        listed = store.list_sessions(user_id="u-1")
        assert len(listed) == 2

        revoked = store.revoke_others("u-1", keep_session_id=s1.session_id)
        assert revoked == 1
        assert store.is_active(s1.session_id)
        assert not store.is_active(s2.session_id)

        assert store.revoke(s1.session_id)
        assert not store.is_active(s1.session_id)


# ---------------------------------------------------------------------------
# 3. ApprovalStore Contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_approval_store_contract(backend: str) -> None:
    with _backend_engine(backend) as eng:
        store = InMemoryApprovalStore() if eng is None else SQLAlchemyApprovalStore(eng)
        req = make_approval_request(
            model_slug="orders",
            model_label="Order",
            operation="edit",
            record_pk="42",
            record_repr="ORD-42",
            payload={"values": {"status": "paid"}},
            diff={"status": {"old": "pending", "new": "paid"}},
            reason="Verified payment",
            requester_id="u-req",
            requester_name="Requester",
        )
        created = store.create(req)
        assert store.pending_count() == 1
        fetched = store.get(created.id)
        assert fetched is not None and fetched.status == "pending"

        approved = store.resolve(
            created.id,
            status="approved",
            reviewer_id="u-rev",
            reviewer_name="Reviewer",
            review_note="Looks good",
        )
        assert approved is not None and approved.status == "approved"
        assert store.pending_count() == 0

        # Second resolution must be rejected (idempotent finality)
        second = store.resolve(
            created.id,
            status="rejected",
            reviewer_id="u-rev2",
            reviewer_name="Other",
        )
        assert second is None


# ---------------------------------------------------------------------------
# 4. SavedViewStore & RecordNoteStore Contracts
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_saved_view_and_record_note_contracts(backend: str) -> None:
    with _backend_engine(backend) as eng:
        sv_store = InMemorySavedViewStore() if eng is None else SQLAlchemySavedViewStore(eng)
        v_personal = sv_store.create(
            SavedViewRecord(
                id="sv-1",
                model_slug="orders",
                name="My Paid",
                query_string="f_status=paid",
                scope="personal",
                owner_id="u-1",
                owner_name="Alice",
            )
        )
        v_team = sv_store.create(
            SavedViewRecord(
                id="sv-2",
                model_slug="orders",
                name="Team Open",
                query_string="f_status=open",
                scope="team",
                owner_id="u-2",
                owner_name="Bob",
            )
        )
        v_role = sv_store.create(
            SavedViewRecord(
                id="sv-3",
                model_slug="orders",
                name="Support Default",
                query_string="f_status=pending",
                scope="role",
                owner_id="u-2",
                owner_name="Bob",
                default_for_role="support",
            )
        )
        views_u1 = sv_store.list_for_model("orders", user_id="u-1", roles=("support",))
        assert [v.id for v in views_u1] == [v_role.id, v_team.id, v_personal.id]

        # Non-owner non-superuser cannot delete another user's view
        assert not sv_store.delete(v_personal.id, actor_id="u-2", is_superuser=False)
        assert sv_store.delete(v_personal.id, actor_id="u-1", is_superuser=False)
        assert sv_store.get(v_personal.id) is None

        note_store = InMemoryRecordNoteStore() if eng is None else SQLAlchemyRecordNoteStore(eng)
        n1 = note_store.add(
            RecordNote(
                id="n-1",
                model_slug="orders",
                record_pk="10",
                author_id="u-1",
                author_name="Alice",
                body="Investigating invoice",
            )
        )
        pinned = note_store.toggle_pin(n1.id, model_slug="orders", record_pk="10")
        assert pinned is not None and pinned.pinned is True
        # Cross-record pin mismatch must return None
        assert note_store.toggle_pin(n1.id, model_slug="orders", record_pk="999") is None
        assert not note_store.delete(n1.id, actor_id="u-2", is_superuser=False)
        assert note_store.delete(n1.id, actor_id="u-1", is_superuser=False)
        assert note_store.list_notes("orders", "10") == []


# ---------------------------------------------------------------------------
# 5. APIKeyStore, SavedQueryStore, MFAStore, PasskeyStore & WebhookDeliveryStore
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_security_and_ops_stores_contract(backend: str) -> None:
    with _backend_engine(backend) as eng:
        # APIKeyStore
        ak_store = InMemoryAPIKeyStore() if eng is None else SQLAlchemyAPIKeyStore(eng)
        plaintext, rec = build_api_key_record(
            name="CI Key",
            owner_id="u-1",
            owner_name="Alice",
            scopes=("orders:view",),
            allowed_ips=("127.0.0.0/8",),
        )
        created_ak = ak_store.create(rec)
        assert ak_store.verify_token(plaintext, client_ip="127.0.0.1") is not None
        assert ak_store.verify_token(plaintext, client_ip="192.0.2.55") is None
        assert ak_store.revoke(created_ak.id, owner_id="u-1")
        assert ak_store.verify_token(plaintext, client_ip="127.0.0.1") is None

        # SavedQueryStore
        sq_store = InMemorySavedQueryStore() if eng is None else SQLAlchemySavedQueryStore(eng)
        sq = sq_store.create(
            SavedQueryRecord(
                id="sq-1",
                name="Revenue",
                sql="SELECT 1 AS x",
                owner_id="u-1",
                owner_name="Alice",
            )
        )
        toggled = sq_store.toggle_pin(sq.id, chart_type="line")
        assert toggled is not None and toggled.is_pinned_to_dashboard is True
        assert toggled.chart_type == "line"
        assert len(sq_store.list_queries(pinned_only=True)) == 1
        assert not sq_store.delete(sq.id, actor_id="u-2", is_superuser=False)
        assert sq_store.delete(sq.id, actor_id="u-1", is_superuser=False)

        # MFAStore (including replay protection & encryption at rest)
        mfa_key = "contract-test-mfa-encryption-key!"
        mfa_store = (
            InMemoryMFAStore(encryption_key=mfa_key)
            if eng is None
            else SQLAlchemyMFAStore(eng, encryption_key=mfa_key)
        )
        secret = generate_totp_secret()
        mfa_store.save(MFAEnrollment(user_id="u-1", secret=secret, enabled=True))
        ts = 1_750_000_000.0
        code = compute_totp(secret, timestamp=ts)
        assert mfa_store.verify_and_record("u-1", code, timestamp=ts) is True
        # Replay of identical TOTP timestep must be rejected!
        assert mfa_store.verify_and_record("u-1", code, timestamp=ts) is False
        mfa_store.delete("u-1")
        assert mfa_store.get("u-1") is None

        # PasskeyStore
        pk_store = InMemoryPasskeyStore() if eng is None else SQLAlchemyPasskeyStore(eng)
        cred = pk_store.add(
            PasskeyCredential(
                credential_id="cred-abc",
                user_id="u-1",
                label="YubiKey",
                public_key_b64="cHVibGljLWtleQ==",
                sign_count=1,
            )
        )
        pk_store.update_sign_count(cred.credential_id, 5)
        got_pk = pk_store.get(cred.credential_id)
        assert got_pk is not None and got_pk.sign_count == 5
        assert not pk_store.delete(cred.credential_id, user_id="u-other")
        assert pk_store.delete(cred.credential_id, user_id="u-1")
        assert pk_store.list_for_user("u-1") == []

        # WebhookDeliveryStore
        wh_store = (
            InMemoryWebhookDeliveryStore() if eng is None else SQLAlchemyWebhookDeliveryStore(eng)
        )
        drec = wh_store.record(
            WebhookDeliveryRecord(
                id="wh-1",
                webhook_url="https://hooks.example.test/ev",
                event_name="record.created",
                payload_json='{"id": 1}',
                status="failed",
                attempts=1,
                last_error="timeout",
            )
        )
        drec.status = "delivered"
        drec.attempts = 2
        drec.last_status_code = 200
        wh_store.update(drec)
        got_wh = wh_store.get("wh-1")
        assert got_wh is not None and got_wh.status == "delivered" and got_wh.attempts == 2


# ---------------------------------------------------------------------------
# 6. PreviewStore Contract (Memory + SQLite + PostgreSQL + Redis!)
# ---------------------------------------------------------------------------
@contextmanager
def _preview_store_for(backend: str) -> Iterator[Any]:
    if backend == "redis":
        with isolated_redis_client() as (client, prefix):
            yield RedisPreviewStore(client, ttl_seconds=60, key_prefix=f"{prefix}preview:")
        return
    with _backend_engine(backend) as eng:
        yield (
            InMemoryPreviewStore(ttl_seconds=60)
            if eng is None
            else SQLAlchemyPreviewStore(eng, ttl_seconds=60)
        )


@pytest.mark.parametrize("backend", _SQL_AND_REDIS_BACKENDS)
def test_preview_store_contract(backend: str) -> None:
    report = DryRunReport(
        token="tok-preview-1",
        model_slug="orders",
        filename="orders.csv",
        format="csv",
        upsert_key=None,
        headers=("code",),
        mapped_columns={"code": "code"},
        rows=(RowDiff(row_number=2, status="create", key_display="ORD-1", coerced_data={"code": "ORD-1"}),),
        creates=1,
        updates=0,
        unchanged=0,
        errors=0,
    )
    with _preview_store_for(backend) as store:
        store.put(report, user_id="u-owner", session_token="sess-A")

        # Peek succeeds for owner, returns None for wrong user/session/model
        assert store.peek("tok-preview-1", user_id="u-owner", session_token="sess-A", model_slug="orders") is not None
        assert store.peek("tok-preview-1", user_id="u-evil", session_token="sess-A", model_slug="orders") is None

        # CRITICAL SECURITY INVARIANT: Unauthorized consume MUST NOT delete owner's preview!
        assert store.consume("tok-preview-1", user_id="u-evil", session_token="sess-A", model_slug="orders") is None
        assert store.consume("tok-preview-1", user_id="u-owner", session_token="sess-B", model_slug="orders") is None
        assert store.consume("tok-preview-1", user_id="u-owner", session_token="sess-A", model_slug="users") is None

        # Legitimate owner can still consume exactly once
        consumed = store.consume(
            "tok-preview-1", user_id="u-owner", session_token="sess-A", model_slug="orders"
        )
        assert consumed is not None and consumed.creates == 1
        assert (
            store.consume(
                "tok-preview-1", user_id="u-owner", session_token="sess-A", model_slug="orders"
            )
            is None
        )


# ---------------------------------------------------------------------------
# 7. RateLimitStore Contract (Memory + SQLite + PostgreSQL + Redis!)
# ---------------------------------------------------------------------------
@contextmanager
def _rate_limit_store_for(backend: str) -> Iterator[Any]:
    if backend == "redis":
        with isolated_redis_client() as (client, prefix):
            yield RedisRateLimitStore(
                client,
                max_attempts=3,
                window_seconds=60,
                lockout_seconds=30,
                key_prefix=f"{prefix}rl:",
            )
        return
    with _backend_engine(backend) as eng:
        yield (
            LoginRateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=30)
            if eng is None
            else SQLAlchemyRateLimitStore(eng, max_attempts=3, window_seconds=60, lockout_seconds=30)
        )


@pytest.mark.parametrize("backend", _SQL_AND_REDIS_BACKENDS)
def test_rate_limit_store_contract(backend: str) -> None:
    with _rate_limit_store_for(backend) as rl:
        locked, _ = rl.is_locked("203.0.113.10", "alice")
        assert not locked

        rl.record_failure("203.0.113.10", "alice")
        rl.record_failure("203.0.113.10", "alice")
        assert rl.is_locked("203.0.113.10", "alice")[0] is False

        rl.record_failure("203.0.113.10", "alice")
        locked, retry_after = rl.is_locked("203.0.113.10", "alice")
        assert locked and retry_after >= 1

        # Different user from same IP is not yet locked by per-user bucket
        assert rl.is_locked("203.0.113.10", "bob")[0] is False

        # Successful login clears user-specific lockout bucket
        rl.record_success("203.0.113.10", "alice")
        assert rl.is_locked("203.0.113.10", "alice")[0] is False


# ---------------------------------------------------------------------------
# 8. JobBackend Contract (ThreadPool + SQLite + PostgreSQL)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("backend", _SQL_BACKENDS)
def test_job_backend_contract(backend: str) -> None:
    done = threading.Event()
    calls = {"n": 0}

    def _flaky_task(ctx: JobContext) -> str:
        calls["n"] += 1
        ctx.log(f"run-{calls['n']}")
        ctx.set_progress(50, "halfway")
        if calls["n"] == 1:
            done.set()
            raise RuntimeError("transient-error")
        ctx.set_progress(100, "complete")
        done.set()
        return "ok"

    with _backend_engine(backend) as eng:
        jb = (
            ThreadPoolJobBackend(max_workers=2)
            if eng is None
            else SQLAlchemyJobBackend(
                eng,
                max_workers=2,
                callable_resolver=lambda name: _flaky_task if name == "flaky" else None,
            )
        )
        try:
            rec = jb.submit(
                name="flaky",
                label="Contract Job",
                actor_id="u-1",
                actor_name="Alice",
                model_slug="orders",
                fn=_flaky_task,
            )
            assert done.wait(timeout=5.0)
            for _ in range(40):
                cur = jb.get(rec.id)
                if cur is not None and cur.status == "failed":
                    break
                time.sleep(0.02)
            cur = jb.get(rec.id)
            assert cur is not None and cur.status == "failed"
            assert jb.can_retry(cur.id)

            done.clear()
            retried = jb.retry(cur.id, actor_id="u-2", actor_name="Bob")
            assert retried is not None and retried.actor_id == "u-2"
            assert done.wait(timeout=5.0)
            for _ in range(40):
                fin = jb.get(retried.id)
                if fin is not None and fin.status == "succeeded":
                    break
                time.sleep(0.02)
            fin = jb.get(retried.id)
            assert fin is not None and fin.status == "succeeded"
            assert any("run-2" in line for line in fin.logs)
        finally:
            jb.shutdown(wait=True)
