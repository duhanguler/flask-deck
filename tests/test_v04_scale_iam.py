from __future__ import annotations

import base64
import io
import json
import re
import sys
import time
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    AuthProvider,
    Deck,
    DeckEvent,
    DeckUser,
    FileFieldConfig,
    InMemoryMFAStore,
    InMemoryPasskeyStore,
    InMemorySessionStore,
    LocalFileStorage,
    MemoryFileStorage,
    MFAEnrollment,
    ModelView,
    OIDCAuthProvider,
    OIDCProviderConfig,
    PasskeyCredential,
    RBACAuthProvider,
    RedisPreviewStore,
    RedisRateLimitStore,
    Role,
    SecretCipher,
    SQLAlchemyJobBackend,
    SQLAlchemyMFAStore,
    SQLAlchemyPasskeyStore,
    SQLAlchemyPreviewStore,
    SQLAlchemyRateLimitStore,
    SQLAlchemySessionStore,
    SQLAlchemyWebhookDeliveryStore,
    WebhookSink,
    compute_totp,
    generate_totp_secret,
    run_security_audit,
)
from flask_deck.cli import deck_cli
from flask_deck.security import CSRF_FORM_FIELD, CSRF_HEADER_NAME
from tests.conftest import extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\sstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\son(?:click|change|submit|input|load)\s*=", re.IGNORECASE)


class M2Base(DeclarativeBase):
    pass


class AssetRecord(M2Base):
    __tablename__ = "m2_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    blob_key: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    secret_key: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("10.00"))
    due_date: Mapped[date | None] = mapped_column(sa.Date, nullable=True)


def _assert_strict_csp(html: str) -> None:
    assert not _INLINE_STYLE_RE.search(html), "Strict CSP violation: inline style= detected"
    assert not _INLINE_HANDLER_RE.search(html), "Strict CSP violation: inline on*= handler detected"


def _make_jwt(payload: dict[str, Any], *, alg: str = "RS256", kid: str = "k1") -> str:
    def _b64(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    sig = "" if alg.lower() == "none" else base64.urlsafe_b64encode(b"sig").decode("ascii").rstrip("=")
    return f"{_b64({'alg': alg, 'typ': 'JWT', 'kid': kid})}.{_b64(payload)}.{sig}"


def _make_rbac(roles: Sequence[Role] | None = None) -> RBACAuthProvider:
    used_roles = list(
        roles
        or [
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="editor",
                permissions=frozenset(
                    {"asset-records:view", "asset-records:create", "asset-records:edit"}
                ),
                masked_fields={"asset-records": frozenset({"secret_key"})},
            ),
        ]
    )
    return RBACAuthProvider(
        roles=used_roles,
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-ed", username="editor", roles=("editor",)),
                password="editor-password",
            ),
        ],
    )


def test_streaming_media_presigned_redirect_and_spooled_async_export(tmp_path: Path) -> None:
    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(eng)
    SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    media_dir = tmp_path / "media"
    local_storage = LocalFileStorage(media_dir)
    job_storage = LocalFileStorage(tmp_path / "jobs")

    big_payload = b"%PDF-1.4\n" + (b"0123456789ABCDEF" * 12000)  # ~192 KB > 64 KB chunk
    stored_pdf = local_storage.save(big_payload, key="docs/manual.pdf", content_type="application/pdf")

    class FakeS3:
        def presign(self, key: str, ttl: int) -> str:
            return f"https://cdn.example.com/{key}?ttl={ttl}"

    class PresignedFakeStorage:
        def save(self, data: bytes, *, key: str, content_type: str) -> Any:
            return local_storage.save(data, key=key, content_type=content_type)

        def open(self, key: str) -> Any:
            return local_storage.open(key)

        def delete(self, key: str) -> None:
            local_storage.delete(key)

        def exists(self, key: str) -> bool:
            return local_storage.exists(key)

        def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
            return FakeS3().presign(key, expires_in)

    s3_proxy = PresignedFakeStorage()
    s3_proxy.save(b"%PDF-1.4\n%%EOF\n", key="docs/presigned.pdf", content_type="application/pdf")

    with SessionLocal() as s:
        s.add_all(
            [
                AssetRecord(
                    name="StreamedAsset",
                    blob_key=stored_pdf.key,
                    secret_key="docs/presigned.pdf",
                    amount=Decimal("42.50"),
                ),
                AssetRecord(
                    name="SecondRow",
                    blob_key=stored_pdf.key,
                    secret_key="docs/presigned.pdf",
                    amount=Decimal("99.00"),
                ),
            ]
        )
        s.commit()

    class AssetView(ModelView):
        model = AssetRecord
        columns = ("id", "name", "amount", "blob_key", "secret_key")
        file_fields = MappingProxyType(
            {
                "blob_key": FileFieldConfig(storage=local_storage, allowed_mimes=frozenset({"application/pdf"})),
                "secret_key": FileFieldConfig(
                    storage=s3_proxy,
                    allowed_mimes=frozenset({"application/pdf"}),
                    use_presigned_redirect=True,
                    presign_ttl=120,
                ),
            }
        )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "stream-test-secret-key-32-bytes!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=eng,
        auth=_make_rbac(),
        job_storage=job_storage,
        auto_audit=False,
    )
    try:
        deck.register(AssetView)
        c_adm = app.test_client()
        tok = login_as(c_adm, "admin", "admin-password")

        # Chunked streaming media download closes handle cleanly and returns exact bytes
        r_media = c_adm.get("/admin/_media/asset-records/blob_key/1")
        assert r_media.status_code == 200
        assert r_media.data == big_payload
        assert r_media.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"

        # Presigned redirect for authorized superuser
        r_presign = c_adm.get("/admin/_media/asset-records/secret_key/1", follow_redirects=False)
        assert r_presign.status_code == 302
        assert r_presign.headers["Location"] == "https://cdn.example.com/docs/presigned.pdf?ttl=120"
        assert "no-store" in r_presign.headers["Cache-Control"]

        # RBAC masked field MUST still block presigned redirect for restricted editor
        c_ed = app.test_client()
        login_as(c_ed, "editor", "editor-password")
        assert c_ed.get("/admin/_media/asset-records/secret_key/1").status_code == 403

        # SpooledTemporaryFile async CSV export -> streamed job artifact download
        r_exp = c_adm.post(
            "/admin/asset-records/export-async",
            data={CSRF_FORM_FIELD: tok},
            follow_redirects=False,
        )
        assert r_exp.status_code == 302
        focus = parse_qs(urlsplit(r_exp.headers["Location"]).query)["focus"][0]
        assert deck.job_backend is not None
        for _ in range(40):
            rec = deck.job_backend.get(focus)
            if rec and rec.status == "succeeded":
                break
            time.sleep(0.05)
        rec = deck.job_backend.get(focus)
        assert rec is not None and rec.status == "succeeded" and rec.artifact_key
        assert job_storage.exists(rec.artifact_key)

        r_art = c_adm.get(f"/admin/_jobs/{focus}/artifact")
        assert r_art.status_code == 200
        csv_text = r_art.data.decode("utf-8")
        assert "StreamedAsset" in csv_text and "SecondRow" in csv_text
    finally:
        deck.close()
        eng.dispose()


def test_multiworker_sqlalchemy_jobs_retry_scheduled_cli_and_sse(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'shared_jobs.db'}"
    eng_a = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    eng_b = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    M2Base.metadata.create_all(eng_a)

    attempts = {"fail_job": 0, "sched": 0}

    def flaky_task(ctx: Any) -> dict[str, Any]:
        attempts["fail_job"] += 1
        ctx.log(f"attempt={attempts['fail_job']}")
        if attempts["fail_job"] == 1:
            raise RuntimeError("boom on first try")
        ctx.set_progress(100, "recovered")
        return {"ok": True}

    def nightly_cleanup(ctx: Any) -> dict[str, Any]:
        attempts["sched"] += 1
        ctx.log("cleaned old rows")
        ctx.set_progress(100, "cleanup done")
        return {"deleted": 0}

    resolvers = {"flaky_task": flaky_task, "scheduled:nightly_cleanup": nightly_cleanup}
    backend_a = SQLAlchemyJobBackend(eng_a, callable_resolver=lambda k: resolvers.get(k))
    backend_b = SQLAlchemyJobBackend(eng_b, callable_resolver=lambda k: resolvers.get(k))

    def _build_app(eng: sa.Engine, backend: SQLAlchemyJobBackend) -> tuple[Flask, Deck]:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "multiworker-jobs-secret-32-bytes!"
        app.config["TESTING"] = True
        d = Deck(app, engine=eng, auth=_make_rbac(), job_backend=backend, auto_audit=False)
        d.register(AssetRecord)
        d.scheduled_job(
            name="nightly_cleanup",
            schedule="0 2 * * *",
            label="Nightly Cleanup",
        )(nightly_cleanup)
        return app, d

    app_a, deck_a = _build_app(eng_a, backend_a)
    app_b, deck_b = _build_app(eng_b, backend_b)
    try:
        # Enqueue on worker A -> wait for failure -> inspect & retry on worker B!
        rec = backend_a.submit(
            name="flaky_task",
            label="Flaky",
            actor_id="u-adm",
            actor_name="Admin",
            model_slug="asset-records",
            fn=flaky_task,
        )
        for _ in range(40):
            cur = backend_b.get(rec.id)
            if cur and cur.status == "failed":
                break
            time.sleep(0.05)
        cur = backend_b.get(rec.id)
        assert cur is not None and cur.status == "failed"
        assert backend_b.can_retry(cur.id)

        c_b = app_b.test_client()
        tok = login_as(c_b, "admin", "admin-password")
        r_retry = c_b.post(f"/admin/_jobs/{rec.id}/retry", data={CSRF_FORM_FIELD: tok}, follow_redirects=False)
        assert r_retry.status_code == 302
        new_id = parse_qs(urlsplit(r_retry.headers["Location"]).query)["focus"][0]
        for _ in range(40):
            r2 = backend_a.get(new_id)
            if r2 and r2.status == "succeeded":
                break
            time.sleep(0.05)
        r2 = backend_a.get(new_id)
        assert r2 is not None and r2.status == "succeeded"

        # Bounded SSE with id frame + Last-Event-ID
        r_sse = c_b.get(
            f"/admin/_api/jobs/{new_id}/stream?max_seconds=1",
            headers={"Last-Event-ID": "0"},
        )
        assert r_sse.status_code == 200
        body = r_sse.get_data(as_text=True)
        assert "id: 1" in body and '"status": "succeeded"' in body

        # Scheduled job UI Run Now
        r_jobs = c_b.get("/admin/_jobs")
        assert r_jobs.status_code == 200
        jobs_html = r_jobs.get_data(as_text=True)
        assert "Nightly Cleanup" in jobs_html
        _assert_strict_csp(jobs_html)

        r_sched = c_b.post(
            "/admin/_jobs/scheduled/nightly_cleanup/run",
            data={CSRF_FORM_FIELD: tok},
            follow_redirects=False,
        )
        assert r_sched.status_code == 302
        sched_id = parse_qs(urlsplit(r_sched.headers["Location"]).query)["focus"][0]
        for _ in range(40):
            rs = backend_b.get(sched_id)
            if rs and rs.status == "succeeded":
                break
            time.sleep(0.05)
        rs = backend_b.get(sched_id)
        assert rs is not None and rs.status == "succeeded"

        # CLI `jobs list` and `jobs run`
        app_a.cli.add_command(deck_cli)
        runner = app_a.test_cli_runner()
        res_list = runner.invoke(args=["deck", "jobs", "list"])
        assert res_list.exit_code == 0 and "nightly_cleanup" in res_list.output
        res_run = runner.invoke(args=["deck", "jobs", "run", "nightly_cleanup"])
        assert res_run.exit_code == 0 and attempts["sched"] >= 2
    finally:
        deck_a.close()
        deck_b.close()
        eng_a.dispose()
        eng_b.dispose()


def test_async_retrying_webhooks_dlq_and_ui() -> None:
    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(eng)
    deliv_store = SQLAlchemyWebhookDeliveryStore(eng)

    mode = {"code": 500}
    calls: list[str] = []

    def _transport(url: str, _body: bytes, hdrs: Mapping[str, str], _t: float) -> int:
        calls.append(f"{mode['code']}:{hdrs.get('X-Deck-Event')}")
        return mode["code"]

    sink = WebhookSink(
        "https://93.184.216.34/hook",
        secret="webhook-secret-thirty-two-bytes!",
        events=("*",),
        async_delivery=True,
        max_retries=2,
        retry_delays=(0.01, 0.01),
        delivery_store=deliv_store,
        transport=_transport,
    )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "webhooks-test-secret-32-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(app, engine=eng, auth=_make_rbac(), auto_audit=False)
    try:
        deck.register(AssetRecord)
        deck.add_webhook(sink)
        sink(DeckEvent(name="record.created", model_slug="m2-assets", record_pk="1"))
        sink.flush(timeout=5.0)

        dlq_items = deliv_store.list_deliveries(status="dead_letter")
        assert len(dlq_items) == 1
        dlq = dlq_items[0]
        assert dlq.attempts == 3  # initial + 2 retries
        assert dlq.last_status_code == 500
        assert len(calls) == 3

        client = app.test_client()
        tok = login_as(client, "admin", "admin-password")
        r_wh = client.get("/admin/_webhooks?status=dead_letter")
        assert r_wh.status_code == 200
        wh_html = r_wh.get_data(as_text=True)
        assert "dead_letter" in wh_html
        _assert_strict_csp(wh_html)

        # Fix downstream & Redeliver
        mode["code"] = 200
        r_red = client.post(
            f"/admin/_webhooks/{dlq.id}/redeliver",
            data={CSRF_FORM_FIELD: tok},
            follow_redirects=False,
        )
        assert r_red.status_code == 302
        sink.flush(timeout=5.0)
        delivered = deliv_store.list_deliveries(status="delivered")
        assert len(delivered) == 1

        # Send Test event from UI
        r_test = client.post(
            "/admin/_webhooks/test",
            data={CSRF_FORM_FIELD: tok, "sink_index": "0"},
            follow_redirects=False,
        )
        assert r_test.status_code == 302
        sink.flush(timeout=5.0)
        assert any("webhook.test" in c for c in calls)
    finally:
        deck.close()
        eng.dispose()


def test_multiworker_preview_ratelimit_and_redis_adapters(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'shared_stores.db'}"
    eng_a = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    eng_b = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    M2Base.metadata.create_all(eng_a)

    prev_a = SQLAlchemyPreviewStore(eng_a)
    prev_b = SQLAlchemyPreviewStore(eng_b)
    rl_a = SQLAlchemyRateLimitStore(eng_a, max_attempts=3, window_seconds=60, lockout_seconds=60)
    rl_b = SQLAlchemyRateLimitStore(eng_b, max_attempts=3, window_seconds=60, lockout_seconds=60)

    def _build(eng: sa.Engine, prev: SQLAlchemyPreviewStore, rl: SQLAlchemyRateLimitStore) -> tuple[Flask, Deck]:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "shared-stores-secret-key-32b!!"
        app.config["TESTING"] = True
        d = Deck(app, engine=eng, auth=_make_rbac(), preview_store=prev, rate_limit_store=rl, auto_audit=False)
        d.register(AssetRecord)
        return app, d

    app_a, deck_a = _build(eng_a, prev_a, rl_a)
    app_b, deck_b = _build(eng_b, prev_b, rl_b)
    try:
        c_a = app_a.test_client()
        c_b = app_b.test_client()
        tok_a = login_as(c_a, "admin", "admin-password")
        tok_b = login_as(c_b, "admin", "admin-password")

        # Share import preview token created on worker A and committed on worker B
        # Simulate one browser client routed to worker A then worker B via shared signed session cookie
        session_cookie = c_a.get_cookie("session")
        assert session_cookie is not None
        c_b.set_cookie("session", session_cookie.value)
        csv_bytes = b"name,amount,due_date\nMultiWorkerRow,55.25,2026-11-23\n"
        r_prev = c_a.post(
            "/admin/asset-records/import",
            data={
                CSRF_FORM_FIELD: tok_a,
                "step": "preview",
                "file": (io.BytesIO(csv_bytes), "rows.csv"),
            },
            content_type="multipart/form-data",
        )
        assert r_prev.status_code == 200
        prev_html = r_prev.get_data(as_text=True)
        m_tok = re.search(r'name="preview_token"\s+value="([^"]+)"', prev_html)
        assert m_tok is not None
        preview_token = m_tok.group(1)

        r_commit = c_b.post(
            "/admin/asset-records/import",
            data={CSRF_FORM_FIELD: tok_a, "step": "commit", "preview_token": preview_token},
            follow_redirects=False,
        )
        assert r_commit.status_code == 302
        _ = tok_b
        with SessionLocal_or_engine(eng_b) as sess:
            row = sess.scalars(sa.select(AssetRecord).where(AssetRecord.name == "MultiWorkerRow")).one()
            assert row.amount == Decimal("55.25")
            assert row.due_date == date(2026, 11, 23)

        # Replay of consumed preview token fails cleanly
        assert (
            prev_a.consume(preview_token, user_id="u-adm", session_token="", model_slug="asset-records")
            is None
        )

        # Multi-worker rate limiter lockout shared across worker A and B
        c_bad = app_a.test_client()
        login_page = c_bad.get("/admin/login")
        ltok = extract_csrf(login_page.get_data(as_text=True))
        for _ in range(3):
            c_bad.post("/admin/login", data={CSRF_FORM_FIELD: ltok, "username": "victim", "password": "wrong"})

        # Check lockout immediately on worker B!
        c_bad_b = app_b.test_client()
        ltok_b = extract_csrf(c_bad_b.get("/admin/login").get_data(as_text=True))
        r_lock = c_bad_b.post("/admin/login", data={CSRF_FORM_FIELD: ltok_b, "username": "victim", "password": "wrong"})
        assert r_lock.status_code == 429 and "Retry-After" in r_lock.headers
    finally:
        deck_a.close()
        deck_b.close()
        eng_a.dispose()
        eng_b.dispose()

    # Fake Redis client tests for RedisPreviewStore & RedisRateLimitStore
    kv: dict[str, str] = {}

    class FakeRedis:
        def getdel(self, key: str) -> str | None:
            return kv.pop(key, None)

        def get(self, key: str) -> str | None:
            return kv.get(key)

        def set(self, key: str, val: str, ex: int | None = None) -> None:
            _ = ex
            kv[key] = val

        def delete(self, *keys: str) -> int:
            return sum(1 for k in keys if kv.pop(k, None) is not None)

    fake_r = FakeRedis()
    r_prev_store = RedisPreviewStore(fake_r)
    from flask_deck.importer import DryRunReport

    rep = DryRunReport(
        token="ptok-1",
        model_slug="items",
        filename="a.csv",
        format="csv",
        upsert_key=None,
        headers=("name",),
        mapped_columns={"name": "name"},
        rows=(),
        creates=1,
        updates=0,
        unchanged=0,
        errors=0,
    )
    r_prev_store.put(rep, user_id="u1", session_token="s1")
    consumed = r_prev_store.consume("ptok-1", user_id="u1", session_token="s1", model_slug="items")
    assert consumed is not None and consumed.creates == 1
    assert r_prev_store.consume("ptok-1", user_id="u1", session_token="s1", model_slug="items") is None

    r_rl = RedisRateLimitStore(fake_r, max_attempts=2, window_seconds=60, lockout_seconds=30)
    assert r_rl.is_locked("1.2.3.4", "u1") == (False, 0)
    r_rl.record_failure("1.2.3.4", "u1")
    assert r_rl.is_locked("1.2.3.4", "u1") == (False, 0)
    r_rl.record_failure("1.2.3.4", "u1")
    locked, retry_s = r_rl.is_locked("1.2.3.4", "u1")
    assert locked and retry_s > 0
    r_rl.record_success("1.2.3.4", "u1")
    assert r_rl.is_locked("1.2.3.4", "u1") == (False, 0)


def SessionLocal_or_engine(eng: sa.Engine) -> sa.orm.Session:
    return sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)()


def test_session_registry_revocation_and_mfa_session_invalidation(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    eng_a = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    eng_b = sa.create_engine(db_url, connect_args={"check_same_thread": False})
    M2Base.metadata.create_all(eng_a)

    s_a = SQLAlchemySessionStore(eng_a)
    s_b = SQLAlchemySessionStore(eng_b)
    mfa_a = SQLAlchemyMFAStore(eng_a, encryption_key="sess-mfa-secret")
    mfa_b = SQLAlchemyMFAStore(eng_b, encryption_key="sess-mfa-secret")

    def _build(eng: sa.Engine, ss: SQLAlchemySessionStore, ms: SQLAlchemyMFAStore) -> tuple[Flask, Deck]:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "sessions-test-secret-32-bytes!!"
        app.config["TESTING"] = True
        d = Deck(app, engine=eng, auth=_make_rbac(), session_store=ss, mfa_store=ms, auto_audit=False)
        d.register(AssetRecord)
        return app, d

    app_a, deck_a = _build(eng_a, s_a, mfa_a)
    app_b, deck_b = _build(eng_b, s_b, mfa_b)
    try:
        c1 = app_a.test_client()
        c2 = app_b.test_client()
        login_as(c1, "admin", "admin-password")
        tok2 = login_as(c2, "admin", "admin-password")

        listed = s_b.list_sessions(user_id="u-adm")
        assert len(listed) == 2

        r_page = c2.get("/admin/_security/sessions?scope=all")
        assert r_page.status_code == 200
        html = r_page.get_data(as_text=True)
        assert "Active Sessions" in html and "CURRENT" in html
        _assert_strict_csp(html)

        # Revoke client 1's session from client 2 UI
        other_sid = next(r.session_id for r in listed if r.session_id != listed[0].session_id)
        # Ensure we revoke whichever is NOT client 2's current sid
        with c2.session_transaction() as sess2:
            c2_sid = sess2["_deck_sid"]
        target_sid = next(r.session_id for r in listed if r.session_id != c2_sid)
        _ = other_sid
        c2.post(f"/admin/_security/sessions/{target_sid}/revoke", data={CSRF_FORM_FIELD: tok2})

        # Client 1 MUST immediately lose access!
        r_revoked = c1.get("/admin/asset-records/", follow_redirects=False)
        assert r_revoked.status_code == 302 and "/admin/login" in r_revoked.headers["Location"]
        assert c1.get("/admin/_api/fk/asset-records").status_code == 401

        # Re-login c1 -> then enable MFA on c2 -> c1 MUST be revoked automatically!
        login_as(c1, "admin", "admin-password")
        c2.get("/admin/_security/mfa")
        with c2.session_transaction() as s_sec:
            setup_secret = s_sec["_deck_mfa_setup_secret"]
        code = compute_totp(setup_secret)
        r_mfa = c2.post(
            "/admin/_security/mfa",
            data={CSRF_FORM_FIELD: tok2, "action": "enable", "code": code},
        )
        assert r_mfa.status_code == 200
        r_after_mfa = c1.get("/admin/asset-records/", follow_redirects=False)
        assert r_after_mfa.status_code == 302 and "/admin/login" in r_after_mfa.headers["Location"]
        assert c2.get("/admin/_security/sessions").status_code == 200
    finally:
        deck_a.close()
        deck_b.close()
        eng_a.dispose()
        eng_b.dispose()


def test_encrypted_totp_secrets_and_key_rotation() -> None:
    secret = generate_totp_secret()
    cipher = SecretCipher("key-v1-alpha", ("key-v0-legacy",))
    enc = cipher.encrypt(secret)
    assert enc.startswith("enc:v1:") and secret not in enc
    assert cipher.decrypt(enc) == secret

    # InMemoryMFAStore encrypts at rest
    mem = InMemoryMFAStore(encryption_key="key-v1-alpha")
    mem.save(MFAEnrollment(user_id="u1", secret=secret, enabled=True))
    assert mem._records["u1"].secret.startswith("enc:v1:")
    loaded = mem.get("u1")
    assert loaded is not None and loaded.secret == secret
    assert mem.verify_and_record("u1", compute_totp(secret))

    # SQLAlchemyMFAStore encryption, fallback decryption, legacy migration, and rotation
    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        store_v1 = SQLAlchemyMFAStore(eng, encryption_key="key-v1-alpha")
        store_v1.save(MFAEnrollment(user_id="u1", secret=secret, enabled=True))

        # Raw DB column MUST NOT contain plaintext Base32 secret
        with eng.connect() as conn:
            raw_row = conn.execute(sa.text("SELECT secret FROM _flask_deck_mfa WHERE user_id='u1'")).scalar()
            assert isinstance(raw_row, str) and raw_row.startswith("enc:v1:")
            assert raw_row != secret
            # Insert a legacy plaintext enrollment directly
            leg_secret = generate_totp_secret()
            conn.execute(
                sa.text(
                    "INSERT INTO _flask_deck_mfa (user_id, secret, enabled, recovery_hashes_json, created_at) "
                    "VALUES ('u-leg', :sec, 1, '[]', '2026-01-01 00:00:00')"
                ),
                {"sec": leg_secret},
            )
            conn.commit()

        # Without key, decrypting encrypted secret must fail loudly
        store_nokey = SQLAlchemyMFAStore(eng)
        with pytest.raises(ValueError, match="encryption_key"):
            store_nokey.get("u1")

        # Key rotation from v1 -> v2 using fallback keys + legacy plaintext upgrade
        store_v2_rot = SQLAlchemyMFAStore(
            eng,
            encryption_key="key-v2-beta",
            encryption_fallback_keys=("key-v1-alpha",),
        )
        assert store_v2_rot.get("u1") is not None
        leg_loaded = store_v2_rot.get("u-leg")
        assert leg_loaded is not None and leg_loaded.secret == leg_secret
        rotated_count = store_v2_rot.rotate_secrets()
        assert rotated_count == 2

        # Now drop v1 fallback key: only v2 remains and works cleanly!
        store_v2_only = SQLAlchemyMFAStore(eng, encryption_key="key-v2-beta")
        assert store_v2_only.verify_and_record("u1", compute_totp(secret))
        assert store_v2_only.verify_and_record("u-leg", compute_totp(leg_secret))
    finally:
        eng.dispose()


def test_oidc_v2_discovery_id_token_presets_and_sso_only_login() -> None:
    # 1. Presets sanity & non-HTTPS rejection
    g_cfg = OIDCProviderConfig.google(client_id="cid", client_secret="sec")
    assert g_cfg.issuer_url == "https://accounts.google.com"
    assert OIDCProviderConfig.github(client_id="c", client_secret="s").authorize_url.startswith("https://")
    assert OIDCProviderConfig.okta(domain="acme.okta.com", client_id="c", client_secret="s").jwks_uri.endswith("/v1/keys")
    assert OIDCProviderConfig.entra(tenant_id="tid", client_id="c", client_secret="s").issuer_url.startswith("https://")
    assert OIDCProviderConfig.keycloak(base_url="https://kc.example.com", realm="prod", client_id="c", client_secret="s").issuer_url.endswith("/realms/prod")
    with pytest.raises(ValueError, match="https://"):
        OIDCProviderConfig(
            name="bad",
            label="Bad",
            client_id="c",
            client_secret="s",
            issuer_url="http://idp.example.com",
        )

    # 2. Discovery + nonce/iss/aud/exp/alg=none verification + SSO-only login form
    disc_calls = 0
    id_mode = {"kind": "valid", "nonce": ""}

    def _transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, _t: float) -> tuple[int, dict[str, Any]]:
        nonlocal disc_calls
        _ = (method, headers, body)
        if url.endswith("/.well-known/openid-configuration"):
            disc_calls += 1
            return 200, {
                "authorization_endpoint": "https://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/token",
                "userinfo_endpoint": "https://idp.example.com/userinfo",
                "jwks_uri": "https://idp.example.com/keys",
            }
        if url == "https://idp.example.com/token":
            now = int(time.time())
            kind = id_mode["kind"]
            nonce = "wrong-nonce" if kind == "bad_nonce" else id_mode["nonce"]
            iss = "https://evil.example.com" if kind == "bad_iss" else "https://idp.example.com"
            aud = "other-client" if kind == "bad_aud" else "app-client"
            exp = now - 3600 if kind == "expired" else now + 300
            alg = "none" if kind == "alg_none" else "RS256"
            tok = _make_jwt({"sub": "alice-sub", "nonce": nonce, "iss": iss, "aud": aud, "exp": exp}, alg=alg)
            return 200, {"access_token": "acc-123", "id_token": tok}
        if url == "https://idp.example.com/userinfo":
            return 200, {"sub": "alice-sub", "email": "alice@example.com", "email_verified": True, "groups": ["admins"]}
        return 404, {}

    sso_cfg = OIDCProviderConfig(
        name="corp",
        label="Corp SSO",
        client_id="app-client",
        client_secret="app-sec",
        issuer_url="https://idp.example.com",
        role_mapping={"admins": "admin"},
        superuser_groups=frozenset({"admins"}),
    )
    auth = OIDCAuthProvider(
        roles=[Role(name="admin", permissions=frozenset({"*"}))],
        providers=[sso_cfg],
        accounts=(),  # SSO-only!
        http_transport=_transport,
    )
    assert auth.supports_login_form is True
    assert auth.supports_password_login is False

    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(eng)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "oidc-v2-test-secret-32-bytes!!!"
    app.config["TESTING"] = True
    deck = Deck(app, engine=eng, auth=auth, auto_audit=False)
    try:
        deck.register(AssetRecord)
        c = app.test_client()

        # SSO-only hides password <form> and rejects POST /login with 403
        r_login = c.get("/admin/login")
        assert r_login.status_code == 200
        login_html = r_login.get_data(as_text=True)
        assert "Sign in with Corp SSO" in login_html
        assert 'name="password"' not in login_html
        ltok = extract_csrf(login_html)
        assert c.post("/admin/login", data={CSRF_FORM_FIELD: ltok, "username": "a", "password": "b"}).status_code == 403

        def _run_sso(kind: str) -> Any:
            id_mode["kind"] = kind
            redir = c.get("/admin/login/sso/corp", follow_redirects=False)
            assert redir.status_code == 302
            qs = parse_qs(urlsplit(redir.headers["Location"]).query)
            id_mode["nonce"] = qs["nonce"][0]
            state = qs["state"][0]
            return c.get(f"/admin/login/sso/corp/callback?code=c1&state={state}", follow_redirects=False)

        for bad_kind in ("alg_none", "bad_nonce", "bad_iss", "bad_aud", "expired"):
            bad_resp = _run_sso(bad_kind)
            assert bad_resp.status_code == 403, f"Expected 403 for id_token {bad_kind}"

        ok_resp = _run_sso("valid")
        assert ok_resp.status_code == 302
        assert disc_calls == 1  # discovery cached across callbacks
        assert c.get("/admin/").status_code == 200
    finally:
        deck.close()
        eng.dispose()


def test_provider_agnostic_impersonation() -> None:
    class CustomDBAuthProvider(AuthProvider):
        supports_login_form = True
        supports_password_login = True

        def __init__(self) -> None:
            self.users = {
                "sup1": DeckUser(id="sup1", username="sup1", roles=("admin",), is_superuser=True),
                "sup2": DeckUser(id="sup2", username="sup2", roles=("admin",), is_superuser=True),
                "ed1": DeckUser(id="ed1", username="ed1", roles=("editor",), is_superuser=False),
            }

        def authenticate(self, username: str, password: str) -> DeckUser | None:
            if password == "pw" and username in self.users:
                return self.users[username]
            return None

        def get_current_user(self, *, idle_timeout: int = 1800, absolute_timeout: int = 43200) -> DeckUser | None:
            uid = self._validate_session_timestamps(idle_timeout=idle_timeout, absolute_timeout=absolute_timeout)
            return self.users.get(uid) if uid else None

        def has_permission(self, user: DeckUser | None, permission: str, *, model_slug: str | None = None, obj: Any = None) -> bool:
            _ = (model_slug, obj)
            if user is None:
                return False
            if user.is_superuser:
                return True
            return permission == "asset-records:view"

        def get_user_by_id(self, user_id: str) -> DeckUser | None:
            return self.users.get(user_id)

        def get_impersonatable_users(self, actor: DeckUser) -> Sequence[DeckUser]:
            if not actor.is_superuser:
                return ()
            return tuple(u for u in self.users.values() if u.id != actor.id and not u.is_superuser)

    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(eng)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "imp-custom-secret-key-32-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        engine=eng,
        auth=CustomDBAuthProvider(),
        enable_impersonation=True,
        impersonate_read_only=True,
        auto_audit=False,
    )
    try:
        deck.register(AssetRecord)
        c = app.test_client()
        tok = login_as(c, "sup1", "pw")

        # Non-RBAC provider still sees impersonate dropdown in UI & can impersonate ed1
        dash = c.get("/admin/").get_data(as_text=True)
        assert "VIEW AS" in dash and 'value="ed1"' in dash

        r_imp = c.post("/admin/_impersonate/start", data={CSRF_FORM_FIELD: tok, "target_user_id": "ed1"})
        assert r_imp.status_code == 302
        # Read-only impersonation blocks POST mutations (CSRF passed -> ReadOnlyError/403)
        r_mut = c.post(
            "/admin/asset-records/new",
            data={CSRF_FORM_FIELD: tok, "name": "Blocked"},
        )
        assert r_mut.status_code == 403

        # Stop impersonation -> superuser cannot impersonate another superuser
        c.post("/admin/_impersonate/stop", data={CSRF_FORM_FIELD: tok})
        c.post("/admin/_impersonate/start", data={CSRF_FORM_FIELD: tok, "target_user_id": "sup2"})
        with c.session_transaction() as sess:
            assert "_deck_impersonated_id" not in sess
    finally:
        deck.close()
        eng.dispose()


def test_passkeys_webauthn_mocked_unavailable_and_prod_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    prod_eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(prod_eng)
    try:
        # 1. Production diagnostics warnings for in-memory job backend, in-memory storage & missing encryption_key
        class ProdFileView(ModelView):
            model = AssetRecord
            file_fields = MappingProxyType({"blob_key": FileFieldConfig(storage=MemoryFileStorage())})

        prod_app = Flask(__name__)
        prod_app.config["SECRET_KEY"] = "prod-diag-secret-key-32-bytes!!"
        prod_app.config["TESTING"] = True
        prod_deck = Deck(
            prod_app,
            engine=prod_eng,
            auth=_make_rbac(),
            environment="production",
            auto_audit=False,
        )
        try:
            prod_deck.register(ProdFileView)
            findings = run_security_audit(prod_app, prod_deck)
            titles = "\n".join(f.get("message", "") for f in findings)
            assert "ThreadPoolJobBackend" in titles
            assert "MemoryFileStorage" in titles
            assert "encryption_key" in titles
        finally:
            prod_deck.close()
    finally:
        prod_eng.dispose()

    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    M2Base.metadata.create_all(eng)
    try:

        # 2. Passkeys graceful 501 when webauthn package is absent, plus UI strict CSP
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "passkeys-test-secret-32-bytes!!"
        app.config["TESTING"] = True
        pk_store = SQLAlchemyPasskeyStore(eng)
        deck = Deck(app, engine=eng, auth=_make_rbac(), passkey_store=pk_store, auto_audit=False)
        try:
            deck.register(AssetRecord)
            c = app.test_client()
            tok = login_as(c, "admin", "admin-password")
            r_pk = c.get("/admin/_security/passkeys")
            assert r_pk.status_code == 200
            _assert_strict_csp(r_pk.get_data(as_text=True))

            # Mock missing webauthn cleanly if installed or absent
            monkeypatch.setitem(sys.modules, "webauthn", None)
            r_501 = c.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: tok}, json={})
            assert r_501.status_code == 501

            # 3. Full mocked webauthn registration + login ceremony
            class FakeWebAuthn:
                @staticmethod
                def generate_registration_options(**kwargs: Any) -> dict[str, Any]:
                    chal = base64.urlsafe_b64encode(b"reg-challenge-16").decode("ascii").rstrip("=")
                    return {"challenge": chal, "rp": {"id": kwargs["rp_id"]}, "user": {"id": "dS1hZG0="}}

                @staticmethod
                def generate_authentication_options(**kwargs: Any) -> dict[str, Any]:
                    chal = base64.urlsafe_b64encode(b"auth-challenge16").decode("ascii").rstrip("=")
                    return {"challenge": chal, "rpId": kwargs["rp_id"]}

                @staticmethod
                def options_to_json(opts: Any) -> str:
                    return json.dumps(opts)

                @staticmethod
                def verify_registration_response(**kwargs: Any) -> Any:
                    assert kwargs["expected_challenge"]
                    return SimpleNamespace(
                        credential_id=b"cred-bytes-1",
                        credential_public_key=b"pubkey-bytes-1",
                        sign_count=0,
                    )

                @staticmethod
                def verify_authentication_response(**kwargs: Any) -> Any:
                    assert kwargs["credential_current_sign_count"] == 0
                    return SimpleNamespace(new_sign_count=7)

            monkeypatch.setitem(sys.modules, "webauthn", FakeWebAuthn())

            r_opts = c.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: tok}, json={})
            assert r_opts.status_code == 200
            r_ver = c.post(
                "/admin/_security/passkeys/register/verify",
                headers={CSRF_HEADER_NAME: tok},
                json={"credential": {"id": "fake"}, "label": "YubiKey 5"},
            )
            assert r_ver.status_code == 200 and r_ver.get_json()["ok"] is True
            cred_id = r_ver.get_json()["credential_id"]

            # New unauthenticated client signs in via Passkey!
            c2 = app.test_client()
            ltok = extract_csrf(c2.get("/admin/login").get_data(as_text=True))
            r_aopts = c2.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: ltok}, json={})
            assert r_aopts.status_code == 200
            r_aver = c2.post(
                "/admin/login/passkey/verify",
                headers={CSRF_HEADER_NAME: ltok},
                json={"credential": {"id": cred_id}},
            )
            assert r_aver.status_code == 200 and r_aver.get_json()["ok"] is True
            assert pk_store.get(cred_id) is not None
            assert pk_store.get(cred_id).sign_count == 7  # type: ignore[union-attr]
            assert c2.get("/admin/").status_code == 200

            # Delete credential via UI
            tok2 = extract_csrf(c2.get("/admin/_security/passkeys").get_data(as_text=True))
            r_del = c2.post(
                f"/admin/_security/passkeys/{cred_id}/delete",
                data={CSRF_FORM_FIELD: tok2},
                follow_redirects=False,
            )
            assert r_del.status_code == 302
            assert pk_store.get(cred_id) is None
        finally:
            deck.close()
    finally:
        eng.dispose()


def test_inmemory_session_and_passkey_store_helpers() -> None:
    ss = InMemorySessionStore()
    from flask_deck.sessions import SessionRecord

    now = datetime.now(timezone.utc)
    ss.register(
        SessionRecord(
            session_id="s1",
            user_id="u1",
            username="u1",
            ip_address="127.0.0.1",
            user_agent="pytest",
            created_at=now,
            last_seen_at=now - timedelta(seconds=5),
        )
    )
    assert ss.is_active("s1")
    ss.touch("s1")
    assert ss.revoke("s1", actor_id="other") is False
    assert ss.revoke("s1", actor_id="u1") is True
    assert not ss.is_active("s1")

    ps = InMemoryPasskeyStore()
    ps.add(PasskeyCredential(credential_id="c1", user_id="u1", label="Key", public_key_b64="cGs"))
    ps.update_sign_count("c1", 3)
    assert ps.get("c1") is not None and ps.get("c1").sign_count == 3  # type: ignore[union-attr]
    assert ps.delete("c1", user_id="wrong") is False
    assert ps.delete("c1", user_id="u1") is True
