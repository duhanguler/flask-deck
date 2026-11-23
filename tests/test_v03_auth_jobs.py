from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckUser,
    InMemoryAuditStore,
    InMemoryMFAStore,
    JobContext,
    ModelView,
    OIDCAuthProvider,
    OIDCProviderConfig,
    RBACAuthProvider,
    Role,
    ThreadPoolJobBackend,
    action,
    build_otpauth_uri,
    compute_totp,
    generate_totp_secret,
    render_qr_svg,
    verify_totp,
)
from flask_deck.security import CSRF_FORM_FIELD, CSRF_SESSION_KEY


class AuthJobBase(DeclarativeBase):
    pass


class JobItem(AuthJobBase):
    __tablename__ = "v03_job_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    synced: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)


def _csrf(client: Any) -> str:
    with client.session_transaction() as sess:
        tok = sess.get(CSRF_SESSION_KEY)
        if not tok:
            tok = "m" * 48
            sess[CSRF_SESSION_KEY] = tok
        return str(tok)


def _login(client: Any, username: str, password: str) -> Any:
    client.get("/admin/login")
    tok = _csrf(client)
    return client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: tok},
        follow_redirects=False,
    )


def test_totp_rfc6238_replay_defense_qr_svg_and_login_flow() -> None:
    # 1. Pure-Python RFC 6238 SHA-1 standard test vector ("12345678901234567890" -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
    rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    # T = 59s -> step 1 -> expected 6-digit RFC 6238 SHA1 code is 287082
    assert compute_totp(rfc_secret, timestamp=59) == "287082"
    step = verify_totp(rfc_secret, "287082", timestamp=59)
    assert step == 1
    # Replay attack in same time-step must be REJECTED!
    assert verify_totp(rfc_secret, "287082", timestamp=59, last_step=step) is None

    # 2. Pure-Python ISO QR SVG check (zero inline style=, valid path & quiet zone)
    secret = generate_totp_secret()
    uri = build_otpauth_uri(secret=secret, account_name="admin@acme.dev", issuer="Acme Ops")
    svg = str(render_qr_svg(uri, pixel_size=184))
    assert svg.startswith('<svg class="dk-qr-svg"')
    assert 'style="' not in svg
    assert "<path d=" in svg

    # 3. Full enrollment -> logout -> login -> /login/mfa challenge -> recovery code single-use
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    AuthJobBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    mfa_store = InMemoryMFAStore()

    auth = RBACAuthProvider(
        roles=[Role(name="admin", permissions=frozenset({"*"}))],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="u1", username="admin@acme.dev", roles=("admin",), is_superuser=True),
                password="secret-password",
            )
        ],
    )
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "mfa-test-secret-key-thirty-two-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, mfa_store=mfa_store, auto_audit=False)
    try:
        deck.register(JobItem)

        client = app.test_client()
        assert _login(client, "admin@acme.dev", "secret-password").status_code == 302

        # Visit /_security/mfa to generate QR & secret
        setup_page = client.get("/admin/_security/mfa")
        assert setup_page.status_code == 200
        assert b"dk-qr-svg" in setup_page.data
        assert not re.search(r'\sstyle="', setup_page.data.decode())

        with client.session_transaction() as sess:
            pending_secret = str(sess["_deck_mfa_setup_secret"])

        # Activate 2FA with valid live TOTP code
        tok = _csrf(client)
        live_code = compute_totp(pending_secret)
        act_resp = client.post(
            "/admin/_security/mfa",
            data={CSRF_FORM_FIELD: tok, "action": "enable", "code": live_code},
        )
        assert act_resp.status_code == 200
        assert b"Save Your One-Time Recovery Codes" in act_resp.data
        recovery_matches = re.findall(r"[0-9A-F]{4}-[0-9A-F]{4}", act_resp.data.decode())
        assert len(recovery_matches) >= 8
        first_recovery = recovery_matches[0]

        # Logout, then login with password -> MUST redirect to /admin/login/mfa (not dashboard!)
        client.post("/admin/logout", data={CSRF_FORM_FIELD: _csrf(client)})
        step1 = _login(client, "admin@acme.dev", "secret-password")
        assert step1.status_code == 302
        assert "/admin/login/mfa" in step1.headers["Location"]
        # Dashboard still blocked before completing MFA!
        assert client.get("/admin/").status_code == 302

        # Replay same TOTP code used during activation -> rejected!
        mfa_tok = _csrf(client)
        replay_resp = client.post("/admin/login/mfa", data={CSRF_FORM_FIELD: mfa_tok, "code": live_code})
        assert replay_resp.status_code == 200
        assert b"Invalid or already-used" in replay_resp.data

        # Use single-use recovery code -> succeeds and logs in!
        ok_mfa = client.post("/admin/login/mfa", data={CSRF_FORM_FIELD: mfa_tok, "code": first_recovery})
        assert ok_mfa.status_code == 302
        assert client.get("/admin/").status_code == 200

        # Recovery code cannot be reused a second time
        assert not mfa_store.verify_and_record("u1", first_recovery)
    finally:
        deck.close()


def test_oidc_pkce_sso_flow_domain_enforcement_and_state_csrf() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    AuthJobBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    mock_profile: dict[str, Any] = {
        "sub": "okta-99",
        "email": "sre@acme.dev",
        "name": "SRE Operator",
        "groups": ["platform-admins"],
    }

    def fake_transport(
        method: str, url: str, headers: Any, body: bytes | None, timeout: float
    ) -> tuple[int, dict[str, Any]]:
        _ = (headers, timeout)
        if method == "POST" and "token" in url:
            assert body is not None and b"code_verifier=" in body
            return 200, {"access_token": "tok_live_123"}
        return 200, dict(mock_profile)

    auth = OIDCAuthProvider(
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(name="viewer", permissions=frozenset({"*:view"})),
        ],
        providers=[
            OIDCProviderConfig(
                name="okta",
                label="Okta Enterprise",
                client_id="cid-1",
                client_secret="csec-1",
                authorize_url="https://idp.acme.dev/authorize",
                token_url="https://idp.acme.dev/token",
                userinfo_url="https://idp.acme.dev/userinfo",
                role_mapping={"platform-admins": "admin"},
                superuser_groups=frozenset({"platform-admins"}),
                allowed_domains=frozenset({"acme.dev"}),
            )
        ],
        http_transport=fake_transport,
    )
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "oidc-test-secret-key-thirty-two-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, auto_audit=False, mfa_store=False)
    try:
        deck.register(JobItem)
        client = app.test_client()

        # Login page shows SSO button
        login_html = client.get("/admin/login").data.decode()
        assert "Sign in with Okta Enterprise" in login_html

        # Start SSO -> redirects with PKCE S256 & state
        start = client.get("/admin/login/sso/okta?next=/admin/job-items/")
        assert start.status_code == 302
        qs = parse_qs(urlsplit(start.headers["Location"]).query)
        assert qs["code_challenge_method"] == ["S256"]
        assert qs["state"][0]

        # Tampered state CSRF must fail (403)
        bad_cb = client.get("/admin/login/sso/okta/callback?code=abc&state=forged")
        assert bad_cb.status_code == 403

        # Fresh flow succeeds and grants superuser admin access
        start2 = client.get("/admin/login/sso/okta?next=/admin/job-items/")
        state2 = parse_qs(urlsplit(start2.headers["Location"]).query)["state"][0]
        ok_cb = client.get(f"/admin/login/sso/okta/callback?code=authcode123&state={state2}")
        assert ok_cb.status_code == 302
        assert ok_cb.headers["Location"].endswith("/admin/job-items/")
        assert client.get("/admin/job-items/").status_code == 200

        # Disallowed email domain must fail (403)
        mock_profile["email"] = "outsider@evil.org"
        c2 = app.test_client()
        st3 = parse_qs(urlsplit(c2.get("/admin/login/sso/okta").headers["Location"]).query)["state"][0]
        deny_cb = c2.get(f"/admin/login/sso/okta/callback?code=authcode999&state={st3}")
        assert deny_cb.status_code == 403
        assert b"not permitted" in deny_cb.data
    finally:
        deck.close()


def test_audited_impersonation_and_background_jobs_sse_artifact() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    AuthJobBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as sess:
        sess.add_all([JobItem(title="Batch A"), JobItem(title="Batch B")])
        sess.commit()

    class JobItemView(ModelView):
        model = JobItem

        @action("sync_bg", label="Sync Background", async_job=True)
        def sync_bg(
            self, records: list[JobItem], form_data: Any, user: Any, job_ctx: JobContext
        ) -> str:
            _ = (form_data, user)
            for idx, rec in enumerate(records, start=1):
                rec.synced = True
                job_ctx.log(f"Synced {rec.title}")
                job_ctx.set_progress(int((idx / len(records)) * 100), f"Done {idx}/{len(records)}")
            return f"Synced {len(records)} items"

    audit_store = InMemoryAuditStore()
    auth = RBACAuthProvider(
        roles=[
            Role(name="super", permissions=frozenset({"*"})),
            Role(name="support", permissions=frozenset({"*:view", "job-items:edit"})),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="adm", username="adm", roles=("super",), is_superuser=True),
                password="pw",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="adm2", username="adm2", roles=("super",), is_superuser=True),
                password="pw",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="sup", username="sup", roles=("support",)),
                password="pw",
            ),
        ],
    )
    jobs = ThreadPoolJobBackend(max_workers=2)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "imp-job-secret-key-thirty-two-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        audit_store=audit_store,
        mfa_store=False,
        job_backend=jobs,
        impersonate_read_only=True,
    )
    try:
        deck.register(JobItemView)

        client = app.test_client()
        assert _login(client, "adm", "pw").status_code == 302
        tok = _csrf(client)

        # 1. Cannot impersonate another superuser
        client.post("/admin/_impersonate/start", data={CSRF_FORM_FIELD: tok, "target_user_id": "adm2"})
        assert b"IMPERSONATING" not in client.get("/admin/").data

        # 2. Impersonate support -> banner visible + read-only guard blocks mutations!
        client.post("/admin/_impersonate/start", data={CSRF_FORM_FIELD: tok, "target_user_id": "sup"})
        dash_imp = client.get("/admin/")
        assert b"IMPERSONATING" in dash_imp.data and b"READ-ONLY" in dash_imp.data
        blocked_mut = client.post(
            "/admin/job-items/1/edit",
            data={CSRF_FORM_FIELD: _csrf(client), "title": "Should Block"},
        )
        assert blocked_mut.status_code == 403

        # Stop impersonation restores full superuser access
        client.post("/admin/_impersonate/stop", data={CSRF_FORM_FIELD: _csrf(client)})
        assert b"IMPERSONATING" not in client.get("/admin/").data

        # 3. Trigger async @action -> runs in background -> SSE stream reports 'succeeded' -> DB updated!
        act = client.post(
            "/admin/job-items/action/sync_bg",
            data={CSRF_FORM_FIELD: _csrf(client), "selected_pks": ["1", "2"]},
            follow_redirects=False,
        )
        assert act.status_code == 302
        job_id = parse_qs(urlsplit(act.headers["Location"]).query)["focus"][0]

        # Wait briefly for worker thread completion
        for _ in range(40):
            rec = jobs.get(job_id)
            if rec is not None and rec.status == "succeeded":
                break
            time.sleep(0.05)

        final_rec = jobs.get(job_id)
        assert final_rec is not None and final_rec.status == "succeeded" and final_rec.progress == 100
        sse = client.get(f"/admin/_api/jobs/{job_id}/stream")
        assert sse.status_code == 200 and "text/event-stream" in sse.content_type
        assert b'"status": "succeeded"' in sse.data

        with SessionLocal() as sess:
            assert all(it.synced for it in sess.scalars(sa.select(JobItem)).all())

        # 4. Async Background CSV Export produces RBAC-scoped downloadable artifact
        exp_job = client.post(
            "/admin/job-items/export-async",
            data={CSRF_FORM_FIELD: _csrf(client), "fmt": "csv"},
            follow_redirects=False,
        )
        assert exp_job.status_code == 302
        exp_id = parse_qs(urlsplit(exp_job.headers["Location"]).query)["focus"][0]
        for _ in range(40):
            r2 = jobs.get(exp_id)
            if r2 is not None and r2.status == "succeeded":
                break
            time.sleep(0.05)

        dl = client.get(f"/admin/_jobs/{exp_id}/artifact")
        assert dl.status_code == 200
        assert b"Batch A" in dl.data
        assert "attachment" in dl.headers["Content-Disposition"]

        # Support user cannot access admin's background job or artifact (403)
        sup_client = app.test_client()
        assert _login(sup_client, "sup", "pw").status_code == 302
        assert sup_client.get(f"/admin/_api/jobs/{exp_id}").status_code == 403
        assert sup_client.get(f"/admin/_jobs/{exp_id}/artifact").status_code == 403
    finally:
        deck.close()
