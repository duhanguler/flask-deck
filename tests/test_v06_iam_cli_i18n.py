from __future__ import annotations

import html
import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    ComplexityValidator,
    Deck,
    DeckUser,
    InMemoryAuditStore,
    InMemorySessionStore,
    ModelView,
    SQLAlchemyAuthProvider,
    UserAttributeSimilarityValidator,
    validate_password_strength,
)
from flask_deck.cli import deck_cli
from tests.conftest import Item, SampleBase, Tenant, extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"""\sstyle\s*=\s*["']""", re.IGNORECASE)
_INLINE_EVENT_RE = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.IGNORECASE)


def _assert_strict_csp_html(body: str) -> None:
    assert not _INLINE_STYLE_RE.search(body), "Inline style= attribute detected!"
    assert not _INLINE_EVENT_RE.search(body), "Inline on*= event handler detected!"


@pytest.fixture()
def iam2_bundle() -> Iterator[
    tuple[
        Flask,
        Deck,
        SQLAlchemyAuthProvider,
        InMemorySessionStore,
        InMemoryAuditStore,
        list[tuple[str, str, str]],
        sa.Engine,
    ]
]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "v06-iam2-test-secret-key-at-least-32-bytes"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SampleBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as sess:
        t1 = Tenant(name="Acme", slug="acme")
        sess.add(t1)
        sess.flush()
        sess.add(Item(code="IT-1", title="Monitor", email="m@acme.dev", tenant_id=t1.id))
        sess.commit()

    auth = SQLAlchemyAuthProvider(engine, password_min_length=8)
    g_admin = auth.create_group(name="admins", label="Admins", permissions=("*",))
    g_iam = auth.create_group(name="iam_mgr", label="IAM Manager", permissions=("iam:manage",))
    g_viewer = auth.create_group(name="viewers", label="Viewers", permissions=("tenants:view",))

    auth.create_user(
        user_id="root",
        username="root",
        email="root@acme.dev",
        password="root-password-123",
        display_name="Root Admin",
        is_superuser=True,
        group_ids=[g_admin.id],
    )
    auth.create_user(
        user_id="mgr1",
        username="iammanager",
        email="mgr@acme.dev",
        password="mgr-password-123",
        display_name="IAM Manager",
        is_superuser=False,
        group_ids=[g_iam.id],
    )
    auth.create_user(
        user_id="u_direct",
        username="directuser",
        email="direct@acme.dev",
        password="direct-password-123",
        display_name="Direct Perm User",
        is_superuser=False,
        group_ids=[g_viewer.id],
        direct_permissions=("items:view",),
    )
    # Seed extra users for pagination
    for i in range(1, 28):
        auth.create_user(
            username=f"bulkuser{i:02d}",
            email=f"bulk{i:02d}@acme.dev",
            password="bulk-password-123",
            display_name=f"Bulk User {i:02d}",
            is_active=(i % 2 == 1),
            group_ids=[g_viewer.id],
        )

    class ItemView(ModelView):
        model = Item
        slug = "items"

    sess_store = InMemorySessionStore()
    audit_store = InMemoryAuditStore()
    sent_resets: list[tuple[str, str, str]] = []

    def _notifier(user: DeckUser, reset_url: str, raw_token: str) -> None:
        sent_resets.append((user.username, reset_url, raw_token))

    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        session_store=sess_store,
        audit_store=audit_store,
        password_reset_notifier=_notifier,
    )
    deck.register(Tenant, ItemView)
    yield app, deck, auth, sess_store, audit_store, sent_resets, engine
    deck.close()
    engine.dispose()


def test_password_validators_default_and_strict() -> None:
    # Default rejects short, numeric-only, and common passwords, accepts normal strong ones
    assert validate_password_strength("short")
    assert validate_password_strength("123456789")
    assert validate_password_strength("password123")
    assert validate_password_strength("root-password-123") == []

    # Strict validators enforce attribute similarity and character complexity
    strict_vals = (UserAttributeSimilarityValidator(), ComplexityValidator())
    assert validate_password_strength(
        "alice_admin_2026!", validators=strict_vals, username="alice_admin", email="alice@acme.dev"
    )
    assert validate_password_strength("alllowercase123", validators=strict_vals)
    assert validate_password_strength("Strong!Pass2026", validators=strict_vals, username="alice") == []


def test_iam_2_0_search_pagination_bulk_and_direct_permissions(
    iam2_bundle: tuple[
        Flask,
        Deck,
        SQLAlchemyAuthProvider,
        InMemorySessionStore,
        InMemoryAuditStore,
        list[tuple[str, str, str]],
        sa.Engine,
    ],
) -> None:
    app, _deck, auth, _sess_store, audit_store, _resets, _eng = iam2_bundle

    # Direct permissions grant items:view without group membership
    c_dir = app.test_client()
    login_as(c_dir, "directuser", "direct-password-123")
    assert c_dir.get("/admin/items/").status_code == 200
    assert c_dir.get("/admin/items/new").status_code == 403

    # Non-superuser IAM manager CANNOT grant '*' or 'iam:manage' via direct_permissions or bulk-edit superuser
    c_mgr = app.test_client()
    mgr_csrf = login_as(c_mgr, "iammanager", "mgr-password-123")
    r_esc = c_mgr.post(
        "/admin/_security/users/create",
        data={
            "_csrf_token": mgr_csrf,
            "username": "escalator",
            "password": "esc-password-123",
            "is_active": "1",
            "direct_permissions": "*\nitems:view",
        },
    )
    assert r_esc.status_code == 403

    r_bulk_su = c_mgr.post(
        "/admin/_security/users/bulk",
        data={"_csrf_token": mgr_csrf, "action": "deactivate", "user_ids": ["root"]},
    )
    assert r_bulk_su.status_code == 403

    # Superuser paginated & filtered /_security/users
    c_root = app.test_client()
    root_csrf = login_as(c_root, "root", "root-password-123")
    r_p1 = c_root.get("/admin/_security/users")
    assert r_p1.status_code == 200
    html_p1 = r_p1.get_data(as_text=True)
    _assert_strict_csp_html(html_p1)
    assert "dk-pag-num is-active" in html_p1
    assert "page=2" in html_p1

    # Search q=directuser + status filter (inspect users table body, excluding sidebar impersonate select)
    html_q = c_root.get("/admin/_security/users?q=directuser").get_data(as_text=True)
    table_q = html_q.split("<table", 1)[1]
    assert "directuser" in table_q
    assert "bulkuser01" not in table_q

    html_su = c_root.get("/admin/_security/users?status=superuser").get_data(as_text=True)
    table_su = html_su.split("<table", 1)[1]
    assert "root" in table_su
    assert "directuser" not in table_su

    # Bulk deactivate last active superuser is blocked safely
    r_last_su = c_root.post(
        "/admin/_security/users/bulk",
        data={"_csrf_token": root_csrf, "action": "deactivate", "user_ids": ["root"]},
        follow_redirects=True,
    )
    assert "last active superuser" in r_last_su.get_data(as_text=True).lower()
    assert auth.get_user_record("root").is_active is True  # type: ignore[union-attr]

    # Bulk deactivate regular user revokes active sessions and logs audit
    r_deact = c_root.post(
        "/admin/_security/users/bulk",
        data={"_csrf_token": root_csrf, "action": "deactivate", "user_ids": ["u_direct"]},
        follow_redirects=True,
    )
    assert "Deactivated 1 user" in r_deact.get_data(as_text=True)
    assert c_dir.get("/admin/items/").status_code == 302  # session revoked!
    entries, _ = audit_store.list_entries(limit=20)
    assert any(e.action == "iam.users_bulk_deactivate" for e in entries)


def test_forgot_password_opt_in_security_anti_enumeration_single_use_and_expiry(
    iam2_bundle: tuple[
        Flask,
        Deck,
        SQLAlchemyAuthProvider,
        InMemorySessionStore,
        InMemoryAuditStore,
        list[tuple[str, str, str]],
        sa.Engine,
    ],
) -> None:
    app, _deck, auth, _sess_store, audit_store, sent_resets, engine = iam2_bundle

    # Existing active session for directuser (will be revoked after reset!)
    c_victim = app.test_client()
    login_as(c_victim, "directuser", "direct-password-123")
    assert c_victim.get("/admin/items/").status_code == 200

    # Login page shows Forgot password? link and strict CSP HTML
    c_anon = app.test_client()
    login_html = c_anon.get("/admin/login").get_data(as_text=True)
    assert "/admin/login/forgot-password" in login_html
    _assert_strict_csp_html(login_html)

    r_fp_get = c_anon.get("/admin/login/forgot-password")
    assert r_fp_get.status_code == 200
    fp_html = r_fp_get.get_data(as_text=True)
    _assert_strict_csp_html(fp_html)
    fp_csrf = extract_csrf(fp_html)

    # Anti-enumeration: identical status & message for non-existent vs real user
    r_ghost = c_anon.post(
        "/admin/login/forgot-password",
        data={"_csrf_token": fp_csrf, "identifier": "ghost@nowhere.dev"},
    )
    r_real = c_anon.post(
        "/admin/login/forgot-password",
        data={"_csrf_token": fp_csrf, "identifier": "direct@acme.dev"},
    )
    assert r_ghost.status_code == 200 and r_real.status_code == 200
    assert "single-use password reset link" in r_ghost.get_data(as_text=True)
    assert "single-use password reset link" in r_real.get_data(as_text=True)
    assert len(sent_resets) == 1
    uname, _url, raw_token = sent_resets[0]
    assert uname == "directuser"

    # Raw token is NEVER stored in DB (only SHA-256 hash)
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT token_hash FROM _flask_deck_password_resets")).fetchall()
        assert len(rows) == 1
        assert rows[0][0] != raw_token
        assert len(rows[0][0]) == 64

    # Reset page renders with strict CSP, rejects weak password, then accepts strong password
    r_rp = c_anon.get(f"/admin/login/reset-password/{raw_token}")
    assert r_rp.status_code == 200
    rp_html = r_rp.get_data(as_text=True)
    _assert_strict_csp_html(rp_html)
    rp_csrf = extract_csrf(rp_html)

    r_weak = c_anon.post(
        f"/admin/login/reset-password/{raw_token}",
        data={"_csrf_token": rp_csrf, "new_password": "password", "confirm_password": "password"},
    )
    assert r_weak.status_code == 200
    assert "too common" in r_weak.get_data(as_text=True).lower()

    r_done = c_anon.post(
        f"/admin/login/reset-password/{raw_token}",
        data={
            "_csrf_token": rp_csrf,
            "new_password": "brand-new-secure-99",
            "confirm_password": "brand-new-secure-99",
        },
        follow_redirects=False,
    )
    assert r_done.status_code == 302
    assert r_done.headers["Location"].endswith("/admin/login")

    # Single-use replay rejected!
    r_replay = c_anon.get(f"/admin/login/reset-password/{raw_token}")
    assert "invalid, expired, or has already been used" in r_replay.get_data(as_text=True)

    # All prior active sessions for directuser were revoked!
    assert c_victim.get("/admin/items/").status_code == 302
    # New password works!
    login_as(c_victim, "directuser", "brand-new-secure-99")
    assert c_victim.get("/admin/items/").status_code == 200

    # Expired token rejected
    issued2 = auth.create_password_reset_token("directuser", ttl_seconds=60)
    assert issued2 is not None
    _, tok2 = issued2
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    with engine.begin() as conn:
        conn.execute(sa.update(auth._password_resets_tbl).values(expires_at=past))
    assert auth.verify_password_reset_token(tok2) is None

    # Audit trail captured both request & completion
    entries, _ = audit_store.list_entries(limit=30)
    actions = {e.action for e in entries}
    assert "password_reset_requested" in actions
    assert "password_reset_completed" in actions

    # Forgot password disabled (404) when password_reset_notifier is NOT provided
    app_off = Flask(__name__)
    app_off.config["SECRET_KEY"] = "off-secret-key-at-least-32-characters-long"
    d_off = Deck(app_off, session_factory=sessionmaker(bind=engine), engine=engine, auth=auth)
    assert app_off.test_client().get("/admin/login/forgot-password").status_code == 404
    d_off.close()


def test_cli_createsuperuser_changepassword_and_jsi18n_locales(
    iam2_bundle: tuple[
        Flask,
        Deck,
        SQLAlchemyAuthProvider,
        InMemorySessionStore,
        InMemoryAuditStore,
        list[tuple[str, str, str]],
        sa.Engine,
    ],
) -> None:
    app, _deck, auth, _sess_store, _audit, _resets, _eng = iam2_bundle
    runner = app.test_cli_runner()

    res_create = runner.invoke(
        deck_cli,
        [
            "createsuperuser",
            "--username",
            "cliadmin",
            "--email",
            "cli@acme.dev",
            "--password",
            "cli-strong-pass-99",
            "--no-input",
        ],
    )
    assert res_create.exit_code == 0, res_create.output
    assert "cliadmin" in res_create.output and "created" in res_create.output.lower()
    created_u = auth.authenticate("cliadmin", "cli-strong-pass-99")
    assert created_u is not None and created_u.is_superuser is True

    res_chpw = runner.invoke(
        deck_cli,
        ["changepassword", "cliadmin", "--password", "cli-rotated-pass-77"],
    )
    assert res_chpw.exit_code == 0, res_chpw.output
    assert auth.authenticate("cliadmin", "cli-strong-pass-99") is None
    assert auth.authenticate("cliadmin", "cli-rotated-pass-77") is not None

    # Verify strict-CSP jsi18n <meta name="deck-i18n"> updates dynamically when locale switches to TR
    c = app.test_client()
    csrf = login_as(c, "cliadmin", "cli-rotated-pass-77")
    r_tr = c.post(
        "/admin/_preferences",
        data={"_csrf_token": csrf, "locale": "tr", "timezone": "Europe/Istanbul", "next": "/admin/"},
        follow_redirects=True,
    )
    assert r_tr.status_code == 200
    body = r_tr.get_data(as_text=True)
    _assert_strict_csp_html(body)
    m = re.search(r'<meta name="deck-i18n" content="([^"]+)"', body)
    assert m is not None
    catalog = json.loads(html.unescape(m.group(1)))
    assert catalog["Saved"] == "Kaydedildi"
    assert catalog["Today"] == "Bugün"
    assert catalog["Load more…"] == "Daha fazla yükle…"
