from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    InMemoryAuditStore,
    InMemorySessionStore,
    ModelView,
    SQLAlchemyAuthProvider,
)
from flask_deck.demo import create_demo_app, reset_demo_app
from tests.conftest import Item, SampleBase, Tenant, extract_csrf, login_as


@pytest.fixture()
def iam_bundle() -> Iterator[tuple[Flask, Deck, SQLAlchemyAuthProvider, InMemorySessionStore, InMemoryAuditStore]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "iam-test-secret-key-with-at-least-32-bytes"
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
        sess.add(Item(code="I-1", title="Box", email="box@acme.dev", tenant_id=t1.id))
        sess.commit()

    auth = SQLAlchemyAuthProvider(engine, password_min_length=8)
    g_ops = auth.create_group(
        name="ops",
        label="Ops",
        permissions=("items:view", "items:edit", "tenants:view"),
        masked_fields={"items": ("email",)},
        readonly_fields={"items": ("code",)},
        hidden_fields={"items": ("price",)},
    )
    g_admin = auth.create_group(name="admins", label="Admins", permissions=("*",))
    auth.create_user(
        user_id="root",
        username="root",
        password="root-password-123",
        display_name="Root",
        is_superuser=True,
        group_ids=[g_admin.id],
    )
    auth.create_user(
        user_id="op1",
        username="operator",
        password="operator-password-123",
        display_name="Operator",
        is_superuser=False,
        group_ids=[g_ops.id],
    )

    class ItemIAMView(ModelView):
        model = Item
        slug = "items"

    sess_store = InMemorySessionStore()
    audit_store = InMemoryAuditStore()
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        session_store=sess_store,
        audit_store=audit_store,
    )
    deck.register(Tenant, ItemIAMView)
    yield app, deck, auth, sess_store, audit_store
    deck.close()
    engine.dispose()


def test_m5_sqlalchemy_auth_rbac_last_superuser_and_sessions(
    iam_bundle: tuple[Flask, Deck, SQLAlchemyAuthProvider, InMemorySessionStore, InMemoryAuditStore],
) -> None:
    app, _, auth, _sess_store, audit_store = iam_bundle

    # Case-insensitive login + 4-level RBAC enforcement
    c_op1 = app.test_client()
    c_op2 = app.test_client()
    login_as(c_op1, "OPERATOR", "operator-password-123")
    op_csrf2 = login_as(c_op2, "operator", "operator-password-123")

    items_html = c_op1.get("/admin/items/").get_data(as_text=True)
    assert "b***@acme.dev" in items_html
    assert "box@acme.dev" not in items_html
    assert c_op1.get("/admin/_security/users").status_code == 403

    # Self-service password change rotates session and revokes other active session
    assert c_op2.get("/admin/_security/password").status_code == 200
    bad_pw = c_op2.post(
        "/admin/_security/password",
        data={
            "_csrf_token": op_csrf2,
            "current_password": "wrong",
            "new_password": "new-password-456",
            "confirm_password": "new-password-456",
        },
        follow_redirects=True,
    )
    assert "incorrect" in bad_pw.get_data(as_text=True)

    ok_pw = c_op2.post(
        "/admin/_security/password",
        data={
            "_csrf_token": op_csrf2,
            "current_password": "operator-password-123",
            "new_password": "new-password-456",
            "confirm_password": "new-password-456",
        },
        follow_redirects=False,
    )
    assert ok_pw.status_code == 302
    assert c_op2.get("/admin/").status_code == 200
    # First session (`c_op1`) must have been revoked immediately!
    assert c_op1.get("/admin/", follow_redirects=False).status_code == 302

    # Audit ledger must NOT contain plaintext new password
    assert all("new-password-456" not in str(e.metadata) for e in audit_store.list_entries()[0])

    # Last-active-superuser protection at provider level
    with pytest.raises(ValueError, match="last active superuser"):
        auth.update_user("root", is_superuser=False)
    with pytest.raises(ValueError, match="last active superuser"):
        auth.update_user("root", is_active=False)
    with pytest.raises(ValueError, match="last active superuser"):
        auth.delete_user("root")

    # Root UI: /_security/users & /_security/groups strict CSP & CRUD + reset revokes session
    c_root = app.test_client()
    r_csrf = login_as(c_root, "root", "root-password-123")
    inline_style_re = re.compile(r"\bstyle\s*=", re.IGNORECASE)
    for sec_path in (
        "/admin/_security/users",
        "/admin/_security/groups",
        "/admin/_security/password",
    ):
        resp = c_root.get(sec_path)
        assert resp.status_code == 200
        assert not inline_style_re.search(resp.get_data(as_text=True))

    # Create user & group via UI
    g_post = c_root.post(
        "/admin/_security/groups/create",
        data={
            "_csrf_token": r_csrf,
            "name": "auditors",
            "label": "Auditors",
            "perm": ["items:view", "audit:view"],
            "hidden_fields_json": "{}",
            "readonly_fields_json": "{}",
            "masked_fields_json": '{"items":["email"]}',
        },
        follow_redirects=False,
    )
    assert g_post.status_code == 302
    created_g = auth.get_group_by_name("auditors")
    assert created_g is not None and "audit:view" in created_g.permissions

    # Admin resets operator password -> c_op2 session revoked immediately!
    rst = c_root.post(
        "/admin/_security/users/op1/reset-password",
        data={"_csrf_token": r_csrf, "new_password": "admin-reset-password-789"},
        follow_redirects=False,
    )
    assert rst.status_code == 302
    assert c_op2.get("/admin/", follow_redirects=False).status_code == 302

    # Deactivated operator cannot log in
    c_root.post(
        "/admin/_security/users/op1/update",
        data={
            "_csrf_token": r_csrf,
            "display_name": "Disabled Op",
            "email": "op@acme.dev",
            "group_ids": [],
        },
        follow_redirects=False,
    )
    assert auth.authenticate("operator", "admin-reset-password-789") is None


def test_m5_demo_app_db_iam_ephemeral_sessions_role_switch_and_reset() -> None:
    app = create_demo_app(stateless_ephemeral_sessions=True, auto_daily_reset=True)
    deck: Deck = app.extensions["flask_deck"]["deck"]
    try:
        assert isinstance(deck.auth, SQLAlchemyAuthProvider)
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")

        # Live IAM pages + ephemeral serverless session hydration work seamlessly
        assert client.get("/admin/_security/users").status_code == 200
        assert client.get("/admin/_security/groups").status_code == 200
        assert client.get("/admin/_security/password").status_code == 200
        assert client.get("/admin/_security/sessions").status_code == 200

        # Create a custom user, then verify reset_demo_app wipes it and restores the 3 seeded accounts
        client.post(
            "/admin/_security/users/create",
            data={
                "_csrf_token": csrf,
                "username": "temp@acme.dev",
                "password": "temp-password-123",
                "is_active": "1",
            },
            follow_redirects=False,
        )
        assert any(u.username == "temp@acme.dev" for u in deck.auth.list_users())

        # Demo role switcher works with SQLAlchemyAuthProvider demo_account_ids and rejects fake IDs
        sw = client.post(
            "/admin/_demo/switch-role",
            data={"_csrf_token": csrf, "account_id": "support", "next": "/admin/users/"},
            follow_redirects=False,
        )
        assert sw.status_code == 302
        fresh_csrf = extract_csrf(client.get("/admin/users/").get_data(as_text=True))
        bad_sw = client.post(
            "/admin/_demo/switch-role",
            data={"_csrf_token": fresh_csrf, "account_id": "nonexistent"},
            follow_redirects=False,
        )
        assert bad_sw.status_code == 404

        reset_demo_app(app, force=True)
        usernames = {u.username for u in deck.auth.list_users()}
        assert usernames == {"admin@acme.dev", "support@acme.dev", "viewer@acme.dev"}
    finally:
        deck.close()
