from __future__ import annotations

import time
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from flask_login import LoginManager, UserMixin, login_user
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    BasicAuthProvider,
    Deck,
    FlaskLoginAuthProvider,
    Role,
    SecurityConfigurationError,
)
from flask_deck.auth import AUTH_IAT_KEY, AUTH_LAST_KEY
from tests.conftest import SampleBase, Tenant, extract_csrf, login_as


def test_fail_closed_in_production_without_auth_or_secret() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        SampleBase.metadata.create_all(engine)

        app_no_auth = Flask(__name__)
        app_no_auth.config["SECRET_KEY"] = "a" * 40
        app_no_auth.debug = False
        app_no_auth.testing = False

        with pytest.raises(SecurityConfigurationError, match="AuthProvider"):
            Deck(app_no_auth, engine=engine, environment="production")

        app_no_secret = Flask(__name__)
        app_no_secret.debug = False
        app_no_secret.testing = False
        auth = BasicAuthProvider.from_plain_passwords({"admin": "pw"})

        with pytest.raises(SecurityConfigurationError, match="secret_key"):
            Deck(app_no_secret, engine=engine, auth=auth, environment="production")
    finally:
        engine.dispose()


def test_rbac_four_levels_masking_scoping_and_matrix(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "alpha_editor", "alpha-password")

    # Row-level scoping: Alpha Editor sees ONLY tenant 1 (ITM-001), NEVER tenant 2 (ITM-002)!
    list_resp = client.get("/admin/items/")
    assert list_resp.status_code == 200
    html = list_resp.get_data(as_text=True)
    assert "ITM-001" in html
    assert "ITM-002" not in html

    # Field masking: email is masked as o***@alpha.io in HTML AND CSV export!
    assert "o***@alpha.io" in html
    assert "ops@alpha.io" not in html

    exp_resp = client.get("/admin/items/export.csv")
    assert exp_resp.status_code == 200
    csv_body = exp_resp.get_data(as_text=True)
    assert "o***@alpha.io" in csv_body
    assert "ops@alpha.io" not in csv_body
    assert "quantity" not in csv_body  # hidden_fields excluded from export too!
    assert "ITM-002" not in csv_body  # tenant 2 excluded from export too!

    # Delete denied by RBAC
    del_resp = client.post("/admin/items/1/delete", data={"_csrf_token": csrf})
    assert del_resp.status_code == 403

    # RBAC Policy Matrix page
    matrix = client.get("/admin/_rbac")
    assert matrix.status_code == 200
    assert "tenant_editor" in matrix.get_data(as_text=True)


def test_session_idle_and_absolute_timeouts(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    login_as(client, "admin", "admin-password")

    # Expire idle timestamp in session -> redirected back to login
    with client.session_transaction() as sess:
        sess[AUTH_LAST_KEY] = int(time.time()) - 99999
    resp = client.get("/admin/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]

    # Re-login and expire absolute timestamp
    login_as(client, "admin", "admin-password")
    with client.session_transaction() as sess:
        sess[AUTH_IAT_KEY] = int(time.time()) - 99999
    resp2 = client.get("/admin/", follow_redirects=False)
    assert resp2.status_code == 302


def test_read_only_mode_blocks_all_mutations() -> None:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "ro-secret-key-at-least-thirty-two-bytes!!"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SampleBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as sess:
        sess.add(Tenant(name="RO Corp", slug="ro-corp"))
        sess.commit()

    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        allow_insecure_open=True,
        read_only=True,
    )
    try:
        deck.register(Tenant)

        client = app.test_client()
        page = client.get("/admin/tenants/")
        assert page.status_code == 200
        assert "READ-ONLY" in page.get_data(as_text=True)
        csrf = extract_csrf(page.get_data(as_text=True))

        create = client.post(
            "/admin/tenants/new",
            data={"_csrf_token": csrf, "name": "Blocked", "slug": "blocked"},
        )
        assert create.status_code == 403
    finally:
        deck.close()


def test_flask_login_auth_provider_integration() -> None:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "flask-login-secret-key-thirty-two-bytes!!"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SampleBase.metadata.create_all(engine)

    lm = LoginManager(app)

    class DemoLoginUser(UserMixin):
        def __init__(self, uid: str) -> None:
            self.id = uid
            self.username = "fl_user"
            self.roles = ("viewer",)

    @lm.user_loader
    def _load(uid: str) -> DemoLoginUser:
        return DemoLoginUser(uid)

    @app.route("/force-login")
    def _force_login() -> str:
        login_user(DemoLoginUser("42"))
        return "ok"

    auth = FlaskLoginAuthProvider(roles=[Role(name="viewer", permissions=frozenset({"*:view"}))])
    deck = Deck(app, engine=engine, auth=auth)
    try:
        deck.register(Tenant)

        client = app.test_client()
        assert client.get("/admin/").status_code == 403

        client.get("/force-login")
        assert client.get("/admin/tenants/").status_code == 200
    finally:
        deck.close()
