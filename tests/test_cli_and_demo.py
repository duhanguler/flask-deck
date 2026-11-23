from __future__ import annotations

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.pool import StaticPool

from flask_deck import Deck, __version__, run_security_audit
from flask_deck.cli import deck_cli, main
from flask_deck.demo import create_demo_app
from tests.conftest import SampleBase, Tenant, login_as


def test_demo_app_all_views_and_rbac_profiles() -> None:
    app = create_demo_app()
    try:
        client = app.test_client()

        # Unauthenticated request redirects to login
        r0 = client.get("/admin/", follow_redirects=False)
        assert r0.status_code == 302
        assert "/admin/login" in r0.headers["Location"]

        # Superadmin sees all models, dashboard charts, audit ledger, RBAC matrix
        login_as(client, "admin@acme.dev", "deck-demo-2026")
        for path in (
            "/admin/",
            "/admin/organizations/",
            "/admin/users/",
            "/admin/products/",
            "/admin/orders/",
            "/admin/tickets/",
            "/admin/_audit",
            "/admin/_rbac",
        ):
            resp = client.get(path)
            assert resp.status_code == 200, f"Failed on {path}"

        # Support engineer sees masked user emails
        c_sup = app.test_client()
        login_as(c_sup, "support@acme.dev", "deck-demo-2026")
        users_html = c_sup.get("/admin/users/").get_data(as_text=True)
        assert "a***@northstar.io" in users_html
        assert "ada@northstar.io" not in users_html

        # Auditor cannot open create page
        c_aud = app.test_client()
        login_as(c_aud, "viewer@acme.dev", "deck-demo-2026")
        assert c_aud.get("/admin/orders/").status_code == 200
        assert c_aud.get("/admin/orders/new").status_code == 403
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_cli_info_audit_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert f"flask-deck {__version__}" in capsys.readouterr().out

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "short"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SampleBase.metadata.create_all(engine)
    deck = Deck(app, engine=engine, allow_insecure_open=True, environment="production")
    try:
        deck.register(Tenant)

        findings = run_security_audit(app, deck)
        severities = {f["severity"] for f in findings}
        assert "CRITICAL" in severities  # OpenAuthProvider in production
        assert "WARN" in severities  # short SECRET_KEY

        runner = app.test_cli_runner()
        info_res = runner.invoke(deck_cli, ["info"])
        assert info_res.exit_code == 0
        assert "/tenants/" in info_res.output

        audit_res = runner.invoke(deck_cli, ["audit"])
        assert audit_res.exit_code == 1
        assert "[CRITICAL]" in audit_res.output
    finally:
        deck.close()
