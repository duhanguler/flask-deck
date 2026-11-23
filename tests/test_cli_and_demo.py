from __future__ import annotations

import re

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


def test_demo_app_showcase_profile_all_v04_pages_and_csp() -> None:
    inline_style_re = re.compile(r"\bstyle\s*=", re.IGNORECASE)
    inline_handler_re = re.compile(
        r"\bon(?:click|change|submit|load|error|mouseover|focus)\s*=", re.IGNORECASE
    )

    app = create_demo_app(seed_profile="showcase")
    deck: Deck = app.extensions["flask_deck"]["deck"]
    try:
        assert deck.adapter is not None
        engine = deck.adapter.get_engine()
        with engine.connect() as conn:
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_organizations")).scalar_one()) >= 30
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_users")).scalar_one()) >= 45
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_products")).scalar_one()) >= 18
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_orders")).scalar_one()) >= 100
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_tickets")).scalar_one()) >= 35
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_infrastructure_nodes")).scalar_one()) >= 20

        assert deck.audit_store is not None
        assert deck.audit_store.verify_chain() == (True, None)
        audit_entries, audit_total = deck.audit_store.list_entries(limit=100)
        assert audit_total >= 30
        assert len(audit_entries) >= 30

        assert deck.approval_store is not None
        assert deck.approval_store.pending_count() >= 4
        assert deck.saved_query_store is not None
        assert len(deck.saved_query_store.list_queries(limit=50)) >= 6
        assert deck.api_key_store is not None
        assert len(deck.api_key_store.list_keys(limit=50)) >= 4
        assert deck.webhook_delivery_store is not None
        assert len(deck.webhook_delivery_store.list_deliveries(limit=50)) >= 8
        assert deck.job_backend is not None
        assert len(deck.job_backend.list_jobs(limit=50)) >= 5

        client = app.test_client()
        login_as(client, "admin@acme.dev", "deck-demo-2026")
        showcase_paths = (
            "/admin/",
            "/admin/organizations/",
            "/admin/users/",
            "/admin/products/?view=gallery",
            "/admin/orders/?view=calendar",
            "/admin/tickets/?view=board",
            "/admin/tickets/?trashed=1",
            "/admin/infrastructure/?view=tree",
            "/admin/infrastructure/1/edit",
            "/admin/_approvals",
            "/admin/_audit",
            "/admin/_sql",
            "/admin/_jobs",
            "/admin/_webhooks",
            "/admin/_security/api-keys",
            "/admin/_schema",
            "/admin/_diagnostics",
            "/admin/_page/sla-monitor",
        )
        for path in showcase_paths:
            resp = client.get(path)
            assert resp.status_code == 200, f"Unexpected status {resp.status_code} on {path}"
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'none'" in csp
            assert "style-src 'self'" in csp
            assert "unsafe-inline" not in csp
            html = resp.get_data(as_text=True)
            assert not inline_style_re.search(html), f"Inline style= leaked on {path}"
            assert not inline_handler_re.search(html), f"Inline event handler leaked on {path}"
    finally:
        deck.close()
