from __future__ import annotations

import re
from dataclasses import replace

import sqlalchemy as sa

from flask_deck.charts import (
    render_gauge_chart,
    render_grouped_bar_chart,
    render_heatmap_chart,
    render_stat_bars,
)
from flask_deck.demo import create_demo_app
from flask_deck.sql_console import execute_readonly_sql, validate_readonly_sql
from tests.conftest import extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\bstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\bon(?:click|change|submit|load|error|mouseover|focus)\s*=", re.IGNORECASE)


def test_v02_all_new_pages_strict_csp_and_zero_inline_styles() -> None:
    app = create_demo_app()
    try:
        client = app.test_client()
        login_as(client, "admin@acme.dev", "deck-demo-2026")

        pages = [
            "/admin/?range=7d",
            "/admin/?range=30d",
            "/admin/?range=90d",
            "/admin/tickets/?view=board",
            "/admin/orders/?view=board",
            "/admin/orders/",
            "/admin/products/1/edit",
            "/admin/tickets/1/edit",
            "/admin/orders/1/edit",
            "/admin/products/new?clone=1",
            "/admin/_schema",
            "/admin/_diagnostics",
            "/admin/_sql",
            "/admin/_page/sla-monitor",
        ]
        for url in pages:
            resp = client.get(url)
            assert resp.status_code == 200, f"Unexpected status on {url}"
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'none'" in csp
            assert "style-src 'self'" in csp
            assert "unsafe-inline" not in csp
            html = resp.get_data(as_text=True)
            assert not _INLINE_STYLE_RE.search(html), f"Inline style= leaked on {url}"
            assert not _INLINE_HANDLER_RE.search(html), f"Inline event handler leaked on {url}"
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_kanban_board_drag_drop_rbac_and_aggregates() -> None:
    app = create_demo_app()
    try:
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")

        # Board view renders draggable cards for superadmin
        board = client.get("/admin/tickets/?view=board")
        assert board.status_code == 200
        bhtml = board.get_data(as_text=True)
        assert "dk-kanban-board" in bhtml
        assert 'draggable="true"' in bhtml
        assert "OPS-412" in bhtml

        # Drag-drop PATCH changes ticket status
        patch = client.patch(
            "/admin/_api/tickets/1/quick-edit",
            json={"field": "status", "value": "resolved"},
            headers={"X-Deck-CSRFToken": csrf},
        )
        assert patch.status_code == 200
        assert patch.get_json()["value"] == "resolved"

        # Table view shows Page Summary aggregation footer + copyable chips + saved views
        tbl = client.get("/admin/orders/")
        assert tbl.status_code == 200
        thtml = tbl.get_data(as_text=True)
        assert "Page Summary" in thtml
        assert "data-deck-copy=" in thtml
        assert "High Value" in thtml

        # Read-only auditor sees non-draggable Kanban cards and cannot PATCH
        aud = app.test_client()
        aud_csrf = login_as(aud, "viewer@acme.dev", "deck-demo-2026")
        aud_board = aud.get("/admin/tickets/?view=board")
        assert aud_board.status_code == 200
        assert 'draggable="true"' not in aud_board.get_data(as_text=True)
        denied = aud.patch(
            "/admin/_api/tickets/1/quick-edit",
            json={"field": "status", "value": "closed"},
            headers={"X-Deck-CSRFToken": aud_csrf},
        )
        assert denied.status_code == 403
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_parameterized_action_modal_and_clone_prefill() -> None:
    app = create_demo_app()
    try:
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")

        # Missing required 'reason' field on escalate action -> blocked cleanly
        missing = client.post(
            "/admin/tickets/action/escalate",
            data={"_csrf_token": csrf, "selected_pks": ["3"], "priority": "critical", "reason": ""},
            follow_redirects=True,
        )
        assert "requires" in missing.get_data(as_text=True)

        # Valid parameterized action succeeds & logs parameters to Audit Ledger
        ok = client.post(
            "/admin/tickets/action/escalate",
            data={
                "_csrf_token": csrf,
                "selected_pks": ["3"],
                "priority": "critical",
                "reason": "Customer SLA window closing",
            },
            follow_redirects=True,
        )
        assert "Escalated 1 ticket(s) to critical (Customer SLA window closing)." in ok.get_data(as_text=True)

        # Clone pre-fills non-unique fields (name) while omitting unique sku and PK
        clone = client.get("/admin/products/new?clone=1")
        assert clone.status_code == 200
        chtml = clone.get_data(as_text=True)
        assert "Dedicated H200 8x Cluster Node" in chtml
        assert 'value="GPU-H200-8X"' not in chtml

        # 3-tab drawer renders Relations + Audit tabs cleanly
        drawer = client.get("/admin/_api/orders/1/drawer")
        assert drawer.status_code == 200
        dhtml = drawer.get_data(as_text=True)
        assert "Relations" in dhtml
        assert "Clone" in dhtml
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_sql_console_firewall_redaction_and_adversarial_blocks() -> None:
    app = create_demo_app()
    try:
        deck = app.extensions["flask_deck"]["deck"]
        assert deck.adapter is not None
        engine = deck.adapter.get_engine()

        # Adversarial mutating / stacked / comment-obfuscated / PRAGMA queries MUST be rejected!
        evil_queries = [
            "DROP TABLE demo_users",
            "DELETE FROM demo_users",
            "UPDATE demo_users SET role = 'owner'",
            "INSERT INTO demo_users (full_name, email, organization_id) VALUES ('x','x@x.com',1)",
            "SELECT 1; DROP TABLE demo_users",
            "/* bypass */ DELETE FROM demo_users",
            "-- comment\nALTER TABLE demo_users ADD COLUMN pwn TEXT",
            "PRAGMA table_info(demo_users)",
            "ATTACH DATABASE '/tmp/pwn.db' AS pwn",
            "WITH d AS (DELETE FROM demo_users) SELECT * FROM d",
        ]
        for bad in evil_queries:
            res = execute_readonly_sql(engine, bad)
            assert res.error is not None, f"SQL firewall failed to block: {bad}"

        # Valid SELECT automatically redacts password_hash & api_token!
        good = execute_readonly_sql(
            engine,
            "SELECT id, full_name, password_hash, api_token FROM demo_users ORDER BY id LIMIT 3",
        )
        assert good.error is None
        assert good.row_count == 3
        assert set(good.redacted_columns) == {"password_hash", "api_token"}
        for row in good.rows:
            assert row[2] == "[REDACTED]"
            assert row[3] == "[REDACTED]"

        # HTTP route test: superadmin runs query & exports CSV, auditor gets 403
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")
        post = client.post(
            "/admin/_sql",
            data={
                "_csrf_token": csrf,
                "sql": "SELECT id, email, password_hash FROM demo_users LIMIT 2",
                "output": "table",
            },
        )
        assert post.status_code == 200
        html = post.get_data(as_text=True)
        assert "[REDACTED]" in html
        assert "pbkdf2:sha256:redacted" not in html

        csv_post = client.post(
            "/admin/_sql",
            data={
                "_csrf_token": csrf,
                "sql": "SELECT '=CMD|calc' AS danger_cell",
                "output": "csv",
            },
        )
        assert csv_post.status_code == 200
        assert "'=CMD|calc" in csv_post.get_data(as_text=True)

        # Auditor lacks sql:query permission -> HTTP 403
        aud = app.test_client()
        login_as(aud, "viewer@acme.dev", "deck-demo-2026")
        assert aud.get("/admin/_sql").status_code == 403

        # Verify validate_readonly_sql accepts WITH CTE & EXPLAIN cleanly
        assert validate_readonly_sql("WITH t AS (SELECT 1 AS n) SELECT * FROM t;").startswith("WITH")
        assert validate_readonly_sql("EXPLAIN QUERY PLAN SELECT 1").startswith("EXPLAIN")
        with engine.connect() as conn:
            assert int(conn.execute(sa.text("SELECT COUNT(*) FROM demo_users")).scalar_one()) == 8
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_demo_role_switcher_and_production_lockout() -> None:
    app = create_demo_app()
    try:
        deck = app.extensions["flask_deck"]["deck"]
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")

        # Switch to support role via CSRF-protected POST -> emails immediately masked!
        sw = client.post(
            "/admin/_demo/switch-role",
            data={"_csrf_token": csrf, "account_id": "support", "next": "/admin/users/"},
            follow_redirects=True,
        )
        assert sw.status_code == 200
        body = sw.get_data(as_text=True)
        assert "a***@northstar.io" in body
        assert "ada@northstar.io" not in body

        # Lazy notifications endpoint works cleanly
        notif = client.get("/admin/_api/notifications")
        assert notif.status_code == 200
        assert "items" in notif.get_json()

        # In production environment, demo role switcher MUST return 404!
        deck.config = replace(deck.config, environment="production")
        new_csrf = extract_csrf(body)
        blocked = client.post(
            "/admin/_demo/switch-role",
            data={"_csrf_token": new_csrf, "account_id": "admin"},
        )
        assert blocked.status_code == 404
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_v02_svg_widgets_escape_xss_and_zero_inline_styles() -> None:
    xss = '<script>alert("xss")</script>'
    outputs = [
        str(render_heatmap_chart([(xss, 4), ("2026-11-21", 8)], unit=xss)),
        str(render_grouped_bar_chart([xss, "B"], [{"name": xss, "data": [5, 10], "tone": "ok"}])),
        str(render_stat_bars([{"label": xss, "value": 42, "max": 50, "meta": xss, "tone": "warn"}])),
        str(render_gauge_chart(88.5, label=xss, tone="ok")),
    ]
    for out in outputs:
        assert "<svg" in out
        assert "<script>" not in out
        assert "style=" not in out
