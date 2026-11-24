from __future__ import annotations

import io
import re
from typing import Any

import sqlalchemy as sa

from flask_deck import Deck, build_api_key_record
from flask_deck.demo import (
    Organization,
    SupportTicket,
    create_demo_app,
)
from flask_deck.iam import SQLAlchemyAuthProvider
from flask_deck.security import mask_ip_address
from tests.conftest import login_as

_INLINE_STYLE_RE = re.compile(r"\bstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(
    r"\bon(?:click|change|submit|load|error|mouseover|focus)\s*=", re.IGNORECASE
)


def test_mask_ip_address_helper() -> None:
    assert mask_ip_address("127.0.0.1") == "127.0.xxx.xxx"
    assert mask_ip_address("203.0.113.42") == "203.0.xxx.xxx"
    assert mask_ip_address("2001:db8:85a3::8a2e:370:7334") == "2001:0db8::xxxx"
    assert mask_ip_address("") == "redacted"
    assert mask_ip_address("not-an-ip") == "redacted"


def test_vercel_entrypoint_enables_demo_safe_mode_by_default() -> None:
    import app as vercel_entry

    deck: Deck = vercel_entry.app.extensions["flask_deck"]["deck"]
    try:
        assert vercel_entry._resolve_demo_safe_mode() is True
        assert deck.config.demo_safe_mode is True
        login_html = vercel_entry.app.test_client().get("/admin/login").get_data(as_text=True)
        assert "Demo Safe Mode" in login_html
    finally:
        deck.close()


def test_demo_safe_mode_visible_inspection_and_strict_csp() -> None:
    app = create_demo_app(
        seed_profile="showcase",
        stateless_ephemeral_sessions=True,
        demo_safe_mode=True,
    )
    deck: Deck = app.extensions["flask_deck"]["deck"]
    try:
        client = app.test_client()
        login_html = client.get("/admin/login").get_data(as_text=True)
        assert "Demo Safe Mode" in login_html

        login_as(client, "admin@acme.dev", "deck-demo-2026")
        assert isinstance(deck.auth, SQLAlchemyAuthProvider)
        super_grp = deck.auth.get_group_by_name("superadmin")
        assert super_grp is not None

        inspect_paths = (
            "/admin/",
            "/admin/_security/users",
            "/admin/_security/users?edit=admin",
            "/admin/_security/groups",
            f"/admin/_security/groups?edit={super_grp.id}",
            "/admin/_security/password",
            "/admin/_security/mfa",
            "/admin/_security/passkeys",
            "/admin/_security/sessions",
            "/admin/_security/api-keys",
            "/admin/_webhooks",
            "/admin/_sql",
            "/admin/_audit",
            "/admin/_diagnostics",
            "/admin/organizations/",
            "/admin/organizations/1",
        )
        for path in inspect_paths:
            resp = client.get(path)
            assert resp.status_code == 200, f"Expected 200 on {path}, got {resp.status_code}"
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'none'" in csp
            assert "unsafe-inline" not in csp
            html = resp.get_data(as_text=True)
            assert not _INLINE_STYLE_RE.search(html), f"Inline style= leaked on {path}"
            assert not _INLINE_HANDLER_RE.search(html), f"Inline handler leaked on {path}"
            assert "DEMO SAFE" in html

        users_html = client.get("/admin/_security/users").get_data(as_text=True)
        assert "DEMO LOCKED" in users_html
        assert "Inspect" in users_html
        assert 'name="username" class="dk-input" required maxlength="120" placeholder="ops@acme.dev" disabled' in users_html

        users_inspect_html = client.get("/admin/_security/users?edit=admin").get_data(as_text=True)
        assert "Inspect User" in users_inspect_html
        assert "Reset Password" in users_inspect_html
        assert "Disabled in Demo" in users_inspect_html

        groups_html = client.get(f"/admin/_security/groups?edit={super_grp.id}").get_data(as_text=True)
        assert "Inspect Group" in groups_html
        assert "DEMO LOCKED" in groups_html
        assert "Disabled in Demo" in groups_html

        mfa_html = client.get("/admin/_security/mfa").get_data(as_text=True)
        assert "<svg" in mfa_html
        assert "DEMO LOCKED" in mfa_html
        assert "Disabled in Demo" in mfa_html

        sessions_html = client.get("/admin/_security/sessions").get_data(as_text=True)
        assert "127.0.xxx.xxx" in sessions_html
        assert "127.0.0.1" not in sessions_html
        assert "DEMO LOCKED" in sessions_html

        audit_html = client.get("/admin/_audit").get_data(as_text=True)
        assert "10.24.xxx.xxx" in audit_html
        assert "10.24.0.18" not in audit_html
        assert 'title="Audit rollback is disabled in public Demo Safe Mode"' in audit_html

        with client.get("/admin/_audit/export?format=csv") as audit_csv:
            assert audit_csv.status_code == 200
            csv_txt = audit_csv.get_data(as_text=True)
            assert "10.24.xxx.xxx" in csv_txt
            assert "10.24.0.18" not in csv_txt

        diag_html = client.get("/admin/_diagnostics").get_data(as_text=True)
        assert "Demo Safe Mode" in diag_html

        org_detail_html = client.get("/admin/organizations/1").get_data(as_text=True)
        assert 'data-demo-locked="1"' in org_detail_html
        assert "data-impact-url=" in org_detail_html
    finally:
        deck.close()


def test_demo_safe_mode_blocks_locked_mutations_fail_closed() -> None:
    app = create_demo_app(
        seed_profile="showcase",
        stateless_ephemeral_sessions=True,
        demo_safe_mode=True,
    )
    deck: Deck = app.extensions["flask_deck"]["deck"]
    try:
        assert deck.adapter is not None
        engine = deck.adapter.get_engine()
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")
        assert isinstance(deck.auth, SQLAlchemyAuthProvider)
        super_grp = deck.auth.get_group_by_name("superadmin")
        assert super_grp is not None

        # 1. IAM User endpoints -> 403 and no user created/modified/deleted
        assert (
            client.post(
                "/admin/_security/users/create",
                data={
                    "_csrf_token": csrf,
                    "username": "intruder@acme.dev",
                    "password": "intruder-password-123",
                    "is_active": "1",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/users/support/update",
                data={"_csrf_token": csrf, "display_name": "Hacked", "email": "x@x.dev"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/users/support/reset-password",
                data={"_csrf_token": csrf, "new_password": "new-password-999"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/users/viewer/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert {u.username for u in deck.auth.list_users()} == {
            "admin@acme.dev",
            "support@acme.dev",
            "viewer@acme.dev",
        }
        assert deck.auth.authenticate("support@acme.dev", "deck-demo-2026") is not None

        # 2. IAM Group endpoints -> 403
        assert (
            client.post(
                "/admin/_security/groups/create",
                data={"_csrf_token": csrf, "name": "evil_group", "perm": "*:view"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/admin/_security/groups/{super_grp.id}/update",
                data={"_csrf_token": csrf, "label": "Tampered", "perm": "*:view"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/admin/_security/groups/{super_grp.id}/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )

        # 3. Password / MFA / Sessions / Passkeys / API Keys / Webhooks / SQL Save / Audit Revert -> 403
        assert (
            client.post(
                "/admin/_security/password",
                data={
                    "_csrf_token": csrf,
                    "current_password": "deck-demo-2026",
                    "new_password": "other-password-999",
                    "confirm_password": "other-password-999",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/mfa",
                data={"_csrf_token": csrf, "action": "enable", "code": "000000"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/sessions/revoke-others",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/sessions/some-sid/revoke",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        pk_opt = client.post(
            "/admin/_security/passkeys/register/options",
            headers={"X-Deck-CSRFToken": csrf},
        )
        assert pk_opt.status_code == 403
        assert pk_opt.get_json() is not None
        assert (
            client.post(
                "/admin/_security/passkeys/register/verify",
                json={"credential": {}},
                headers={"X-Deck-CSRFToken": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/passkeys/fake-cred/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_security/api-keys/create",
                data={"_csrf_token": csrf, "name": "rogue", "scopes": "*:view"},
            ).status_code
            == 403
        )
        assert deck.api_key_store is not None
        existing_key = deck.api_key_store.list_keys(limit=1)[0]
        assert (
            client.post(
                f"/admin/_security/api-keys/{existing_key.id}/revoke",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_webhooks/test",
                data={"_csrf_token": csrf, "sink_index": "0"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_webhooks/wh-demo-003/redeliver",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_sql/save",
                data={
                    "_csrf_token": csrf,
                    "name": "Evil Pinned Query",
                    "sql": "SELECT 1",
                    "pin": "1",
                },
            ).status_code
            == 403
        )
        assert deck.saved_query_store is not None
        sq = deck.saved_query_store.list_queries(limit=1)[0]
        assert (
            client.post(
                f"/admin/_sql/{sq.id}/pin",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/admin/_sql/{sq.id}/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )

        assert deck.audit_store is not None
        audit_entries, _ = deck.audit_store.list_entries(limit=50)
        revertible = next(e for e in audit_entries if e.is_revertible)
        assert (
            client.post(
                f"/admin/_audit/{revertible.id}/revert",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )

        # 4. Shared Team/Role Saved Views locked; Personal Saved Views remain allowed
        assert (
            client.post(
                "/admin/_api/organizations/saved-views",
                json={"name": "Bad Team View", "scope": "team", "query_string": "tab=enterprise"},
                headers={"X-Deck-CSRFToken": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_api/organizations/saved-views",
                data={
                    "_csrf_token": csrf,
                    "name": "Bad Role View",
                    "scope": "role",
                    "default_for_role": "support",
                    "query_string": "tab=enterprise",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/_api/organizations/saved-views/sv-org-ent/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        ok_sv = client.post(
            "/admin/_api/organizations/saved-views",
            json={"name": "Personal Test", "scope": "personal", "query_string": "tab=growth"},
            headers={"X-Deck-CSRFToken": csrf},
        )
        assert ok_sv.status_code == 201

        # 5. Permanent Delete, Bulk Hard Delete, Bulk Force Delete, and select_across -> 403
        assert (
            client.post(
                "/admin/organizations/1/delete",
                data={"_csrf_token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/organizations/action/delete",
                data={"_csrf_token": csrf, "selected_pks": "1"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/tickets/1/delete",
                data={"_csrf_token": csrf, "force": "1"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/admin/tickets/action/force_delete",
                data={"_csrf_token": csrf, "selected_pks": "1"},
            ).status_code
            == 403
        )

        orders_html = client.get("/admin/orders/?page_size=2").get_data(as_text=True)
        m_tok = re.search(r'data-slice-token="([^"]+)"', orders_html)
        assert m_tok is not None
        assert (
            client.post(
                "/admin/orders/action/mark_shipped",
                data={
                    "_csrf_token": csrf,
                    "select_across": "1",
                    "slice_token": m_tok.group(1),
                },
            ).status_code
            == 403
        )

        # 6. Import Dry-Run Preview works (200), Import Commit is blocked (403)
        with engine.connect() as conn:
            org_count_before = int(
                conn.execute(sa.text("SELECT COUNT(*) FROM demo_organizations")).scalar_one()
            )
        csv_bytes = (
            b"name,slug,plan,mrr_cents,seats_used,seats_limit,is_active\n"
            b"Dry Preview Org,dry-preview-org,growth,150000,10,20,true\n"
        )
        preview_resp = client.post(
            "/admin/organizations/import",
            data={
                "_csrf_token": csrf,
                "step": "preview",
                "file": (io.BytesIO(csv_bytes), "orgs.csv"),
            },
            content_type="multipart/form-data",
        )
        assert preview_resp.status_code == 200
        preview_html = preview_resp.get_data(as_text=True)
        assert "Step 2" in preview_html
        assert "Disabled in Demo" in preview_html
        m_prev = re.search(r'name="preview_token"\s+value="([^"]+)"', preview_html)
        assert m_prev is not None
        commit_resp = client.post(
            "/admin/organizations/import",
            data={
                "_csrf_token": csrf,
                "step": "commit",
                "preview_token": m_prev.group(1),
            },
        )
        assert commit_resp.status_code == 403
        with engine.connect() as conn:
            org_count_after = int(
                conn.execute(sa.text("SELECT COUNT(*) FROM demo_organizations")).scalar_one()
            )
        assert org_count_after == org_count_before

        # 7. REST API v1 allows GET (200) and blocks write POST/PATCH/DELETE (403); MCP blocks propose_*
        plaintext_key, key_rec = build_api_key_record(
            name="Test Bearer Key",
            owner_id="admin",
            owner_name="Duhan Güler",
            scopes=["*:view", "organizations:*"],
            roles=["superadmin"],
            is_superuser=True,
        )
        deck.api_key_store.create(key_rec)
        bearer_hdr = {"Authorization": f"Bearer {plaintext_key}"}
        assert client.get("/admin/_api/v1/organizations", headers=bearer_hdr).status_code == 200
        assert (
            client.post(
                "/admin/_api/v1/organizations",
                json={"name": "Blocked API Org", "slug": "blocked-api"},
                headers=bearer_hdr,
            ).status_code
            == 403
        )
        assert (
            client.patch(
                "/admin/_api/v1/organizations/1",
                json={"name": "Blocked Patch"},
                headers=bearer_hdr,
            ).status_code
            == 403
        )
        assert (
            client.delete(
                "/admin/_api/v1/organizations/1",
                headers=bearer_hdr,
            ).status_code
            == 403
        )

        mcp_list = client.post(
            "/admin/_mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_models", "arguments": {}}},
            headers=bearer_hdr,
        )
        assert mcp_list.status_code == 200
        assert not mcp_list.get_json()["result"].get("isError", False)

        mcp_write = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "propose_create",
                    "arguments": {"slug": "organizations", "values": {"name": "Blocked", "slug": "blk"}},
                },
            },
            headers=bearer_hdr,
        )
        assert mcp_write.status_code == 200
        res_mcp: dict[str, Any] = mcp_write.get_json()["result"]
        assert res_mcp.get("isError") is True
        assert "Demo Safe Mode" in res_mcp["structuredContent"]["error"]
    finally:
        deck.close()


def test_demo_safe_mode_preserves_safe_interactive_features() -> None:
    app = create_demo_app(
        seed_profile="showcase",
        stateless_ephemeral_sessions=True,
        demo_safe_mode=True,
    )
    deck: Deck = app.extensions["flask_deck"]["deck"]
    try:
        client = app.test_client()
        csrf = login_as(client, "admin@acme.dev", "deck-demo-2026")

        # 1. Cascade Delete Impact Preview works on permanent-locked Org #1
        imp = client.post(
            "/admin/_api/organizations/delete-impact",
            json={"pks": ["1"], "force": False},
            headers={"X-Deck-CSRFToken": csrf},
        )
        assert imp.status_code == 200
        imp_data = imp.get_json()
        assert imp_data["total_affected"] > 0

        # 2. Read-only SQL execution works
        sql_r = client.post(
            "/admin/_sql",
            data={
                "_csrf_token": csrf,
                "sql": "SELECT COUNT(*) AS org_count FROM demo_organizations",
                "output": "table",
                "chart_type": "table",
            },
        )
        assert sql_r.status_code == 200
        assert "32" in sql_r.get_data(as_text=True)

        # 3. Reversible soft-delete and restore on SupportTicket work
        sd_r = client.post(
            "/admin/tickets/1/delete",
            data={"_csrf_token": csrf},
            follow_redirects=False,
        )
        assert sd_r.status_code == 302
        rest_r = client.post(
            "/admin/tickets/1/restore",
            data={"_csrf_token": csrf},
            follow_redirects=False,
        )
        assert rest_r.status_code == 302
        with app.app_context():
            sess = deck.get_session()
            t1 = sess.get(SupportTicket, 1)
            assert t1 is not None and t1.deleted_at is None
            org1 = sess.get(Organization, 1)
            assert org1 is not None

        # 4. CSV export + Demo Role Switcher work
        with client.get("/admin/organizations/export.csv") as exp_csv:
            assert exp_csv.status_code == 200
            assert "Northstar Robotics" in exp_csv.get_data(as_text=True)

        sw = client.post(
            "/admin/_demo/switch-role",
            data={"_csrf_token": csrf, "account_id": "support", "next": "/admin/users/"},
            follow_redirects=False,
        )
        assert sw.status_code == 302
        sup_users = client.get("/admin/users/?q=Ada").get_data(as_text=True)
        assert "a***@northstar.io" in sup_users
        assert "ada@northstar.io" not in sup_users
    finally:
        deck.close()
