"""Behavioral & security boundary tests for the JSON-RPC 2.0 MCP Server (HTTP & stdio)."""

from __future__ import annotations

import io
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from flask_deck import (
    ActionField,
    Deck,
    DeckUser,
    InMemoryAPIKeyStore,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    ModelView,
    RBACAuthProvider,
    Role,
    action,
    build_api_key_record,
)
from flask_deck.exceptions import PermissionDeniedError
from flask_deck.mcp_server import run_mcp_stdio
from tests._backends import sqlite_memory_engine


class McpBase(DeclarativeBase):
    pass


class McpAsset(McpBase):
    __tablename__ = "mcp_assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    note: Mapped[str] = mapped_column(sa.String(120), default="", nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)


class McpAssetView(ModelView):
    model = McpAsset
    slug = "assets"
    searchable_columns = ("code", "note")
    filterable_columns = ("code",)
    sortable_columns = ("id", "code")
    soft_delete_column = "deleted_at"
    version_column = "version"

    @action(
        "tag_asset",
        label="Tag Asset",
        fields=(ActionField("tag", "text", label="Tag", required=True),),
    )
    def tag_asset(self, records: list[McpAsset], form_data: Any, user: Any) -> str:
        t = form_data.get("tag", "")
        for r in records:
            r.note = f"{r.note}[{t}]"
        return f"Tagged {len(records)}"


@contextmanager
def _build_mcp_app(
    *,
    mcp_require_approval: bool = True,
    read_only: bool = False,
    demo_safe_mode: bool = False,
    enable_approvals: bool = True,
) -> Any:
    with sqlite_memory_engine() as eng:
        McpBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "mcp-protocol-secret-32-bytes!!!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[
                Role("superadmin", permissions=frozenset({"*"})),
                Role("viewer", permissions=frozenset({"assets:view"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="secret-pass",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="viewer", username="viewer", roles=("viewer",)),
                    password="secret-pass",
                ),
            ],
        )
        keys = InMemoryAPIKeyStore()
        admin_tok, admin_rec = build_api_key_record(
            name="admin-mcp", owner_id="admin", owner_name="Admin", scopes=("*",), is_superuser=True
        )
        viewer_tok, viewer_rec = build_api_key_record(
            name="viewer-mcp", owner_id="viewer", owner_name="Viewer", scopes=("assets:view",), roles=("viewer",)
        )
        keys.create(admin_rec)
        keys.create(viewer_rec)

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            api_key_store=keys,
            audit_store=InMemoryAuditStore(),
            approval_store=InMemoryApprovalStore() if enable_approvals else None,
            enable_mcp=True,
            mcp_require_approval=mcp_require_approval,
            read_only=read_only,
            demo_safe_mode=demo_safe_mode,
            enable_sql_console=True,
        )
        deck.register(McpAssetView)
        try:
            yield app, deck, eng, admin_tok, viewer_tok
        finally:
            deck.close()


def _rpc(client: Any, hdr: dict[str, str], payload: Any) -> Any:
    return client.post("/admin/_mcp", json=payload, headers=hdr)


def test_mcp_http_framing_dns_rebinding_resources_and_all_read_tools() -> None:
    with _build_mcp_app(mcp_require_approval=False) as (app, _deck, _eng, admin_tok, viewer_tok):
        admin_hdr = {"Authorization": f"Bearer {admin_tok}"}
        viewer_hdr = {"Authorization": f"Bearer {viewer_tok}"}
        client = app.test_client()
        # Cross-origin DNS rebinding blocked (403); non-object body -> 400
        r_origin = client.post(
            "/admin/_mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={**admin_hdr, "Origin": "https://evil.example.com"},
        )
        assert r_origin.status_code == 403
        assert client.post("/admin/_mcp", data="[]", content_type="application/json", headers=admin_hdr).status_code == 400

        # Protocol lifecycle: initialize, ping, notification (204), unknown method (-32601)
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}).get_json()["result"]["protocolVersion"]
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 2, "method": "ping"}).get_json()["result"] == {}
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 204
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 3, "method": "bogus/op"}).get_json()["error"]["code"] == -32601

        # tools/list, resources/list, resources/read (valid + invalid URI + unknown slug)
        tools = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}).get_json()["result"]["tools"]
        assert len(tools) == 11

        res_list = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 5, "method": "resources/list"}).get_json()["result"]["resources"]
        assert any(r["uri"] == "deck://models/assets" for r in res_list)

        res_read = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": {"uri": "deck://models/assets"}}).get_json()
        assert "contents" in res_read["result"]
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": "http://bad"}}).get_json()["error"]["code"] == -32602
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": {"uri": "deck://models/missing"}}).get_json()["error"]["code"] == -32000

        # Direct execution (mcp_require_approval=False): create -> get -> query -> update -> action -> audit -> sql -> soft/force delete
        r_create = _rpc(
            client,
            admin_hdr,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "propose_create", "arguments": {"slug": "assets", "values": {"code": "A-1", "note": "init"}}},
            },
        ).get_json()["result"]
        assert r_create["isError"] is False
        rec = r_create["structuredContent"]["record"]
        pk = rec["_pk"]

        # Duplicate create fails via SAVEPOINT rollback cleanly (isError=True)
        r_dup = _rpc(
            client,
            admin_hdr,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "propose_create", "arguments": {"slug": "assets", "values": {"code": "A-1"}}},
            },
        ).get_json()["result"]
        assert r_dup["isError"] is True

        # get_record + missing record + query_records + describe_model + list_models
        r_get = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "get_record", "arguments": {"slug": "assets", "pk": pk}}}).get_json()["result"]
        assert r_get["structuredContent"]["record"]["code"] == "A-1"
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "get_record", "arguments": {"slug": "assets", "pk": "9999"}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "query_records", "arguments": {"slug": "assets", "filters": {"code": "A-1"}}}}).get_json()["result"]["structuredContent"]["total"] == 1
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": {"name": "list_models", "arguments": {}}}).get_json()["result"]["structuredContent"]["models"]

        # propose_update: OCC mismatch fails, valid update bumps integer version
        r_occ = _rpc(
            client,
            admin_hdr,
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {"name": "propose_update", "arguments": {"slug": "assets", "pk": pk, "expected_version": "wrong", "values": {"note": "x"}}},
            },
        ).get_json()["result"]
        assert r_occ["isError"] is True

        r_upd = _rpc(
            client,
            admin_hdr,
            {
                "jsonrpc": "2.0",
                "id": 16,
                "method": "tools/call",
                "params": {"name": "propose_update", "arguments": {"slug": "assets", "pk": pk, "expected_version": rec["_version"], "values": {"note": "v2"}}},
            },
        ).get_json()["result"]
        assert r_upd["isError"] is False and r_upd["structuredContent"]["record"]["version"] == 2

        # propose_action: unknown action, missing pks, missing required param, valid execution
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {"name": "propose_action", "arguments": {"slug": "assets", "action_name": "nope", "pks": [pk]}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 18, "method": "tools/call", "params": {"name": "propose_action", "arguments": {"slug": "assets", "action_name": "tag_asset", "pks": []}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 19, "method": "tools/call", "params": {"name": "propose_action", "arguments": {"slug": "assets", "action_name": "tag_asset", "pks": [pk], "params": {}}}}).get_json()["result"]["isError"] is True
        r_act = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "propose_action", "arguments": {"slug": "assets", "action_name": "tag_asset", "pks": [pk], "params": {"tag": "prod"}}}}).get_json()["result"]
        assert r_act["isError"] is False and r_act["structuredContent"]["status"] == "executed"

        # get_audit_log + run_readonly_sql (valid, unknown bind, blocked DDL)
        r_aud = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {"name": "get_audit_log", "arguments": {"model_slug": "assets"}}}).get_json()["result"]
        assert r_aud["structuredContent"]["total"] >= 2
        r_sql = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 22, "method": "tools/call", "params": {"name": "run_readonly_sql", "arguments": {"sql": "SELECT code FROM mcp_assets"}}}).get_json()["result"]
        assert r_sql["structuredContent"]["row_count"] == 1
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 23, "method": "tools/call", "params": {"name": "run_readonly_sql", "arguments": {"sql": "SELECT 1", "bind_key": "missing"}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 24, "method": "tools/call", "params": {"name": "run_readonly_sql", "arguments": {"sql": "DROP TABLE mcp_assets"}}}).get_json()["result"]["isError"] is True

        # Viewer denied create & audit & unknown tool error
        assert _rpc(client, viewer_hdr, {"jsonrpc": "2.0", "id": 25, "method": "tools/call", "params": {"name": "propose_create", "arguments": {"slug": "assets", "values": {"code": "B"}}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 26, "method": "tools/call", "params": {"name": "no_such_tool", "arguments": {}}}).get_json()["result"]["isError"] is True

        # Soft delete -> update soft-deleted rejected -> force delete succeeds
        r_sdel = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 27, "method": "tools/call", "params": {"name": "propose_delete", "arguments": {"slug": "assets", "pk": pk}}}).get_json()["result"]
        assert r_sdel["structuredContent"]["soft"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 28, "method": "tools/call", "params": {"name": "propose_update", "arguments": {"slug": "assets", "pk": pk, "values": {"note": "z"}}}}).get_json()["result"]["isError"] is True
        r_hdel = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 29, "method": "tools/call", "params": {"name": "propose_delete", "arguments": {"slug": "assets", "pk": pk, "force": True}}}).get_json()["result"]
        assert r_hdel["structuredContent"]["soft"] is False


def test_mcp_hitl_approvals_safe_modes_and_stdio_runner() -> None:
    # 1. HITL approval queueing + get_approval_status access rules
    with _build_mcp_app(mcp_require_approval=True) as (app, deck, _eng, admin_tok, viewer_tok):
        admin_hdr = {"Authorization": f"Bearer {admin_tok}"}
        viewer_hdr = {"Authorization": f"Bearer {viewer_tok}"}
        client = app.test_client()
        r_prop = _rpc(
            client,
            admin_hdr,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "propose_create", "arguments": {"slug": "assets", "values": {"code": "HITL-1"}, "reason": "agent"}},
            },
        ).get_json()["result"]
        assert r_prop["structuredContent"]["status"] == "pending_approval"
        appr_id = r_prop["structuredContent"]["approval_id"]

        r_st = _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_approval_status", "arguments": {"approval_id": appr_id}}}).get_json()["result"]
        assert r_st["structuredContent"]["status"] == "pending"
        assert _rpc(client, viewer_hdr, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_approval_status", "arguments": {"approval_id": appr_id}}}).get_json()["result"]["isError"] is True
        assert _rpc(client, admin_hdr, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_approval_status", "arguments": {"approval_id": "missing"}}}).get_json()["result"]["isError"] is True

        # stdio transport framing: blank line, invalid JSON (-32700), non-object (-32600), valid ping
        with app.app_context():
            with pytest.raises(PermissionDeniedError):
                run_mcp_stdio(deck, api_key_token="dk_live_invalid", stdin=io.StringIO(""), stdout=io.StringIO())

            stdin = io.StringIO(
                "\n"
                "{broken json\n"
                "[]\n"
                '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            )
            stdout = io.StringIO()
            assert run_mcp_stdio(deck, api_key_token=admin_tok, stdin=stdin, stdout=stdout) == 0
            lines = [json.loads(line) for line in stdout.getvalue().strip().splitlines()]
            assert [m.get("error", {}).get("code") for m in lines[:2]] == [-32700, -32600]
            assert lines[2]["result"] == {}

    # 2. Demo Safe Mode & Read-Only Mode block mutating MCP tools
    for kwargs in ({"demo_safe_mode": True}, {"read_only": True}):
        with _build_mcp_app(**kwargs) as (app_m, _deck_m, _eng_m, tok_m, _):
            c = app_m.test_client()
            res = _rpc(
                c,
                {"Authorization": f"Bearer {tok_m}"},
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "propose_create", "arguments": {"slug": "assets", "values": {"code": "X"}}},
                },
            ).get_json()["result"]
            assert res["isError"] is True


def test_mcp_origin_acl_diff_redaction_and_malformed_arg_regressions() -> None:
    class HiddenAssetView(ModelView):
        model = McpAsset
        slug = "hidden-assets"
        can_view = False

    class GuardedAssetView(ModelView):
        model = McpAsset
        slug = "guarded-assets"
        approval_required = ("edit", "delete")

        def can_view_record(self, obj: Any, user: Any) -> bool:
            return not (obj.code == "TOP-SECRET" and user is not None and not user.is_superuser)

    with sqlite_memory_engine() as eng:
        McpBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SessionLocal() as s:
            a_pub = McpAsset(code="PUB-1", note="hidden-secret-body")
            a_sec = McpAsset(code="TOP-SECRET", note="classified-body")
            s.add_all([a_pub, a_sec])
            s.commit()
            pub_pk, sec_pk = str(a_pub.id), str(a_sec.id)

        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role(
                    "viewer",
                    permissions=frozenset({"guarded-assets:view", "guarded-assets:delete", "hidden-assets:view"}),
                    hidden_fields={"guarded-assets": frozenset({"note"})},
                    masked_fields={"guarded-assets": frozenset({"code"})},
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="adm", username="adm", roles=("admin",), is_superuser=True),
                    password="secret",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="vw", username="vw", roles=("viewer",)),
                    password="secret",
                ),
            ],
        )
        keys = InMemoryAPIKeyStore()
        adm_tok, adm_rec = build_api_key_record(
            name="adm", owner_id="adm", owner_name="Admin", scopes=("*",), is_superuser=True
        )
        vw_tok, vw_rec = build_api_key_record(
            name="vw",
            owner_id="vw",
            owner_name="Viewer",
            scopes=("guarded-assets:*", "hidden-assets:*"),
            roles=("viewer",),
        )
        keys.create(adm_rec)
        keys.create(vw_rec)

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "mcp-bug-hunt-secret-32-bytes!!!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            api_key_store=keys,
            approval_store=InMemoryApprovalStore(),
            audit_store=InMemoryAuditStore(),
            enable_mcp=True,
            mcp_require_approval=True,
        )
        deck.register(HiddenAssetView, GuardedAssetView)
        try:
            client = app.test_client()
            adm_hdr = {"Authorization": f"Bearer {adm_tok}"}
            vw_hdr = {"Authorization": f"Bearer {vw_tok}"}

            # 1. Malformed IPv6 Origin & Origin: null blocked with 403 (never 500)
            assert client.post(
                "/admin/_mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={**adm_hdr, "Origin": "http://[::1"},
            ).status_code == 403
            assert client.post(
                "/admin/_mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                headers={**adm_hdr, "Origin": "null"},
            ).status_code == 403

            # 2. can_view=False enforced on describe_model, query_records, and get_record
            for tool, args in (
                ("describe_model", {"slug": "hidden-assets"}),
                ("query_records", {"slug": "hidden-assets"}),
                ("get_record", {"slug": "hidden-assets", "pk": pub_pk}),
            ):
                res = _rpc(
                    client,
                    adm_hdr,
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool, "arguments": args}},
                ).get_json()["result"]
                assert res["isError"] is True

            # 3. can_view_record enforced on get_record & query_records
            r_sec_get = _rpc(
                client,
                vw_hdr,
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_record", "arguments": {"slug": "guarded-assets", "pk": sec_pk}}},
            ).get_json()["result"]
            assert r_sec_get["isError"] is True
            r_vw_q = _rpc(
                client,
                vw_hdr,
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "query_records", "arguments": {"slug": "guarded-assets"}}},
            ).get_json()["result"]
            assert len(r_vw_q["structuredContent"]["items"]) == 1

            # 4. Approval diffs strip hidden_fields & mask masked_fields in propose_delete & get_approval_status
            r_pdel = _rpc(
                client,
                vw_hdr,
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "propose_delete", "arguments": {"slug": "guarded-assets", "pk": pub_pk}}},
            ).get_json()["result"]
            assert r_pdel["isError"] is False
            appr_id = r_pdel["structuredContent"]["approval_id"]
            r_ast = _rpc(
                client,
                vw_hdr,
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "get_approval_status", "arguments": {"approval_id": appr_id}}},
            ).get_json()["result"]
            diff = r_ast["structuredContent"]["diff"]
            assert "note" not in diff
            assert "hidden-secret-body" not in json.dumps(diff)
            if "code" in diff:
                assert "PUB-1" not in json.dumps(diff["code"])

            # 5. Malformed tool args return clean isError=True (no unhandled 500)
            for tool, args in (
                ("query_records", {"slug": "guarded-assets", "page": None, "page_size": "bad"}),
                ("get_record", {"slug": "guarded-assets", "pk": "not-an-int"}),
                ("propose_action", {"slug": "guarded-assets", "action_name": "x", "pks": 123}),
            ):
                resp = _rpc(
                    client,
                    adm_hdr,
                    {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": tool, "arguments": args}},
                )
                assert resp.status_code == 200
                body = resp.get_json()
                assert body["result"]["isError"] is True or "error" in body
        finally:
            deck.close()
