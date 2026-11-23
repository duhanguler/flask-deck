from __future__ import annotations

import io
import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from flask_deck import (
    Deck,
    DeckUser,
    InMemoryAPIKeyStore,
    ModelView,
    RBACAuthProvider,
    Role,
    SQLAlchemyAPIKeyStore,
    SQLAlchemyApprovalStore,
    SQLAlchemyAuditStore,
    action,
    api_key_allows,
    api_key_to_user,
    build_api_key_record,
    run_mcp_stdio,
)
from flask_deck.security import CSRF_FORM_FIELD
from tests.conftest import extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\sstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\son(?:click|change|submit|input|load)\s*=", re.IGNORECASE)


class M4Base(DeclarativeBase):
    pass


class ApiOrder(M4Base):
    __tablename__ = "m4_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    tenant: Mapped[str] = mapped_column(sa.String(32), default="acme", nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), default="open", nullable=False)
    is_vip: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("50.00"))
    secret_key: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    secret_note: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    def __str__(self) -> str:
        return f"ApiOrder {self.code}"


def _assert_strict_csp(resp: Any) -> None:
    html = resp.get_data(as_text=True)
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert not _INLINE_STYLE_RE.search(html)
    assert not _INLINE_HANDLER_RE.search(html)
    assert "<style" not in html.lower()


def _make_m4_rbac() -> RBACAuthProvider:
    return RBACAuthProvider(
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="ops_agent",
                permissions=frozenset(
                    {
                        "api-orders:view",
                        "api-orders:create",
                        "api-orders:edit",
                        "api-orders:delete",
                        "api-orders:action:escalate",
                        "approvals:view",
                        "audit:view",
                        "sql:query",
                        "api_keys:manage",
                    }
                ),
                masked_fields={"api-orders": frozenset({"amount"})},
                hidden_fields={"api-orders": frozenset({"secret_note"})},
            ),
            Role(
                name="viewer",
                permissions=frozenset({"api-orders:view", "approvals:view"}),
            ),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-adm", username="admin", roles=("admin",), is_superuser=True, tenant_id="acme"
                ),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-ops", username="ops", roles=("ops_agent",), tenant_id="acme"
                ),
                password="ops-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-reviewer", username="reviewer", roles=("admin",), is_superuser=True, tenant_id="acme"
                ),
                password="reviewer-password",
            ),
        ],
    )


def _setup_m4_deck(
    tmp_path: Path,
    *,
    enable_rest_api: bool = True,
    enable_mcp: bool = True,
    mcp_require_approval: bool = True,
    approval_required: bool = False,
    read_only: bool = False,
    rate_max: int = 120,
) -> tuple[Flask, Deck, sa.Engine, sessionmaker[Any]]:
    db_path = tmp_path / "m4_api_mcp.sqlite3"
    eng = sa.create_engine(
        f"sqlite:///{db_path.as_posix()}", connect_args={"check_same_thread": False}
    )
    try:
        M4Base.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SessionLocal() as s:
            s.add_all(
                [
                    ApiOrder(
                        code="ORD-A1",
                        tenant="acme",
                        status="open",
                        is_vip=True,
                        amount=Decimal("125.00"),
                        secret_key="internal_secret_a1",
                        secret_note="hidden_note_a1",
                        version=1,
                    ),
                    ApiOrder(
                        code="ORD-B1",
                        tenant="other_corp",
                        status="open",
                        is_vip=False,
                        amount=Decimal("300.00"),
                        secret_key="internal_secret_b1",
                        secret_note="hidden_note_b1",
                        version=1,
                    ),
                ]
            )
            s.commit()

        class ApiOrderView(ModelView):
            model = ApiOrder
            columns = ("id", "code", "tenant", "status", "is_vip", "amount", "version")
            searchable_columns = ("code", "status")
            filterable_columns = ("status", "tenant", "is_vip")
            form_columns = ("code", "tenant", "status", "is_vip", "amount", "secret_note")
            version_column = "version"

            def scope_query(self, stmt: Any, user: DeckUser | None) -> Any:
                # Multi-tenant row scope when user carries tenant_id in metadata or field
                if user is not None and not user.is_superuser:
                    return stmt.where(ApiOrder.tenant == "acme")
                return stmt

            @action(name="escalate", label="Escalate Order")
            def escalate(self, records: list[ApiOrder], form: Any, user: Any) -> str:
                for r in records:
                    r.status = "escalated"
                return f"Escalated {len(records)} orders"

        view = ApiOrderView()
        view.approval_required = approval_required

        app = Flask(__name__)
        app.secret_key = "m4-api-and-mcp-test-secret-key"
        app.config["TESTING"] = True

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=_make_m4_rbac(),
            audit_store=SQLAlchemyAuditStore(eng) if not read_only else False,
            approval_store=SQLAlchemyApprovalStore(eng) if not read_only else False,
            enable_rest_api=enable_rest_api,
            enable_mcp=enable_mcp,
            mcp_require_approval=mcp_require_approval,
            read_only=read_only,
            api_rate_limit_max=rate_max,
            api_rate_limit_window_seconds=60,
        )
        deck.register(view)
        return app, deck, eng, SessionLocal
    except Exception:
        eng.dispose()
        raise


def test_api_key_lifecycle_security_ui_and_in_memory_parity(tmp_path: Path) -> None:
    app, deck, eng, _ = _setup_m4_deck(tmp_path)
    try:
        assert isinstance(deck.api_key_store, SQLAlchemyAPIKeyStore)

        # UI key creation by non-superuser ops user cannot escalate to admin/superuser
        c_ops = app.test_client()
        login_as(c_ops, "ops", "ops-password")
        page = c_ops.get("/admin/_security/api-keys")
        assert page.status_code == 200
        _assert_strict_csp(page)
        csrf = extract_csrf(page.get_data(as_text=True))

        created_resp = c_ops.post(
            "/admin/_security/api-keys/create",
            data={
                CSRF_FORM_FIELD: csrf,
                "name": "Ops Automation",
                "scopes": "api-orders:view, api-orders:create",
                "roles": "admin",  # escalation attempt
                "is_superuser": "1",  # escalation attempt
                "allowed_ips": "127.0.0.1, 10.0.0.0/8",
                "ttl_days": "30",
            },
            follow_redirects=True,
        )
        assert created_resp.status_code == 200
        _assert_strict_csp(created_resp)
        html1 = created_resp.get_data(as_text=True)
        m_key = re.search(r'data-deck-new-api-key>(dk_live_[a-f0-9]+)<', html1)
        assert m_key is not None
        plaintext_key = m_key.group(1)

        # Refresh NEVER shows plaintext token again
        html2 = c_ops.get("/admin/_security/api-keys").get_data(as_text=True)
        assert plaintext_key not in html2

        keys = deck.api_key_store.list_keys()
        assert len(keys) == 1
        rec = keys[0]
        assert rec.roles == ("ops_agent",)  # escalated "admin" dropped
        assert rec.is_superuser is False
        assert rec.key_hash != plaintext_key
        assert deck.api_key_store.verify_token(plaintext_key, client_ip="127.0.0.1") is not None
        assert deck.api_key_store.verify_token(plaintext_key, client_ip="192.168.1.5") is None

        # Revoke key immediately blocks auth
        c_ops.post(
            f"/admin/_security/api-keys/{rec.id}/revoke",
            data={CSRF_FORM_FIELD: csrf},
        )
        assert deck.api_key_store.verify_token(plaintext_key, client_ip="127.0.0.1") is None

        # InMemoryAPIKeyStore + expiration check parity
        mem_store = InMemoryAPIKeyStore()
        pt_valid, rec_valid = build_api_key_record(
            name="Mem Valid",
            owner_id="u-1",
            owner_name="Alice",
            scopes=("api-orders:*",),
            roles=("ops_agent",),
            allowed_ips=("127.0.0.0/24",),
        )
        mem_store.create(rec_valid)
        verified = mem_store.verify_token(pt_valid, client_ip="127.0.0.5")
        assert verified is not None
        assert api_key_allows(verified, "api-orders:edit")
        assert not api_key_allows(verified, "users:delete")
        synth_user = api_key_to_user(verified)
        assert synth_user.id == f"apikey:{verified.id}"

        pt_exp, rec_exp = build_api_key_record(
            name="Expired Key", owner_id="u-1", owner_name="Alice"
        )
        rec_exp.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        mem_store.create(rec_exp)
        assert mem_store.verify_token(pt_exp) is None
    finally:
        deck.close()
        eng.dispose()


def test_rest_api_v1_crud_openapi_pii_occ_approvals_and_rate_limit(tmp_path: Path) -> None:
    app, deck, eng, SessionLocal = _setup_m4_deck(
        tmp_path,
        enable_rest_api=True,
        enable_mcp=False,
        approval_required=False,
        rate_max=20,
    )
    try:
        assert deck.api_key_store is not None
        pt_ops, rec_ops = build_api_key_record(
            name="Ops Full API",
            owner_id="u-ops",
            owner_name="Ops",
            scopes=("*",),
            roles=("ops_agent",),
        )
        deck.api_key_store.create(rec_ops)

        pt_ro, rec_ro = build_api_key_record(
            name="ReadOnly Scoped Key",
            owner_id="u-ops",
            owner_name="Ops",
            scopes=("api-orders:view",),
            roles=("ops_agent",),
        )
        deck.api_key_store.create(rec_ro)

        client = app.test_client()

        # 1. Missing/invalid Bearer -> 401
        assert client.get("/admin/_api/v1/models").status_code == 401
        assert (
            client.get(
                "/admin/_api/v1/models",
                headers={"Authorization": "Bearer dk_live_invalid_token_12345"},
            ).status_code
            == 401
        )

        # 2. OpenAPI 3.1 + models discovery
        h_ops = {"Authorization": f"Bearer {pt_ops}"}
        oa = client.get("/admin/_api/v1/openapi.json", headers=h_ops)
        assert oa.status_code == 200
        spec = oa.get_json()
        assert spec["openapi"] == "3.1.0"
        assert "BearerAuth" in spec["components"]["securitySchemes"]
        assert "/admin/_api/v1/api-orders" in spec["paths"]
        assert "secret_note" not in spec["components"]["schemas"]["ApiOrder"]["properties"]

        # 3. Collection list obeys row scope (tenant='acme') + masked amount + omitted hidden/sensitive
        lst = client.get("/admin/_api/v1/api-orders", headers=h_ops)
        assert lst.status_code == 200
        body = lst.get_json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["code"] == "ORD-A1"
        assert "secret_key" not in item
        assert "secret_note" not in item
        assert "***" in str(item["amount"]) or item["amount"] != "125.00"

        # 4. Out-of-scope tenant record -> 404
        assert client.get("/admin/_api/v1/api-orders/2", headers=h_ops).status_code == 404

        # 5. Create (no CSRF cookie needed!) -> 201 + ETag; forbidden field -> 422
        bad_field = client.post(
            "/admin/_api/v1/api-orders",
            json={"code": "ORD-BAD", "secret_note": "forbidden"},
            headers=h_ops,
        )
        assert bad_field.status_code == 422

        cr = client.post(
            "/admin/_api/v1/api-orders",
            json={"code": "ORD-REST-1", "tenant": "acme", "status": "open", "is_vip": True, "amount": "80.00"},
            headers=h_ops,
        )
        assert cr.status_code == 201
        created = cr.get_json()
        new_pk = created["_pk"]
        etag = cr.headers["ETag"].strip('"')

        # 6. Partial PATCH preserves omitted boolean is_vip=True + OCC If-Match checks
        p_ok = client.patch(
            f"/admin/_api/v1/api-orders/{new_pk}",
            json={"status": "processing"},
            headers={**h_ops, "If-Match": etag},
        )
        assert p_ok.status_code == 200
        assert p_ok.get_json()["is_vip"] is True
        assert p_ok.get_json()["version"] == 2

        # Stale If-Match returns 409 Conflict
        p_stale = client.patch(
            f"/admin/_api/v1/api-orders/{new_pk}",
            json={"status": "closed"},
            headers={**h_ops, "If-Match": etag},
        )
        assert p_stale.status_code == 409

        # 7. Action execution + scoped read-only key blocked from writes (403)
        act_ok = client.post(
            "/admin/_api/v1/api-orders/actions/escalate",
            json={"pks": [new_pk]},
            headers=h_ops,
        )
        assert act_ok.status_code == 200

        h_ro = {"Authorization": f"Bearer {pt_ro}"}
        assert client.get("/admin/_api/v1/api-orders", headers=h_ro).status_code == 200
        assert (
            client.post(
                "/admin/_api/v1/api-orders",
                json={"code": "ORD-DENY"},
                headers=h_ro,
            ).status_code
            == 403
        )

        # 8. DELETE + Rate-Limit 429 enforcement
        assert client.delete(f"/admin/_api/v1/api-orders/{new_pk}", headers=h_ops).status_code == 200
        with SessionLocal() as s:
            assert s.get(ApiOrder, int(new_pk)) is None

        # Exhaust rate limit on h_ro
        hit_429 = False
        for _ in range(25):
            r_rl = client.get("/admin/_api/v1/models", headers=h_ro)
            if r_rl.status_code == 429:
                hit_429 = True
                assert "Retry-After" in r_rl.headers
                break
        assert hit_429
    finally:
        deck.close()
        eng.dispose()


def test_mcp_hitl_savepoint_queue_human_approval_and_stdio_transport(tmp_path: Path) -> None:
    app, deck, eng, SessionLocal = _setup_m4_deck(
        tmp_path,
        enable_rest_api=True,
        enable_mcp=True,
        mcp_require_approval=True,
        approval_required=False,
    )
    try:
        assert deck.api_key_store is not None
        pt_agent, rec_agent = build_api_key_record(
            name="Claude Ops Agent",
            owner_id="u-ops",
            owner_name="Ops",
            scopes=("*",),
            roles=("ops_agent",),
        )
        deck.api_key_store.create(rec_agent)
        h_mcp = {"Authorization": f"Bearer {pt_agent}"}

        client = app.test_client()

        # 1. DNS rebinding / Origin check blocks cross-origin browser requests (403)
        r_origin = client.post(
            "/admin/_mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={**h_mcp, "Origin": "https://attacker.invalid"},
        )
        assert r_origin.status_code == 403

        # 2. Initialize, tools/list, resources/list, read tools + read-only SQL protection
        r_init = client.post(
            "/admin/_mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers=h_mcp,
        )
        assert r_init.status_code == 200
        assert r_init.get_json()["result"]["protocolVersion"] == "2025-03-26"

        r_tools = client.post(
            "/admin/_mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers=h_mcp,
        )
        tool_names = {t["name"] for t in r_tools.get_json()["result"]["tools"]}
        assert {
            "list_models",
            "describe_model",
            "query_records",
            "get_record",
            "get_audit_log",
            "run_readonly_sql",
            "get_approval_status",
            "propose_create",
            "propose_update",
            "propose_delete",
            "propose_action",
        }.issubset(tool_names)

        # query_records masks amount and hides other_corp + secret_note
        r_query = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "query_records", "arguments": {"slug": "api-orders"}},
            },
            headers=h_mcp,
        )
        q_out = r_query.get_json()["result"]["structuredContent"]
        assert q_out["total"] == 1
        assert q_out["items"][0]["code"] == "ORD-A1"
        assert "secret_note" not in q_out["items"][0]

        # run_readonly_sql executes SELECT cleanly, blocks DML & blocks deck_api_keys table
        r_sql_ok = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "run_readonly_sql",
                    "arguments": {"sql": "SELECT code, status FROM m4_orders ORDER BY id"},
                },
            },
            headers=h_mcp,
        )
        assert r_sql_ok.get_json()["result"]["isError"] is False
        assert r_sql_ok.get_json()["result"]["structuredContent"]["row_count"] == 2

        r_sql_block = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "run_readonly_sql",
                    "arguments": {"sql": "SELECT prefix, key_hash FROM deck_api_keys"},
                },
            },
            headers=h_mcp,
        )
        assert r_sql_block.get_json()["result"]["isError"] is True

        # 3. HITL: Invalid propose_create fails SAVEPOINT cleanly without queueing approval
        r_bad_create = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "propose_create",
                    "arguments": {
                        "slug": "api-orders",
                        "values": {"code": "ORD-A1", "status": "open"},  # duplicate unique code
                    },
                },
            },
            headers=h_mcp,
        )
        assert r_bad_create.get_json()["result"]["isError"] is True
        assert deck.approval_store is not None
        assert deck.approval_store.pending_count() == 0

        # 4. Valid propose_create queues approval request with actor_type='mcp_agent' (DB still untouched)
        r_prop_create = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "propose_create",
                    "arguments": {
                        "slug": "api-orders",
                        "values": {"code": "ORD-MCP-1", "tenant": "acme", "status": "pending", "amount": "199.00"},
                        "reason": "Automated customer compensation order",
                    },
                },
            },
            headers=h_mcp,
        )
        prop_res = r_prop_create.get_json()["result"]["structuredContent"]
        assert prop_res["status"] == "pending_approval"
        assert prop_res["actor_type"] == "mcp_agent"
        app_id = prop_res["approval_id"]

        with SessionLocal() as s:
            assert s.scalar(sa.select(ApiOrder).where(ApiOrder.code == "ORD-MCP-1")) is None

        # Agent polls get_approval_status cleanly
        r_stat = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "get_approval_status", "arguments": {"approval_id": app_id}},
            },
            headers=h_mcp,
        )
        assert r_stat.get_json()["result"]["structuredContent"]["status"] == "pending"

        # 5. Human reviewer sees 'mcp_agent' badge in /_approvals & approves -> DB commits + audit written!
        human = app.test_client()
        login_as(human, "reviewer", "reviewer-password")
        q_html = human.get("/admin/_approvals").get_data(as_text=True)
        assert "mcp_agent" in q_html
        assert "ORD-MCP-1" in q_html
        csrf_h = extract_csrf(q_html)
        human.post(
            f"/admin/_approvals/{app_id}/approve",
            data={CSRF_FORM_FIELD: csrf_h, "review_note": "LGTM from agent"},
            follow_redirects=False,
        )

        with SessionLocal() as s:
            created_ord = s.scalar(sa.select(ApiOrder).where(ApiOrder.code == "ORD-MCP-1"))
            assert created_ord is not None
            assert created_ord.amount == Decimal("199.00")

        assert deck.audit_store is not None
        audits, _ = deck.audit_store.list_entries(model_slug="api-orders", action="create")
        assert audits[0].metadata["actor_type"] == "mcp_agent"
        assert audits[0].metadata["approved_by"] == "u-reviewer"

        # REST approval detail reflects approved state
        rest_stat = client.get(f"/admin/_api/v1/approvals/{app_id}", headers=h_mcp)
        assert rest_stat.status_code == 200
        assert rest_stat.get_json()["status"] == "approved"

        # 6. propose_update, propose_delete, propose_action queue cleanly too
        r_pu = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "propose_update",
                    "arguments": {"slug": "api-orders", "pk": "1", "values": {"status": "paused"}},
                },
            },
            headers=h_mcp,
        )
        assert r_pu.get_json()["result"]["structuredContent"]["status"] == "pending_approval"

        r_pa = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "propose_action",
                    "arguments": {"slug": "api-orders", "action_name": "escalate", "pks": ["1"]},
                },
            },
            headers=h_mcp,
        )
        assert r_pa.get_json()["result"]["structuredContent"]["status"] == "pending_approval"

        r_pd = client.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "propose_delete",
                    "arguments": {"slug": "api-orders", "pk": "1", "reason": "Cleanup"},
                },
            },
            headers=h_mcp,
        )
        assert r_pd.get_json()["result"]["structuredContent"]["status"] == "pending_approval"

        # 7. Stdio transport NDJSON test
        stdin_buf = io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 100, "method": "initialize"})
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            + "\n"
            + json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 101,
                    "method": "tools/call",
                    "params": {"name": "list_models", "arguments": {}},
                }
            )
            + "\n"
        )
        stdout_buf = io.StringIO()
        assert run_mcp_stdio(deck, api_key_token=pt_agent, stdin=stdin_buf, stdout=stdout_buf) == 0
        lines = [json.loads(ln) for ln in stdout_buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 2
        assert lines[0]["result"]["protocolVersion"] == "2025-03-26"
        assert lines[1]["result"]["structuredContent"]["models"][0]["slug"] == "api-orders"
    finally:
        deck.close()
        eng.dispose()


def test_rest_and_mcp_read_only_mode_enforcement(tmp_path: Path) -> None:
    app, deck, eng, _ = _setup_m4_deck(tmp_path, read_only=True)
    try:
        assert deck.api_key_store is not None
        pt_key, rec = build_api_key_record(
            name="RO Probe",
            owner_id="u-adm",
            owner_name="Admin",
            scopes=("*",),
            roles=("admin",),
            is_superuser=True,
        )
        deck.api_key_store.create(rec)
        hdrs = {"Authorization": f"Bearer {pt_key}"}
        c = app.test_client()

        assert c.get("/admin/_api/v1/api-orders", headers=hdrs).status_code == 200
        assert (
            c.post("/admin/_api/v1/api-orders", json={"code": "RO-BLOCK"}, headers=hdrs).status_code
            == 403
        )
        # MCP read tools succeed even in read_only=True, while propose_* returns error
        r_list = c.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_models", "arguments": {}},
            },
            headers=hdrs,
        )
        assert r_list.status_code == 200
        assert r_list.get_json()["result"]["isError"] is False

        r_write = c.post(
            "/admin/_mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "propose_create",
                    "arguments": {"slug": "api-orders", "values": {"code": "RO-MCP"}},
                },
            },
            headers=hdrs,
        )
        assert r_write.status_code == 200
        assert r_write.get_json()["result"]["isError"] is True
        assert "read-only" in r_write.get_json()["result"]["structuredContent"]["error"].lower()
    finally:
        deck.close()
        eng.dispose()


def test_rest_maker_checker_202_and_cli_mcp_command(tmp_path: Path) -> None:
    app, deck, eng, SessionLocal = _setup_m4_deck(
        tmp_path,
        enable_rest_api=True,
        enable_mcp=True,
        approval_required=True,
    )
    try:
        assert deck.api_key_store is not None and deck.approval_store is not None
        pt, rec = build_api_key_record(
            name="Agent REST Maker",
            owner_id="u-ops",
            owner_name="Ops",
            scopes=("*",),
            roles=("ops_agent",),
        )
        deck.api_key_store.create(rec)
        c = app.test_client()
        hdrs = {"Authorization": f"Bearer {pt}"}

        r202 = c.post(
            "/admin/_api/v1/api-orders",
            json={"code": "ORD-REST-APP", "tenant": "acme", "status": "open", "is_vip": True, "amount": "45.00"},
            headers=hdrs,
        )
        assert r202.status_code == 202
        app_id = r202.get_json()["approval_id"]

        rev = app.test_client()
        login_as(rev, "reviewer", "reviewer-password")
        csrf_r = extract_csrf(rev.get("/admin/_approvals").get_data(as_text=True))
        rev.post(f"/admin/_approvals/{app_id}/approve", data={CSRF_FORM_FIELD: csrf_r})
        with SessionLocal() as s:
            assert s.scalar(sa.select(ApiOrder).where(ApiOrder.code == "ORD-REST-APP")) is not None

        from flask_deck.cli import deck_cli

        runner = app.test_cli_runner()
        res = runner.invoke(
            deck_cli,
            ["mcp", "--api-key", pt],
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n",
        )
        assert res.exit_code == 0
        assert '"result":{}' in res.output or '"result": {}' in res.output
    finally:
        deck.close()
        eng.dispose()
