from __future__ import annotations

import io
import secrets
import struct
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import sqlalchemy as sa
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckConfig,
    DeckUser,
    ModelView,
    QuickTab,
    RBACAuthProvider,
    Role,
    action,
)
from flask_deck.audit import InMemoryAuditStore, make_audit_entry
from flask_deck.cli import deck_cli, main
from flask_deck.demo import SupportTicket, create_demo_app
from flask_deck.events import (
    DeckEvent,
    DeckEventBus,
    WebhookSink,
    _is_non_public_ip,
    _NoRedirectHandler,
    _resolve_and_validate_url,
    _send_pinned_request,
    is_ssrf_safe_url,
    sign_webhook_payload,
)
from flask_deck.exporter import iter_export_chunks
from flask_deck.query import (
    build_filter_condition,
    build_search_clause,
    compute_page_aggregates,
    compute_quick_tab_counts,
    estimate_table_rows,
    execute_list_query,
    soft_delete_predicate,
)
from flask_deck.sql_console import execute_readonly_sql
from flask_deck.sso import (
    OIDCAuthProvider,
    OIDCProviderConfig,
    _default_http_transport,
    generate_pkce_pair,
)
from flask_deck.storage import (
    FileFieldConfig,
    LocalFileStorage,
    MemoryFileStorage,
    S3StorageBackend,
    detect_mime_from_bytes,
    parse_image_dimensions,
    validate_and_read_upload,
)
from tests.conftest import Item, SampleBase, Tenant, login_as


def _make_png(width: int = 4, height: int = 4) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"


def _make_gif(width: int = 8, height: int = 6, with_extensions: bool = True) -> bytes:
    header = b"GIF89a" + struct.pack("<HHB", width, height, 0x80) + b"\x00\x00" + (b"\x00" * 6)
    ext = b"\x21\xFE\x03abc\x00" if with_extensions else b""
    desc = b"\x2C" + struct.pack("<HHHHB", 0, 0, width + 2, height + 1, 0x80) + (b"\x00" * 6) + b"\x02\x01\x01\x00"
    return header + ext + desc + b"\x3B"


def _make_webp(chunk_type: bytes = b"VP8L", w: int = 16, h: int = 12) -> bytes:
    if chunk_type == b"VP8L":
        bits = ((w - 1) & 0x3FFF) | (((h - 1) & 0x3FFF) << 14)
        body = b"VP8L" + struct.pack("<I", 5) + b"\x2f" + struct.pack("<I", bits)
    elif chunk_type == b"VP8X":
        body = (
            b"VP8X"
            + struct.pack("<I", 10)
            + b"\x00\x00\x00\x00"
            + (w - 1).to_bytes(3, "little")
            + (h - 1).to_bytes(3, "little")
        )
    else:
        body = b"VP8 " + struct.pack("<I", 10) + b"\x00\x00\x00\x9d\x01\x2a" + struct.pack("<HH", w, h)
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WEBP" + body


def _make_jpeg(w: int = 32, h: int = 24) -> bytes:
    seg = struct.pack(">HBHH", 8, 8, h, w)
    return b"\xff\xd8\xff\xe0\x00\x04\x00\x00\xff\xc0" + seg + b"\xff\xd9"


# ---------------------------------------------------------------------------
# P0 Security & Integrity Hardening Regressions (M1)
# ---------------------------------------------------------------------------


def test_sql_console_alias_and_multi_wildcard_redaction() -> None:
    app = create_demo_app()
    try:
        deck: Deck = app.extensions["flask_deck"]["deck"]
        assert deck.adapter is not None
        engine = deck.adapter.get_engine()

        # P0-1: Alias before wildcard must redact BOTH `leaked` AND expanded `password_hash`/`api_token`
        res1 = execute_readonly_sql(
            engine,
            "SELECT password_hash AS leaked, * FROM demo_users ORDER BY id LIMIT 3",
        )
        assert res1.error is None
        assert res1.row_count == 3
        assert "leaked" in res1.redacted_columns
        for row in res1.rows:
            assert row[0] == "[REDACTED]"
            assert "pbkdf2:" not in " ".join(str(c) for c in row)

        # Expression suffix after wildcard also redacted
        res2 = execute_readonly_sql(
            engine,
            "SELECT *, substr(api_token, 1, 8) AS tok FROM demo_users ORDER BY id LIMIT 2",
        )
        assert res2.error is None
        tok_idx = res2.columns.index("tok")
        for row in res2.rows:
            assert row[tok_idx] == "[REDACTED]"

        # Ambiguous multi-wildcard fails closed by redacting safely
        res3 = execute_readonly_sql(
            engine,
            "SELECT * FROM demo_users u JOIN demo_organizations o ON u.organization_id = o.id LIMIT 1",
        )
        assert res3.error is None
        assert "pbkdf2:" not in " ".join(str(c) for c in res3.rows[0])
    finally:
        app.extensions["flask_deck"]["deck"].close()


def test_audit_dashboard_and_export_rbac_side_channels() -> None:
    class BaseA(DeclarativeBase):
        pass

    class OrgA(BaseA):
        __tablename__ = "orgs_a"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    class ItemA(BaseA):
        __tablename__ = "items_a"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
        secret_note: Mapped[str | None] = mapped_column(sa.String(80), nullable=True)
        org_id: Mapped[int] = mapped_column(sa.ForeignKey("orgs_a.id"), nullable=False)
        org = sa.orm.relationship(OrgA)

    class ItemAView(ModelView):
        model = ItemA
        list_columns = ("id", "title", "secret_note", "org_id")
        searchable_columns = ("title", "org.name")

    class SecretTag(BaseA):
        __tablename__ = "tags_a"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    engine = sa.create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Sess = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    audit_store = InMemoryAuditStore(max_entries=100)
    deck: Deck | None = None

    try:
        BaseA.metadata.create_all(engine)
        lim_user = DeckUser(id="lim", username="lim", roles=("limited_auditor",))
        roles = [
            Role(name="superadmin", permissions=frozenset({"*"})),
            Role(
                name="limited_auditor",
                permissions=frozenset({"item-as:view", "item-as:export", "audit:view"}),
                masked_fields={"item-as": frozenset({"secret_note"}), "org-as": frozenset({"name"})},
                hidden_fields={"item-as": frozenset({"org_id"})},
            ),
        ]
        auth = RBACAuthProvider(
            roles=roles,
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="admin-password",
                ),
                RBACAuthProvider.make_account(user=lim_user, password="lim-password"),
            ],
        )
        app = Flask(__name__)
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.config["TESTING"] = True
        deck = Deck(app, engine=engine, session_factory=Sess, auth=auth, audit_store=audit_store)
        deck.register(OrgA, ItemAView, SecretTag)

        with Sess() as sess:
            sess.add_all([OrgA(id=1, name="Acme Org"), OrgA(id=2, name="Beta Org")])
            sess.flush()
            sess.add_all(
                [
                    ItemA(id=1, title="Alpha Item", secret_note="secret-alpha", org_id=1),
                    ItemA(id=2, title="Gamma Item", secret_note="secret-gamma", org_id=2),
                ]
            )
            sess.commit()

        audit_store.record(
            make_audit_entry(
                actor_id="admin",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="item-as",
                model_label="Item A",
                record_pk="1",
                record_repr="Alpha Item",
                changes={"secret_token": {"old": "tok_super_secret_1", "new": "tok_super_secret_2"}},
            )
        )
        audit_store.record(
            make_audit_entry(
                actor_id="admin",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="sql_query",
                model_slug="_sql",
                model_label="SQL Console",
                record_pk="0",
                record_repr="SELECT * FROM users",
                changes={},
            )
        )
        audit_store.record(
            make_audit_entry(
                actor_id="admin",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="secret-tags",
                model_label="Secret Tag",
                record_pk="1",
                record_repr="HiddenTag",
                changes={"name": {"old": "old", "new": "new"}},
            )
        )

        c_lim = app.test_client()
        login_as(c_lim, "lim", "lim-password")

        # P0-2: Dashboard does NOT leak unauthorized model ("secret-tags") or unredacted secrets
        dash = c_lim.get("/admin/").get_data(as_text=True)
        assert "HiddenTag" not in dash
        assert "tok_super_secret_2" not in dash

        # P0-3: Audit ledger hides _sql and unauthorized models, and blocks blind search over changes
        audit_html = c_lim.get("/admin/_audit").get_data(as_text=True)
        assert "HiddenTag" not in audit_html
        assert "SELECT * FROM users" not in audit_html
        assert 'value="_sql"' not in audit_html

        blind_probe = c_lim.get("/admin/_audit?q=Alpha").get_data(as_text=True)
        assert "Alpha Item" in blind_probe
        secret_probe = c_lim.get("/admin/_audit?q=tok_super_secret_2").get_data(as_text=True)
        assert "Alpha Item" not in secret_probe

        # Model history respects extra_sensitive_patterns and redacts secret_token
        hist = c_lim.get("/admin/item-as/1/history").get_data(as_text=True)
        assert "tok_super_secret_2" not in hist
        assert "[REDACTED]" in hist

        # P0-4: Export dotted-relation search blocked when target field org.name is masked/hidden
        with Sess() as sess:
            items_view = deck.views["item-as"]
            chunk_iter, _ct, _ext = iter_export_chunks(
                sess,
                items_view,
                fmt="csv",
                auth=auth,
                user=lim_user,
                search_term="Acme",
                views_by_model={OrgA: deck.views["org-as"], ItemA: items_view},
                chunk_size=10,
            )
            csv_text = "".join(chunk_iter)
            assert "Alpha Item" not in csv_text

        exp_q = c_lim.get("/admin/item-as/export.csv?q=Acme")
        assert exp_q.status_code == 200
        assert "Alpha Item" not in exp_q.get_data(as_text=True)

        # Sync export emits audit entry with action="export"
        exp = c_lim.get("/admin/item-as/export.csv")
        assert exp.status_code == 200
        export_entries, _ = audit_store.list_entries(model_slug="item-as")
        assert any(e.action == "export" and e.actor_id == "lim" for e in export_entries)
    finally:
        if deck is not None:
            deck.close()
        engine.dispose()


def test_oidc_require_verified_email_without_allowed_domains() -> None:
    role = Role(name="viewer", permissions=frozenset({"*:view"}))
    cfg = OIDCProviderConfig(
        name="okta",
        label="Okta",
        client_id="cid",
        client_secret="sec",
        authorize_url="https://idp.example.com/authorize",
        token_url="https://idp.example.com/token",
        userinfo_url="https://idp.example.com/userinfo",
        require_verified_email=True,
        allowed_domains=frozenset(),
    )

    def _transport(_method: str, url: str, _headers: Any, _body: Any, _timeout: float) -> tuple[int, dict[str, Any]]:
        if "token" in url:
            return 200, {"access_token": "tok-1"}
        return 200, {"sub": "u1", "email": "alice@anywhere.org", "email_verified": False}

    provider = OIDCAuthProvider(roles=[role], providers=[cfg], http_transport=_transport)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secrets.token_hex(32)

    with app.test_request_context("/admin/sso/okta/login"):
        redirect_url = provider.build_authorize_redirect("okta", redirect_uri="https://app/cb")
        state = parse_qs(urlsplit(redirect_url).query)["state"][0]
        with pytest.raises(PermissionError, match="not verified"):
            provider.complete_callback("okta", code="abc", state=state, redirect_uri="https://app/cb")


def test_bulk_abac_trash_events_jobs_oracle_count_mode_and_falsy_condition(sa_bundle: tuple[Any, ...]) -> None:
    app, deck, _engine, SessionLocal, _audit = sa_bundle

    emitted: list[DeckEvent] = []
    deck.events.subscribe("*", emitted.append)

    item_view = deck.views["items"]
    orig_conditions = item_view.field_conditions
    item_view.field_conditions = {"secret_note": ("is_active", "falsy")}

    c_admin = app.test_client()
    csrf = login_as(c_admin, "admin", "admin-password")

    with SessionLocal() as sess:
        item_ids = [i.id for i in sess.scalars(sa.select(Item).order_by(Item.id.asc())).all()]
    assert len(item_ids) >= 2
    target_id = str(item_ids[-1])

    # Hard delete on Item (which has no soft_delete_column) emits record.deleted
    del_resp = c_admin.post(
        "/admin/items/action/delete",
        data={"_csrf_token": csrf, "selected_pks": [target_id]},
        follow_redirects=False,
    )
    assert del_resp.status_code == 302
    assert any(e.name == "record.deleted" for e in emitted)

    create_resp = c_admin.post(
        "/admin/items/new",
        data={
            "_csrf_token": csrf,
            "code": "FALSY-1",
            "title": "Falsy Test",
            "status": "draft",
            "price": "10.00",
            "tenant_id": "1",
            "secret_note": "visible only when inactive",
        },
        follow_redirects=False,
    )
    assert create_resp.status_code == 302
    item_view.field_conditions = orig_conditions

    # Jobs existence oracle fix: editor without jobs:view_all gets 403 for BOTH missing and other user's job
    job = deck.job_backend.submit(
        name="demo",
        label="Admin Job",
        actor_id="admin",
        actor_name="Admin",
        model_slug="items",
        fn=lambda _ctx: "ok",
    )
    c_editor = app.test_client()
    login_as(c_editor, "alpha_editor", "alpha-password")
    assert c_editor.get(f"/admin/_jobs/{job.id}/artifact").status_code == 403
    assert c_editor.get("/admin/_jobs/nonexistent-id-999/artifact").status_code == 403
    assert c_editor.get(f"/admin/_api/jobs/{job.id}").status_code == 403
    assert c_editor.get("/admin/_api/jobs/nonexistent-id-999").status_code == 403
    assert c_admin.get("/admin/_api/jobs/nonexistent-id-999").status_code == 404

    jobs_html = c_admin.get("/admin/_jobs").get_data(as_text=True)
    assert "data-job-logs>" in jobs_html

    item_view.count_mode = "none"
    list_html = c_admin.get("/admin/items/").get_data(as_text=True)
    assert "Items" in list_html
    item_view.count_mode = "exact"

    # Bulk soft-delete -> bulk restore -> bulk force_delete on demo SupportTicket (which has soft_delete_column)
    demo_app = create_demo_app()
    try:
        demo_deck: Deck = demo_app.extensions["flask_deck"]["deck"]
        c_demo = demo_app.test_client()
        d_csrf = login_as(c_demo, "admin@acme.dev", "deck-demo-2026")
        with demo_app.app_context():
            first_ticket = demo_deck.adapter.get_session().scalars(  # type: ignore[union-attr]
                sa.select(SupportTicket).where(SupportTicket.deleted_at.is_(None)).order_by(SupportTicket.id.asc())
            ).first()
            assert first_ticket is not None
            tid = str(first_ticket.id)

        r_del = c_demo.post(
            "/admin/tickets/action/delete",
            data={"_csrf_token": d_csrf, "selected_pks": [tid]},
            follow_redirects=False,
        )
        assert r_del.status_code == 302
        r_res = c_demo.post(
            "/admin/tickets/action/restore",
            data={"_csrf_token": d_csrf, "selected_pks": [tid]},
            follow_redirects=False,
        )
        assert r_res.status_code == 302
        with demo_app.app_context():
            restored = demo_deck.adapter.get_session().get(SupportTicket, int(tid))  # type: ignore[union-attr]
            assert restored is not None and restored.deleted_at is None

        c_demo.post(
            "/admin/tickets/action/delete",
            data={"_csrf_token": d_csrf, "selected_pks": [tid]},
            follow_redirects=False,
        )
        r_force = c_demo.post(
            "/admin/tickets/action/force_delete",
            data={"_csrf_token": d_csrf, "selected_pks": [tid]},
            follow_redirects=False,
        )
        assert r_force.status_code == 302
        with demo_app.app_context():
            assert demo_deck.adapter.get_session().get(SupportTicket, int(tid)) is None  # type: ignore[union-attr]
    finally:
        demo_app.extensions["flask_deck"]["deck"].close()


def test_bulk_per_object_abac_and_time_input_and_multibind_and_impersonation() -> None:
    class PrimaryBase(DeclarativeBase):
        pass

    class MetricsBase(DeclarativeBase):
        pass

    class ScopedDoc(PrimaryBase):
        __tablename__ = "scoped_docs"
        id: Mapped[int] = mapped_column(primary_key=True)
        owner_id: Mapped[str] = mapped_column(sa.String(40), nullable=False, index=True)
        title: Mapped[str] = mapped_column(sa.String(100), nullable=False)
        window_time: Mapped[time | None] = mapped_column(sa.Time, nullable=True)

    class ScopedDocView(ModelView):
        model = ScopedDoc
        list_columns = ("id", "owner_id", "title", "window_time")

        def scope_query(self, stmt: Any, user: DeckUser) -> Any:
            if user.is_superuser:
                return stmt
            return stmt.where(ScopedDoc.owner_id == user.id)

        @action("stamp", label="Stamp")
        def stamp(self, records: list[ScopedDoc], _form: Any, _user: Any) -> str:
            for r in records:
                r.title = f"Stamped:{r.title}"
            return f"Stamped {len(records)}"

    class BindMetric(MetricsBase):
        __tablename__ = "bind_metrics"
        id: Mapped[int] = mapped_column(primary_key=True)
        metric: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    class BindMetricView(ModelView):
        model = BindMetric
        bind_key = "metrics"

    app = Flask(__name__)
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    eng2 = sa.create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    deck: Deck | None = None
    try:
        with app.app_context():
            PrimaryBase.metadata.create_all(db.engine)
            MetricsBase.metadata.create_all(eng2)
            db.session.add_all(
                [
                    ScopedDoc(id=1, owner_id="alice", title="Alice Doc", window_time=time(9, 30)),
                    ScopedDoc(id=2, owner_id="bob", title="Bob Secret", window_time=time(14, 15)),
                ]
            )
            db.session.commit()
        with sessionmaker(bind=eng2)() as msess:
            msess.add(BindMetric(metric="cpu_ok"))
            msess.commit()

        roles = [
            Role(name="superadmin", permissions=frozenset({"*"})),
            Role(
                name="user",
                permissions=frozenset(
                    {"scoped-docs:view", "scoped-docs:delete", "scoped-docs:action:stamp", "bind-metrics:view"}
                ),
            ),
        ]
        auth = RBACAuthProvider(
            roles=roles,
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="pw",
                ),
                RBACAuthProvider.make_account(user=DeckUser(id="alice", username="alice", roles=("user",)), password="pw"),
                RBACAuthProvider.make_account(user=DeckUser(id="bob", username="bob", roles=("user",)), password="pw"),
            ],
        )
        deck = Deck(
            app,
            db,
            binds={"metrics": eng2},
            auth=auth,
            demo_role_switcher=True,
            enable_impersonation=True,
            demo_credentials=[("admin", "pw", "Admin"), ("alice", "pw", "Alice")],
        )
        deck.register(ScopedDocView, BindMetricView)
        emitted: list[DeckEvent] = []
        deck.events.subscribe("*", emitted.append)

        c_admin = app.test_client()
        csrf_admin = login_as(c_admin, "admin", "pw")
        m_resp = c_admin.get("/admin/bind-metrics/")
        assert m_resp.status_code == 200
        assert "cpu_ok" in m_resp.get_data(as_text=True)

        admin_home = c_admin.get("/admin/").get_data(as_text=True)
        assert "Impersonate" in admin_home

        edit_html = c_admin.get("/admin/scoped-docs/1/edit").get_data(as_text=True)
        assert 'type="time"' in edit_html

        act = c_admin.post(
            "/admin/scoped-docs/action/stamp",
            data={"_csrf_token": csrf_admin, "selected_pks": ["1"]},
            follow_redirects=False,
        )
        assert act.status_code == 302
        assert any(e.name == "action.executed" for e in emitted)

        c_alice = app.test_client()
        csrf_alice = login_as(c_alice, "alice", "pw")
        c_alice.post(
            "/admin/scoped-docs/action/delete",
            data={"_csrf_token": csrf_alice, "selected_pks": ["2"]},
            follow_redirects=False,
        )
        c_alice.post(
            "/admin/scoped-docs/action/stamp",
            data={"_csrf_token": csrf_alice, "selected_pks": ["2"]},
            follow_redirects=False,
        )
        with app.app_context():
            bob_doc = db.session.get(ScopedDoc, 2)
            assert bob_doc is not None
            assert bob_doc.title == "Bob Secret"
    finally:
        if deck is not None:
            deck.close()
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        eng2.dispose()


# ---------------------------------------------------------------------------
# Coverage Suite: events.py, storage.py, query.py, sso.py, cli.py >= 85%
# ---------------------------------------------------------------------------


def test_events_ssrf_hmac_bus_and_pinned_request(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client
    import ipaddress
    import socket

    assert _is_non_public_ip(ipaddress.ip_address("::ffff:127.0.0.1"))
    assert _is_non_public_ip(ipaddress.ip_address("2002:7f00:0001::1"))
    assert _is_non_public_ip(ipaddress.ip_address("2001:0000:4136:e378:8000:63bf:3fff:fdd2"))

    assert not _resolve_and_validate_url("ftp://example.com/hook")[0]
    assert not _resolve_and_validate_url("https:///missing-host")[0]
    assert not _resolve_and_validate_url("https://localhost/hook")[0]
    assert not _resolve_and_validate_url("https://127.0.0.1/hook")[0]
    assert not _resolve_and_validate_url("http://169.254.169.254/latest/meta-data", allow_http=True)[0]

    ok, _reason, ip = _resolve_and_validate_url("http://127.0.0.1:8080/hook", allow_http=True, allow_private_ips=True)
    assert ok and ip == "127.0.0.1"
    ok_host, _r2, ip2 = _resolve_and_validate_url("http://internal.local/hook", allow_http=True, allow_private_ips=True)
    assert ok_host and ip2 is None

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("dns down")))
    ok_dns, reason_dns, _ = _resolve_and_validate_url("https://unknown.invalid/hook")
    assert not ok_dns and "DNS resolution failed" in reason_dns

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    ok_pub, _reason, ip_pub = _resolve_and_validate_url("https://example.com/webhook")
    assert ok_pub and ip_pub == "93.184.216.34"
    assert is_ssrf_safe_url("https://example.com/webhook")[0]

    with pytest.raises(urllib.error.HTTPError):
        _NoRedirectHandler().redirect_request(
            urllib.request.Request("https://example.com/h"),
            None,
            302,
            "Found",
            {},
            "http://127.0.0.1/",
        )

    closed: list[bool] = []

    class _FakeResp:
        def __init__(self, status: int) -> None:
            self.status = status

        def read(self, _n: int = 1024) -> bytes:
            return b"ok"

    class _FakeConn:
        def __init__(self, host: str, port: int, timeout: float = 5.0, **_kw: Any) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout

        def request(self, _method: str, _path: str, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            assert headers is not None and body is not None

        def getresponse(self) -> _FakeResp:
            return _FakeResp(302 if self.host == "1.1.1.2" else 200)

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(http.client, "HTTPConnection", _FakeConn)
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConn)

    _send_pinned_request(
        "https://example.com/hook?a=1",
        pinned_ip="93.184.216.34",
        body=b"{}",
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    _send_pinned_request(
        "http://example.com/hook",
        pinned_ip="93.184.216.34",
        body=b"{}",
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    with pytest.raises(ValueError, match="redirect"):
        _send_pinned_request(
            "http://example.com/hook",
            pinned_ip="1.1.1.2",
            body=b"{}",
            headers={},
            timeout=5.0,
        )
    assert len(closed) >= 3

    class _FakeOpenerResp:
        def __enter__(self) -> _FakeOpenerResp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

        def read(self, _n: int = 1024) -> bytes:
            return b"ok"

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_h: SimpleNamespace(open=lambda *_a, **_kw: _FakeOpenerResp()),
    )
    _send_pinned_request(
        "http://internal.local:9999/hook",
        pinned_ip=None,
        body=b"{}",
        headers={"X-Test": "1"},
        timeout=2.0,
    )

    seen: list[DeckEvent] = []
    bus = DeckEventBus()
    bus.subscribe("record.created", seen.append)
    bus.subscribe("record.created", lambda _ev: (_ for _ in ()).throw(RuntimeError("boom")))
    ev = DeckEvent(name="record.created", model_slug="items", record_pk="1", actor_id="admin", payload={"title": "A"})
    errors = bus.emit(ev)
    assert len(seen) == 1
    assert len(errors) == 1 and "boom" in errors[0]
    assert "sha256=" in sign_webhook_payload(b"body", "secret-key")

    delivered: list[tuple[str, bytes, dict[str, str], float]] = []
    sink = WebhookSink(
        "https://93.184.216.34/hook",
        secret="top-secret-key-123456",
        events=("record.created",),
        transport=lambda u, b, h, t: (delivered.append((u, b, h, t)), 200)[1],
    )
    assert sink.matches("record.created")
    assert not sink.matches("action.executed")
    sink(ev)
    sink(DeckEvent(name="action.executed"))
    assert len(delivered) == 1
    assert delivered[0][2]["X-Deck-Signature"] == sign_webhook_payload(delivered[0][1], "top-secret-key-123456")

    with pytest.raises(ValueError, match="at least 16"):
        WebhookSink("https://93.184.216.34/hook", secret="short")


def test_storage_backends_mime_sniff_and_dimensions(tmp_path: Path) -> None:
    png = _make_png(16, 12)
    assert detect_mime_from_bytes(png) == "image/png"
    assert parse_image_dimensions(png, "image/png") == (16, 12)

    gif = _make_gif(10, 8, with_extensions=True)
    assert detect_mime_from_bytes(gif) == "image/gif"
    assert parse_image_dimensions(gif, "image/gif") == (12, 9)

    for subtype in (b"VP8L", b"VP8X", b"VP8 "):
        wp = _make_webp(subtype, 20, 14)
        assert detect_mime_from_bytes(wp) == "image/webp"
        assert parse_image_dimensions(wp, "image/webp") == (20, 14)

    jpg = _make_jpeg(32, 24)
    assert detect_mime_from_bytes(jpg) == "image/jpeg"
    assert parse_image_dimensions(jpg, "image/jpeg") == (32, 24)

    assert detect_mime_from_bytes(b"%PDF-1.4\n...") == "application/pdf"
    assert detect_mime_from_bytes(b"PK\x03\x04...") == "application/zip"
    assert detect_mime_from_bytes(b"\x1f\x8b\x08...") == "application/gzip"
    assert detect_mime_from_bytes(b"\x00\x01binary\x02") is None
    assert detect_mime_from_bytes(b"\xef\xbb\xbf<!-- comment --><svg></svg>") == "image/svg+xml"
    assert detect_mime_from_bytes(b"<script>alert(1)</script>") is None
    assert detect_mime_from_bytes(b'{"k": 1}', filename="data.json") == "application/json"
    assert detect_mime_from_bytes(b"a,b\n1,2\n", filename="rows.csv") == "text/csv"
    assert detect_mime_from_bytes(b"hello", filename="note.txt") == "text/plain"

    cfg = FileFieldConfig(
        storage=MemoryFileStorage(),
        kind="image",
        allowed_mimes=frozenset({"image/png"}),
        max_bytes=200,
        max_image_pixels=10,
    )
    with pytest.raises(ValueError, match="pixels"):
        validate_and_read_upload(io.BytesIO(png), filename="a.png", config=cfg, default_max_bytes=1000)
    with pytest.raises(ValueError, match="exceeds"):
        validate_and_read_upload(
            io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"0" * 300), filename="b.png", config=cfg, default_max_bytes=1000
        )
    with pytest.raises(ValueError):
        validate_and_read_upload(io.BytesIO(b"<svg></svg>"), filename="evil.svg", config=cfg, default_max_bytes=1000)

    local = LocalFileStorage(tmp_path)
    sf = local.save(png, key="items/test.png", content_type="image/png")
    assert sf.size_bytes == len(png)
    assert local.exists("items/test.png")
    fh, ctype = local.open("items/test.png")
    try:
        assert fh.read() == png
        assert ctype == "image/png"
    finally:
        fh.close()
    assert local.presigned_url("items/test.png") is None
    with pytest.raises(ValueError):
        local.open("../escape.png")
    local.delete("../escape.png")
    local.delete("items/test.png")
    assert not local.exists("items/test.png")
    with pytest.raises(FileNotFoundError):
        local.open("items/missing.png")

    mem = MemoryFileStorage()
    mem.save(png, key="a/b.png", content_type="image/png")
    assert mem.exists("a/b.png")
    assert mem.presigned_url("a/b.png") is None
    mh, _ = mem.open("a/b.png")
    try:
        assert mh.read() == png
    finally:
        mh.close()
    mem.delete("a/b.png")
    assert not mem.exists("a/b.png")
    assert not mem.exists("../bad")

    objects: dict[str, tuple[bytes, str]] = {}

    class _FakeS3:
        def put_object(self, **kw: Any) -> None:
            objects[kw["Key"]] = (kw["Body"], kw["ContentType"])

        def get_object(self, **kw: Any) -> dict[str, Any]:
            if kw["Key"] not in objects:
                exc = Exception("NoSuchKey")
                exc.response = {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}}  # type: ignore[attr-defined]
                raise exc
            data, ctype = objects[kw["Key"]]
            return {"Body": io.BytesIO(data), "ContentType": ctype}

        def delete_object(self, **kw: Any) -> None:
            objects.pop(kw["Key"], None)

        def head_object(self, **kw: Any) -> dict[str, Any]:
            if kw["Key"] not in objects:
                raise KeyError(kw["Key"])
            return {}

        def generate_presigned_url(self, _op: str, Params: dict[str, Any], ExpiresIn: int) -> str:
            return f"https://s3.example/{Params['Bucket']}/{Params['Key']}?ttl={ExpiresIn}"

    with pytest.raises(ValueError):
        S3StorageBackend("")
    s3 = S3StorageBackend("my-bucket", prefix="uploads", client=_FakeS3())
    s3.save(b"%PDF-1.4\n%", key="doc/a.pdf", content_type="application/pdf")
    assert s3.exists("doc/a.pdf")
    sh, sc = s3.open("doc/a.pdf")
    try:
        assert sh.read().startswith(b"%PDF")
        assert sc == "application/pdf"
    finally:
        sh.close()
    url = s3.presigned_url("doc/a.pdf", expires_in=120)
    assert url is not None and "ttl=120" in url
    s3.delete("doc/a.pdf")
    assert not s3.exists("doc/a.pdf")
    with pytest.raises(FileNotFoundError):
        s3.open("doc/missing.pdf")


def test_query_filters_arrays_json_estimation_and_aggregates(sa_bundle: tuple[Any, ...]) -> None:
    from flask_deck.introspection import introspect_model

    class BaseQ(DeclarativeBase):
        pass

    class SlimBase(DeclarativeBase):
        pass

    class ComplexRow(BaseQ):
        __tablename__ = "complex_rows"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
        amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), nullable=False)
        rating: Mapped[float] = mapped_column(sa.Float, nullable=False)
        ext_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
        born_on: Mapped[date] = mapped_column(sa.Date, nullable=False)
        at_time: Mapped[time] = mapped_column(sa.Time, nullable=False)
        created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
        deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
        is_archived: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
        meta: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
        tags_arr: Mapped[Any] = mapped_column(sa.ARRAY(sa.String), nullable=True)
        nums_arr: Mapped[Any] = mapped_column(sa.ARRAY(sa.Integer), nullable=True)
        floats_arr: Mapped[Any] = mapped_column(sa.ARRAY(sa.Float), nullable=True)
        bools_arr: Mapped[Any] = mapped_column(sa.ARRAY(sa.Boolean), nullable=True)

    meta = introspect_model(ComplexRow)
    uid = uuid.uuid4()

    # Coercion & filter operator branches (valid + invalid)
    assert build_filter_condition(meta, "missing", "x") is None
    assert build_filter_condition(meta, "name", "1", op="null") is not None
    assert build_filter_condition(meta, "name", "0", op="null") is not None
    assert build_filter_condition(meta, "name", "invalid", op="null") is None
    assert build_filter_condition(meta, "meta", "tier", op="has_key", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "meta", "tier", op="has_key", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "meta", "tier=pro", op="path", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "meta", "tier=pro", op="path", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "meta", '{"tier":"pro","n":null}', op="json_contains", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "meta", '{"tier":"pro","n":null}', op="json_contains", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "meta", "{bad json", op="json_contains", dialect_name="sqlite") is None
    assert build_filter_condition(meta, "meta", '{"a":{"b":{"c":{"d":{"e":1}}}}}', op="json_contains", dialect_name="sqlite") is None
    assert build_filter_condition(meta, "meta", "pro", op="contains", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "meta", "pro", op="badop", dialect_name="sqlite") is None
    assert build_filter_condition(meta, "tags_arr", "ops", op="array_contains", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "tags_arr", "ops,sec", op="array_any", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "tags_arr", "ops", op="array_contains", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "tags_arr", "ops,sec", op="array_any", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "nums_arr", "12,bad", op="array_any", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "floats_arr", "1.5,bad", op="array_any", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "bools_arr", "true,bad", op="array_any", dialect_name="sqlite") is not None
    for preset in ("today", "7d", "30d", "month"):
        assert build_filter_condition(meta, "created_at", preset, op="preset") is not None
    assert build_filter_condition(meta, "created_at", "bad", op="preset") is None
    assert build_filter_condition(meta, "name", "Al", op="startswith") is not None
    assert build_filter_condition(meta, "name", "   ", op="contains") is None
    assert build_filter_condition(meta, "amount", "12.50", op="gte") is not None
    assert build_filter_condition(meta, "amount", "bad", op="gte") is None
    assert build_filter_condition(meta, "rating", "4.5", op="lt") is not None
    assert build_filter_condition(meta, "rating", "bad", op="lt") is None
    assert build_filter_condition(meta, "ext_id", str(uid)) is not None
    assert build_filter_condition(meta, "ext_id", "bad-uuid") is None
    assert build_filter_condition(meta, "born_on", "2026-01-15", op="gt") is not None
    assert build_filter_condition(meta, "born_on", "bad-date", op="gt") is None
    assert build_filter_condition(meta, "at_time", "09:30:00", op="lte") is not None
    assert build_filter_condition(meta, "at_time", "bad-time", op="lte") is None
    assert build_filter_condition(meta, "created_at", "2026-01-15", op="lte") is not None
    assert build_filter_condition(meta, "created_at", "bad-dt", op="lte") is None
    assert build_filter_condition(meta, "is_archived", "yes") is not None
    assert build_filter_condition(meta, "is_archived", "invalid-bool") is None
    assert build_filter_condition(meta, "id", "1", op="neq") is not None
    assert build_filter_condition(meta, "id", "bad", op="neq") is None
    assert build_filter_condition(meta, "id", "1,2,3") is not None
    assert build_filter_condition(meta, "id", "") is None

    assert soft_delete_predicate(meta, None) is None
    assert soft_delete_predicate(meta, "missing") is None
    assert soft_delete_predicate(meta, "is_archived", trashed=True) is not None
    assert soft_delete_predicate(meta, "is_archived", trashed=False) is not None

    clause, joins = build_search_clause(meta, ["name", "amount", "missing"], "12")
    assert clause is not None and joins == []
    assert build_search_clause(meta, ["name"], "") == (None, [])

    class SlimRow(SlimBase):
        __tablename__ = "slim_rows"
        id: Mapped[int] = mapped_column(primary_key=True)
        val: Mapped[int] = mapped_column(sa.Integer, nullable=False)
        deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    engine = sa.create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    slim_meta = introspect_model(SlimRow)
    try:
        SlimBase.metadata.create_all(engine)
        Sess = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with Sess() as sess:
            slim_items = [SlimRow(id=1, val=10), SlimRow(id=2, val=30), SlimRow(id=3, val=50)]
            sess.add_all(slim_items)
            sess.commit()
            assert estimate_table_rows(sess, slim_meta) is None

            agg = compute_page_aggregates(slim_items, {"val": "avg"})
            assert agg["val"] == ("AVG", 30.0)
            for agg_op, exp_val in (("sum", 90.0), ("min", 10.0), ("max", 50.0)):
                res_a = compute_page_aggregates(slim_items, {"val": agg_op})
                assert res_a["val"] == (agg_op.upper(), exp_val)

            tabs, trash_cnt = compute_quick_tab_counts(
                sess,
                slim_meta,
                (),
                (QuickTab("all", "All"), QuickTab("hi", "Hi", filters={"val__gte": 20})),
                dialect_name="sqlite",
                soft_delete_column="deleted_at",
            )
            assert tabs == {"all": 3, "hi": 2} and trash_cnt == 0

            # execute_list_query keyset cursor & estimated/none count modes
            p1 = execute_list_query(
                sess,
                slim_meta,
                base_stmt=sa.select(SlimRow),
                displayed_columns=("id", "val"),
                searchable_columns=("val",),
                filterable_columns=frozenset({"val"}),
                sortable_columns=frozenset({"id", "val"}),
                quick_tabs=(QuickTab("all", "All"),),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="val",
                sort_dir="asc",
                default_sort=("id", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="estimated",
                cursor_secret=b"cursor-test-secret",
                soft_delete_column="deleted_at",
            )
            assert len(p1.items) == 2 and p1.next_cursor is not None
            p2 = execute_list_query(
                sess,
                slim_meta,
                base_stmt=sa.select(SlimRow),
                displayed_columns=("id", "val"),
                searchable_columns=("val",),
                filterable_columns=frozenset({"val"}),
                sortable_columns=frozenset({"id", "val"}),
                quick_tabs=(QuickTab("all", "All"),),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="val",
                sort_dir="asc",
                default_sort=("id", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="none",
                after_cursor=p1.next_cursor,
                cursor_secret=b"cursor-test-secret",
                soft_delete_column="deleted_at",
            )
            assert len(p2.items) == 1 and p2.prev_cursor is not None
            p_back = execute_list_query(
                sess,
                slim_meta,
                base_stmt=sa.select(SlimRow),
                displayed_columns=("id", "val"),
                searchable_columns=("val",),
                filterable_columns=frozenset({"val"}),
                sortable_columns=frozenset({"id", "val"}),
                quick_tabs=(QuickTab("all", "All"),),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="val",
                sort_dir="asc",
                default_sort=("id", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="exact",
                before_cursor=p2.prev_cursor,
                cursor_secret=b"cursor-test-secret",
                soft_delete_column="deleted_at",
            )
            assert len(p_back.items) == 2
    finally:
        engine.dispose()

    # Fake PG session for estimate_table_rows reltuples branches
    @contextmanager
    def _noop_nested() -> Any:
        yield None

    class _FakePGSess:
        def __init__(self, val: Any, raise_err: bool = False) -> None:
            self._val = val
            self._raise = raise_err

        def get_bind(self) -> Any:
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def begin_nested(self) -> Any:
            return _noop_nested()

        def execute(self, _stmt: Any) -> Any:
            if self._raise:
                raise RuntimeError("pg fail")
            return SimpleNamespace(scalar=lambda: self._val)

    assert estimate_table_rows(_FakePGSess(42), slim_meta) == 42  # type: ignore[arg-type]
    assert estimate_table_rows(_FakePGSess(-1), slim_meta) is None  # type: ignore[arg-type]
    assert estimate_table_rows(_FakePGSess(None), slim_meta) is None  # type: ignore[arg-type]
    assert estimate_table_rows(_FakePGSess(0, raise_err=True), slim_meta) is None  # type: ignore[arg-type]

    # Dotted search across Tenant relation via sa_bundle
    _app, deck, _eng, SessionLocal, _audit = sa_bundle
    item_view = deck.views["items"]
    with SessionLocal() as sess:
        page_res = execute_list_query(
            sess,
            item_view.meta,
            base_stmt=sa.select(Item),
            displayed_columns=("id", "title", "tenant"),
            searchable_columns=("title", "tenant.name"),
            filterable_columns=frozenset({"status"}),
            sortable_columns=frozenset({"id", "title"}),
            quick_tabs=item_view.quick_tabs,
            active_tab_key="active",
            search_term="Alpha",
            filter_params={"status": "active", "tenant_id": ""},
            sort_by="title",
            sort_dir="desc",
            default_sort=("id", "asc"),
            page=1,
            page_size=20,
            max_page_size=100,
        )
        assert page_res.pagination_mode == "offset" and page_res.total >= 0

        # Invalid/unknown sort falls back to default_sort
        page_res2 = execute_list_query(
            sess,
            item_view.meta,
            base_stmt=sa.select(Item),
            displayed_columns=("id", "title"),
            searchable_columns=("title", "tenant.name"),
            filterable_columns=frozenset({"status"}),
            sortable_columns=frozenset({"id", "title"}),
            quick_tabs=item_view.quick_tabs,
            active_tab_key=None,
            search_term="",
            filter_params={"unknown_col": "x"},
            sort_by="nonexistent",
            sort_dir="asc",
            default_sort=None,
            page=99,
            page_size=20,
            max_page_size=100,
            count_mode="estimated",
        )
        assert page_res2.page == 1


def test_sso_transport_pkce_callback_and_session(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="https://"):
        _default_http_transport("GET", "http://insecure.example/userinfo", {}, None, 5.0)
    with pytest.raises(ValueError, match="https://"):
        OIDCProviderConfig(
            name="bad",
            label="Bad",
            client_id="cid",
            client_secret="sec",
            authorize_url="http://idp/a",
            token_url="https://idp/t",
            userinfo_url="https://idp/u",
        )

    class _MockResp:
        def __init__(self, status: int, body: bytes) -> None:
            self.status = status
            self._body = body

        def __enter__(self) -> _MockResp:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

        def read(self, _n: int = 1024) -> bytes:
            return self._body

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_h: SimpleNamespace(open=lambda *_a, **_kw: _MockResp(200, b'{"ok": true}')),
    )
    st, payload = _default_http_transport("GET", "https://idp.example/userinfo", {}, None, 5.0)
    assert st == 200 and payload == {"ok": True}

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_h: SimpleNamespace(open=lambda *_a, **_kw: _MockResp(200, b"[1, 2]")),
    )
    with pytest.raises(PermissionError, match="non-object"):
        _default_http_transport("GET", "https://idp.example/userinfo", {}, None, 5.0)

    def _bad_http_json(*_a: Any, **_kw: Any) -> Any:
        raise urllib.error.HTTPError("https://idp.example/t", 400, "bad", {}, io.BytesIO(b'{"error":"invalid"}'))  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_h: SimpleNamespace(open=_bad_http_json))
    st400, p400 = _default_http_transport("POST", "https://idp.example/t", {}, b"x", 5.0)
    assert st400 == 400 and p400["error"] == "invalid"

    def _bad_http_raw(*_a: Any, **_kw: Any) -> Any:
        raise urllib.error.HTTPError("https://idp.example/t", 502, "bad gw", {}, io.BytesIO(b"not-json"))  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_h: SimpleNamespace(open=_bad_http_raw))
    st502, p502 = _default_http_transport("POST", "https://idp.example/t", {}, b"x", 5.0)
    assert st502 == 502 and "error" in p502

    def _net_err(*_a: Any, **_kw: Any) -> Any:
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_h: SimpleNamespace(open=_net_err))
    with pytest.raises(PermissionError, match="communication failed"):
        _default_http_transport("GET", "https://idp.example/u", {}, None, 5.0)

    v, c = generate_pkce_pair()
    assert v and c and v != c

    role_admin = Role(name="admin", permissions=frozenset({"*"}))
    role_view = Role(name="viewer", permissions=frozenset({"*:view"}))
    cfg = OIDCProviderConfig(
        name="google",
        label="Google",
        client_id="cid",
        client_secret="sec",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        role_claim="groups",
        role_mapping={"ops": "admin"},
        superuser_groups=frozenset({"root"}),
        allowed_domains=frozenset({"acme.dev"}),
        require_verified_email=True,
    )

    scenario = {"mode": "ok"}

    def _transport(_m: str, url: str, _h: Any, _b: Any, _t: float) -> tuple[int, dict[str, Any]]:
        m = scenario["mode"]
        if "token" in url:
            if m == "tok_err":
                return 500, {"error": "down"}
            if m == "no_at":
                return 200, {}
            return 200, {"access_token": "tok"}
        if m == "ui_err":
            return 401, {"error": "unauth"}
        if m == "no_sub":
            return 200, {"email": "ada@acme.dev"}
        if m == "bad_domain":
            return 200, {"sub": "u-1", "email": "ada@evil.com", "email_verified": True}
        return 200, {
            "sub": "u-42",
            "email": "ada@acme.dev",
            "email_verified": True,
            "name": "Ada",
            "groups": ["ops", "root"],
        }

    sso = OIDCAuthProvider(roles=[role_admin, role_view], providers=[cfg], http_transport=_transport)
    assert len(sso.get_sso_providers()) == 1
    assert sso.get_sso_provider("google") is cfg
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    with app.test_request_context("/"):
        assert sso.get_current_user() is None
        with pytest.raises(ValueError, match="Unknown OIDC provider"):
            sso.build_authorize_redirect("unknown", redirect_uri="https://app/cb")
        with pytest.raises(ValueError, match="Unknown OIDC provider"):
            sso.complete_callback("unknown", code="c", state="s", redirect_uri="https://app/cb")

        sso.build_authorize_redirect("google", redirect_uri="https://app/cb", next_url="/admin/items/")
        with pytest.raises(PermissionError, match="state"):
            sso.complete_callback("google", code="c", state="wrong", redirect_uri="https://app/cb")

        for err_mode in ("tok_err", "no_at", "ui_err", "no_sub", "bad_domain"):
            scenario["mode"] = err_mode
            u = sso.build_authorize_redirect("google", redirect_uri="https://app/cb")
            st_tok = parse_qs(urlsplit(u).query)["state"][0]
            with pytest.raises(PermissionError):
                sso.complete_callback("google", code="code123", state=st_tok, redirect_uri="https://app/cb")

        scenario["mode"] = "ok"
        auth_url2 = sso.build_authorize_redirect("google", redirect_uri="https://app/cb", next_url="/admin/items/")
        state2 = parse_qs(urlsplit(auth_url2).query)["state"][0]
        user, nxt = sso.complete_callback("google", code="code123", state=state2, redirect_uri="https://app/cb")
        assert user.is_superuser and "admin" in user.roles and nxt == "/admin/items/"
        sso.login_user(user)
        loaded = sso.get_current_user()
        assert loaded is not None and loaded.email == "ada@acme.dev"
        sso.logout_user()
        assert sso.get_current_user() is None


def test_cli_commands_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    empty_app = Flask("empty")
    empty_app.config["TESTING"] = True
    runner = empty_app.test_cli_runner()
    res_info = runner.invoke(deck_cli, ["info"])
    assert "No Flask-Deck" in res_info.output
    res_audit = runner.invoke(deck_cli, ["audit"])
    assert "No Flask-Deck" in res_audit.output

    clean_app = Flask("clean")
    clean_app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=True,
        TESTING=True,
    )
    eng = sa.create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SampleBase.metadata.create_all(eng)
    auth = RBACAuthProvider(
        roles=[Role(name="admin", permissions=frozenset({"*"}))],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="a", username="a", roles=("admin",)),
                password="very-long-strong-password-123",
            )
        ],
    )
    from flask_deck.jobs import SQLAlchemyJobBackend

    deck = Deck(
        clean_app,
        engine=eng,
        auth=auth,
        job_backend=SQLAlchemyJobBackend(eng),
        job_storage=LocalFileStorage(tmp_path / "jobs"),
        config=DeckConfig(
            environment="production",
            max_upload_bytes=1024 * 1024,
            require_mfa_for_superusers=True,
            encryption_key=secrets.token_urlsafe(32),
        ),
    )
    deck.register(Tenant)
    try:
        r_ok = clean_app.test_cli_runner().invoke(deck_cli, ["audit"])
        assert r_ok.exit_code == 0
        assert "Zero security" in r_ok.output

        ran: list[tuple[str, int]] = []
        created_apps: list[Flask] = []

        def _fake_run(self_app: Flask, host: str = "127.0.0.1", port: int = 5055, **_kw: Any) -> None:
            created_apps.append(self_app)
            ran.append((host, port))

        monkeypatch.setattr(Flask, "run", _fake_run)
        r_demo = runner.invoke(deck_cli, ["demo", "--port", "5099"])
        assert r_demo.exit_code == 0
        assert ran == [("127.0.0.1", 5099)]
        for a in created_apps:
            for d in a.extensions.get("flask_deck", {}).values():
                d.close()
    finally:
        deck.close()
        eng.dispose()

    assert main(["version"]) == 0
    _ = capsys.readouterr()
    called: list[bool] = []
    monkeypatch.setattr("flask_deck.cli._run_demo", lambda **_kw: called.append(True))
    assert main(["demo"]) == 0 and called == [True]
