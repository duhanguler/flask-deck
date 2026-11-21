from __future__ import annotations

import io
import ipaddress
import struct
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    BasicAuthProvider,
    CurrencyFormatter,
    Deck,
    DeckConfig,
    DeckUser,
    FileFieldConfig,
    InMemoryAuditStore,
    InMemoryMFAStore,
    LocalFileStorage,
    ModelView,
    ProgressBarFormatter,
    RBACAuthProvider,
    RelativeTimeFormatter,
    Role,
    S3StorageBackend,
    ThreadPoolJobBackend,
    action,
    compute_totp,
)
from flask_deck.charts import (
    render_area_chart,
    render_bar_chart,
    render_donut_chart,
    render_gauge_chart,
)
from flask_deck.deck import MFA_SETUP_SECRET_KEY
from flask_deck.events import _is_non_public_ip, _NoRedirectHandler, _resolve_and_validate_url
from flask_deck.formatters import Formatter
from flask_deck.i18n import format_locale_decimal
from flask_deck.introspection import introspect_model
from flask_deck.query import build_filter_condition, execute_list_query
from flask_deck.security import (
    LoginRateLimiter,
    build_csp_header,
    is_safe_display_url,
    sanitize_csv_cell,
)
from flask_deck.sql_console import (
    execute_readonly_sql,
    format_sql_result_csv,
    validate_readonly_sql,
)
from flask_deck.storage import MemoryFileStorage, detect_mime_from_bytes, parse_image_dimensions
from tests.conftest import extract_csrf, login_as

# ---------------------------------------------------------------------------
# 1. SQL Console Hardening (Lexer, Aliases, Internal Tables, Dangerous Funcs)
# ---------------------------------------------------------------------------


def test_sql_console_lexer_redaction_and_bypass_defenses() -> None:
    # Comment-in-string smuggling must NOT hide a second statement
    with pytest.raises(ValueError):
        validate_readonly_sql("SELECT '/*'; DROP TABLE demo_users; SELECT '*/'")

    # Writable CTEs & transaction control must be rejected
    with pytest.raises(ValueError):
        validate_readonly_sql("WITH x AS (DELETE FROM demo_users RETURNING *) SELECT * FROM x")
    with pytest.raises(ValueError):
        validate_readonly_sql("SELECT 1; COMMIT")

    # Internal MFA / credential tables & dangerous PG functions must be blocked
    with pytest.raises(ValueError):
        validate_readonly_sql("SELECT * FROM _flask_deck_mfa")
    with pytest.raises(ValueError):
        validate_readonly_sql("SELECT pg_read_binary_file('/etc/passwd')")
    with pytest.raises(ValueError):
        validate_readonly_sql("SELECT set_config('log_statement', 'none', false)")

    # Column-alias bypass: SELECT password_hash AS p MUST still redact col index 1
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE u (id INTEGER PRIMARY KEY, name TEXT, password_hash TEXT, api_token TEXT)"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO u VALUES (1, 'Ada', 'pbkdf2:sha256:secret', 'tok_live_999')"
                )
            )
        res = execute_readonly_sql(
            engine, "SELECT id, name, password_hash AS p, api_token t FROM u"
        )
        assert res.error is None
        assert res.columns == ("id", "name", "p", "t")
        assert res.rows == ((1, "Ada", "[REDACTED]", "[REDACTED]"),)

        # CTE/subquery attempting to smuggle sensitive column under opaque alias is blocked
        res_cte = execute_readonly_sql(
            engine, "WITH c AS (SELECT id, password_hash AS x FROM u) SELECT id, x FROM c"
        )
        assert res_cte.error is not None

        # CSV column header formula injection neutralization
        csv_text = format_sql_result_csv(
            ("=HYPERLINK(\"https://evil.example\")", "name"),
            (("1", "\n=SUM(A1:A2)"),),
            sanitize_csv=True,
        )
        assert "'=HYPERLINK" in csv_text
        assert "'\n=SUM(A1:A2)" in csv_text
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# 2. SSRF, Security Primitives & Distributed Login Rate Limiting
# ---------------------------------------------------------------------------


def test_webhook_ssrf_and_security_primitives() -> None:
    # CGNAT (Alibaba metadata 100.100.100.200) & IPv4-mapped IPv6 loopback must be blocked
    assert _is_non_public_ip(ipaddress.ip_address("100.100.100.200")) is True
    assert _is_non_public_ip(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert _is_non_public_ip(ipaddress.ip_address("169.254.169.254")) is True
    assert _is_non_public_ip(ipaddress.ip_address("8.8.8.8")) is False

    # Invalid port & loopback rejected cleanly
    ok_port, reason_port, _ = _resolve_and_validate_url("https://example.com:999999/hook")
    assert ok_port is False and "port" in reason_port.lower()
    ok_loop, _, _ = _resolve_and_validate_url("http://127.0.0.1:8080/hook", allow_http=True)
    assert ok_loop is False

    # 3xx redirects blocked by _NoRedirectHandler
    handler = _NoRedirectHandler()
    req = urllib.request.Request("https://hooks.example.com/events")
    with pytest.raises(urllib.error.HTTPError, match="SSRF guard blocked"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1/")  # type: ignore[arg-type]

    # URL & CSV & CSP hardening
    assert is_safe_display_url("/\\evil.com") is False
    assert is_safe_display_url("\x00https://example.com") is False
    assert is_safe_display_url("https://example.com/ok") is True
    assert sanitize_csv_cell("\n=CMD|' /C calc'!A0").startswith("'")

    with pytest.raises(ValueError):
        DeckConfig(csp_img_sources=("https://ok.com; script-src 'unsafe-inline'",))
    csp = build_csp_header(
        "validnonce123", extra_img_sources=("https://ok.com; script-src 'unsafe-inline'",)
    )
    assert "unsafe-inline" not in csp
    csp_bad_nonce = build_csp_header("bad'nonce;script-src *")
    assert "script-src *" not in csp_bad_nonce
    assert ";script-src" not in csp_bad_nonce

    # Distributed IP rotation against a single username triggers per-account bucket (2x threshold)
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=120)
    for i in range(6):
        limiter.record_failure(f"198.51.100.{i + 1}", "admin")
    locked, retry_after = limiter.is_locked("203.0.113.99", "admin")
    assert locked is True and retry_after > 0


# ---------------------------------------------------------------------------
# 3. Multi-Role RBAC Field Restriction Collapse & @deck.page Permission
# ---------------------------------------------------------------------------


def test_multi_role_rbac_preserves_field_restrictions_and_page_permission() -> None:
    auth = RBACAuthProvider(
        roles=[
            Role(
                name="support",
                permissions=frozenset({"users:view", "users:edit"}),
                masked_fields={"users": frozenset({"email"})},
                hidden_fields={"users": frozenset({"ssn"})},
                readonly_fields={"users": frozenset({"tier"})},
            ),
            Role(
                name="auditor",
                permissions=frozenset({"audit:view"}),
            ),
            Role(
                name="viewer",
                permissions=frozenset({"*:view"}),
            ),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="u1", username="combo", roles=("support", "auditor")),
                password="pw",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="u2", username="viewonly", roles=("viewer",)),
                password="pw",
            ),
        ],
    )
    combo_user = DeckUser(id="u1", username="combo", roles=("support", "auditor"))
    assert auth.masked_fields_for(combo_user, "users") == frozenset({"email"})
    assert auth.hidden_fields_for(combo_user, "users") == frozenset({"ssn"})
    assert auth.readonly_fields_for(combo_user, "users") == frozenset({"tier"})

    # Explicit @deck.page(permission="billing:admin") must NOT be bypassed by *:view
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long!"
        app.config["TESTING"] = True
        deck = Deck(app, engine=engine, session_factory=sessionmaker(bind=engine), auth=auth, auto_audit=False)

        @deck.page("billing-secrets", title="Billing Secrets", permission="billing:admin")
        def _billing_page(_ctx: Any) -> list[Any]:
            return []

        client = app.test_client()
        login_as(client, "viewonly", "pw")
        resp = client.get("/admin/_page/billing-secrets")
        assert resp.status_code == 403
        # Sidebar must also omit the forbidden custom page
        dash = client.get("/admin/").get_data(as_text=True)
        assert "Billing Secrets" not in dash
        deck.close()
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# 4. MFA Superuser Enforcement, Re-Auth Disable, Impersonation & Read-Only
# ---------------------------------------------------------------------------


def test_mfa_enforcement_disable_reauth_and_impersonation_block() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long!"
        app.config["TESTING"] = True
        mfa_store = InMemoryMFAStore()
        auth = RBACAuthProvider(
            roles=[
                Role(name="admin", permissions=frozenset({"*"})),
                Role(name="editor", permissions=frozenset({"*:view"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="su", username="boss", roles=("admin",), is_superuser=True),
                    password="pw",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="ed", username="alice", roles=("editor",)),
                    password="pw",
                ),
            ],
        )
        deck = Deck(
            app,
            engine=engine,
            session_factory=sessionmaker(bind=engine),
            auth=auth,
            mfa_store=mfa_store,
            require_mfa_for_superusers=True,
            enable_impersonation=True,
            impersonate_read_only=True,
            auto_audit=False,
        )

        # 1. Superuser is redirected to /_security/mfa until enrolled
        c_su = app.test_client()
        r_login = c_su.get("/admin/login")
        tok = extract_csrf(r_login.get_data(as_text=True))
        c_su.post("/admin/login", data={"username": "boss", "password": "pw", "_csrf_token": tok})
        r_dash = c_su.get("/admin/", follow_redirects=False)
        assert r_dash.status_code == 302
        assert "/admin/_security/mfa" in r_dash.headers["Location"]

        # Enroll superuser in MFA
        mfa_page = c_su.get("/admin/_security/mfa").get_data(as_text=True)
        tok2 = extract_csrf(mfa_page)
        with c_su.session_transaction() as sess:
            secret = sess[MFA_SETUP_SECRET_KEY]
        code = compute_totp(secret)
        r_en = c_su.post(
            "/admin/_security/mfa",
            data={"_csrf_token": tok2, "action": "enable", "code": code},
        )
        assert r_en.status_code == 200
        assert mfa_store.get("su") is not None and mfa_store.get("su").enabled  # type: ignore[union-attr]

        # Dashboard is now unlocked
        assert c_su.get("/admin/").status_code == 200

        # Superuser CANNOT disable MFA while require_mfa_for_superusers=True
        r_dis = c_su.post(
            "/admin/_security/mfa",
            data={"_csrf_token": tok2, "action": "disable", "code": code},
        )
        assert "cannot be disabled" in r_dis.get_data(as_text=True).lower()
        assert mfa_store.get("su") is not None

        # Start impersonating alice -> /_security/mfa MUST return 403
        r_imp = c_su.post(
            "/admin/_impersonate/start",
            data={"_csrf_token": tok2, "target_user_id": "ed"},
            follow_redirects=False,
        )
        assert r_imp.status_code == 302
        assert c_su.get("/admin/_security/mfa").status_code == 403

        # 2. Non-superuser disabling MFA requires a valid current TOTP code (and rejects replay!)
        c_ed = app.test_client()
        tok_ed = login_as(c_ed, "alice", "pw")
        c_ed.get("/admin/_security/mfa")
        with c_ed.session_transaction() as sess:
            ed_secret = sess[MFA_SETUP_SECRET_KEY]
        t_step = int(time.time()) // 30
        c_ed.post(
            "/admin/_security/mfa",
            data={"_csrf_token": tok_ed, "action": "enable", "code": compute_totp(ed_secret, timestamp=t_step * 30)},
        )
        # Missing/wrong code fails
        r_bad_dis = c_ed.post(
            "/admin/_security/mfa",
            data={"_csrf_token": tok_ed, "action": "disable", "code": "000000"},
        )
        assert mfa_store.get("ed") is not None
        assert "valid current" in r_bad_dis.get_data(as_text=True).lower()
        # Same timestep replay fails
        assert mfa_store.verify_and_record("ed", compute_totp(ed_secret, timestamp=t_step * 30)) is False
        # Next timestep code succeeds
        next_code = compute_totp(ed_secret, timestamp=(t_step + 1) * 30)
        assert mfa_store.verify_and_record("ed", next_code, timestamp=(t_step + 1) * 30) is True
        # Replay of that exact next timestep fails
        assert mfa_store.verify_and_record("ed", next_code, timestamp=(t_step + 1) * 30) is False
        deck.close()
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# 5. RBAC masked_fields End-to-End Protection
# ---------------------------------------------------------------------------


def test_masked_fields_protected_across_forms_clone_search_sort_audit(sa_bundle: Any) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    client = app.test_client()
    tok = login_as(client, "alpha_editor", "alpha-password")

    # 1. Edit form MUST NOT leak plaintext masked email (`ops@alpha.io`)
    edit_html = client.get("/admin/items/1/edit").get_data(as_text=True)
    assert "ops@alpha.io" not in edit_html

    # 2. Tampered POST attempting to overwrite masked email MUST NOT change email
    client.post(
        "/admin/items/1/edit",
        data={
            "_csrf_token": tok,
            "code": "ITM-001",
            "title": "Primary Server Updated",
            "email": "attacker@evil.io",
            "status": "active",
            "tenant_id": "1",
        },
        follow_redirects=False,
    )
    with SessionLocal() as sess:
        from tests.conftest import Item

        item = sess.get(Item, 1)
        assert item is not None
        assert item.title == "Primary Server Updated"
        assert item.email == "ops@alpha.io"

    # 3. ?clone=1 MUST NOT prefill masked email
    clone_html = client.get("/admin/items/new?clone=1").get_data(as_text=True)
    assert "ops@alpha.io" not in clone_html

    # 4. ?q=ops@alpha.io MUST NOT act as search oracle on masked field
    search_html = client.get("/admin/items/?q=ops@alpha.io").get_data(as_text=True)
    assert "ITM-001" not in search_html

    # 5. ?f_email=nonexistent MUST NOT act as filter oracle (ITM-001 still shown, no active filter)
    flt_resp = client.get("/admin/items/?f_email=nonexistent")
    assert flt_resp.status_code == 200
    flt_html = flt_resp.get_data(as_text=True)
    assert "ITM-001" in flt_html
    assert "Active filters:" not in flt_html

    # 6. Admin edits email -> alpha_editor viewing audit_list sees masked value, never plaintext!
    admin_client = app.test_client()
    a_tok = login_as(admin_client, "admin", "admin-password")
    admin_client.post(
        "/admin/items/1/edit",
        data={
            "_csrf_token": a_tok,
            "code": "ITM-001",
            "title": "Primary Server Updated",
            "email": "secret-new@alpha.io",
            "status": "active",
            "price": "199.50",
            "quantity": "3",
            "tenant_id": "1",
        },
        follow_redirects=False,
    )
    audit_html = client.get("/admin/_audit").get_data(as_text=True)
    assert "secret-new@alpha.io" not in audit_html
    assert "ops@alpha.io" not in audit_html


# ---------------------------------------------------------------------------
# 6. Multi-Bind Full Lifecycle + Quick-Edit XSS Escaping
# ---------------------------------------------------------------------------


class _MultiBase(DeclarativeBase):
    pass


class _MetricRow(_MultiBase):
    __tablename__ = "reg_metrics"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True)


class _XssFormatter(Formatter):
    def format(self, value: Any, obj: Any = None) -> str:
        # Deliberately returns plain str (NOT Markup) containing HTML
        return f"<img src=x onerror=alert('{value}')>"


def test_multi_bind_full_lifecycle_and_quick_edit_xss_escaping() -> None:
    primary_eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    metrics_eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    _MultiBase.metadata.create_all(metrics_eng)
    try:
        with sessionmaker(bind=metrics_eng)() as ms:
            ms.add(_MetricRow(name="cpu_p99", active=True))
            ms.commit()

        class MetricView(ModelView):
            model = _MetricRow
            slug = "reg-metrics"
            bind_key = "metrics"
            columns = ("id", "name", "active")
            searchable_columns = ("name",)
            inline_editable_columns = ("active",)
            import_key_columns = ("name",)
            column_formatters = MappingProxyType({"active": _XssFormatter()})

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long!"
        app.config["TESTING"] = True
        audit_store = InMemoryAuditStore()
        deck = Deck(
            app,
            engine=primary_eng,
            session_factory=sessionmaker(bind=primary_eng),
            binds={"metrics": metrics_eng},
            auth=BasicAuthProvider.from_plain_passwords({"admin": "pw"}),
            audit_store=audit_store,
        )
        deck.register(MetricView)

        # Unknown bind_key must raise KeyError (never silently fall back to primary)
        with app.app_context(), pytest.raises(KeyError):
            deck.get_session("nonexistent_bind")

        client = app.test_client()
        tok = login_as(client, "admin", "pw")

        # Dashboard, list, search, schema ERD all succeed against secondary bind!
        assert client.get("/admin/").status_code == 200
        assert "cpu_p99" in client.get("/admin/reg-metrics/").get_data(as_text=True)
        sr = client.get("/admin/_api/search?q=cpu_p99").get_json()
        assert any("cpu_p99" in item["title"] for item in sr["results"])
        assert client.get("/admin/_schema").status_code == 200

        # Quick-edit PATCH routes to secondary bind AND HTML-escapes plain str formatter!
        patch_resp = client.patch(
            "/admin/_api/reg-metrics/1/quick-edit",
            json={"field": "active", "value": False},
            headers={"X-Deck-CSRFToken": tok},
        )
        assert patch_resp.status_code == 200
        payload = patch_resp.get_json()
        assert payload["value"] is False
        assert "<img" not in payload["display"]
        assert "&lt;img" in payload["display"]

        # Audit revert routes to secondary bind and restores active=True!
        entries, _ = audit_store.list_entries(model_slug="reg-metrics")
        assert len(entries) == 1
        rev = client.post(
            f"/admin/_audit/{entries[0].id}/revert",
            data={"_csrf_token": tok},
            follow_redirects=False,
        )
        assert rev.status_code == 302
        with sessionmaker(bind=metrics_eng)() as ms:
            row = ms.get(_MetricRow, 1)
            assert row is not None and row.active is True

        # Import dry-run & commit route to secondary bind!
        csv_bytes = b"name,active\nmem_p99,true\n"
        r_prev = client.post(
            "/admin/reg-metrics/import",
            data={
                "_csrf_token": tok,
                "step": "preview",
                "file": (io.BytesIO(csv_bytes), "metrics.csv"),
            },
            content_type="multipart/form-data",
        )
        assert r_prev.status_code == 200
        assert "mem_p99" in r_prev.get_data(as_text=True)
        deck.close()
    finally:
        primary_eng.dispose()
        metrics_eng.dispose()


# ---------------------------------------------------------------------------
# 7. Cursor Tampering, Empty-String Sort & PG Generic sa.JSON / sa.ARRAY
# ---------------------------------------------------------------------------


class _PgGenericBase(DeclarativeBase):
    pass


class _PgGenericModel(_PgGenericBase):
    __tablename__ = "pg_generic_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(64), default="")
    tags: Mapped[list[str] | None] = mapped_column(sa.ARRAY(sa.String()), nullable=True)
    meta: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)


def test_cursor_tampering_empty_sort_and_pg_generic_compilation() -> None:
    pg_meta = introspect_model(_PgGenericModel)
    pg_dialect = postgresql.dialect()

    # Generic sa.JSON path filter & generic sa.ARRAY filters compile cleanly on PostgreSQL!
    c_path = build_filter_condition(pg_meta, "meta", "env.tier=pro", op="path", dialect_name="postgresql")
    assert c_path is not None and str(c_path.compile(dialect=pg_dialect))
    c_arr_c = build_filter_condition(pg_meta, "tags", "ops", op="array_contains", dialect_name="postgresql")
    assert c_arr_c is not None and "ANY" in str(c_arr_c.compile(dialect=pg_dialect)).upper()
    c_arr_a = build_filter_condition(pg_meta, "tags", "ops,sec", op="array_any", dialect_name="postgresql")
    assert c_arr_a is not None and "OR" in str(c_arr_a.compile(dialect=pg_dialect)).upper()

    # Empty-string sort cursor pagination & cross-slice tampering rejection
    class _CurBase(DeclarativeBase):
        pass

    class _CurItem(_CurBase):
        __tablename__ = "cur_items"
        id: Mapped[int] = mapped_column(primary_key=True)
        code: Mapped[str] = mapped_column(sa.String(32), default="")

    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    _CurBase.metadata.create_all(eng)
    try:
        SessionLocal = sessionmaker(bind=eng)
        with SessionLocal() as sess:
            sess.add_all([_CurItem(code=""), _CurItem(code=""), _CurItem(code="a"), _CurItem(code="b")])
            sess.commit()
            meta = introspect_model(_CurItem)
            p1 = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(_CurItem),
                displayed_columns=("id", "code"),
                searchable_columns=("code",),
                filterable_columns=frozenset({"code"}),
                sortable_columns=frozenset({"id", "code"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="code",
                sort_dir="asc",
                default_sort=("code", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                cursor_secret=b"cursor-test-secret",
            )
            assert [r.id for r in p1.items] == [1, 2]
            assert p1.next_cursor is not None

            p2 = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(_CurItem),
                displayed_columns=("id", "code"),
                searchable_columns=("code",),
                filterable_columns=frozenset({"code"}),
                sortable_columns=frozenset({"id", "code"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="code",
                sort_dir="asc",
                default_sort=("code", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                after_cursor=p1.next_cursor,
                cursor_secret=b"cursor-test-secret",
            )
            assert [r.id for r in p2.items] == [3, 4]

            # Replaying p1.next_cursor under a different search_term (slice digest mismatch) resets to page 1
            p_tampered = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(_CurItem),
                displayed_columns=("id", "code"),
                searchable_columns=("code",),
                filterable_columns=frozenset({"code"}),
                sortable_columns=frozenset({"id", "code"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="a",
                filter_params={},
                sort_by="code",
                sort_dir="asc",
                default_sort=("code", "asc"),
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                after_cursor=p1.next_cursor,
                cursor_secret=b"cursor-test-secret",
            )
            assert [r.code for r in p_tampered.items] == ["a"]
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# 8. Storage Hardening (BOM SVG, "." Key, GIF Frame Bomb, S3 NoSuchKey)
# ---------------------------------------------------------------------------


def test_storage_bom_svg_gif_frame_bomb_and_s3_errors(tmp_path: Path) -> None:
    # UTF-8 BOM + XML comment + SVG must be classified as image/svg+xml (and blocked for normal uploads)
    bom_svg = b"\xef\xbb\xbf<!-- sneaky --><svg xmlns='http://www.w3.org/2000/svg'></svg>"
    assert detect_mime_from_bytes(bom_svg) == "image/svg+xml"
    bom_html = b"\xef\xbb\xbf<!-- hi --><html><script>alert(1)</script></html>"
    assert detect_mime_from_bytes(bom_html) is None

    # GIF with tiny 1x1 logical screen but huge 5000x5000 0x2C image descriptor
    gif_bomb = (
        b"GIF89a"
        + struct.pack("<HHBBB", 1, 1, 0, 0, 0)
        + b"\x2c"
        + struct.pack("<HHHHB", 0, 0, 5000, 5000, 0)
        + b"\x3b"
    )
    dims = parse_image_dimensions(gif_bomb, "image/gif")
    assert dims == (5000, 5000)

    # LocalFileStorage rejects ".", "..", ""
    store = LocalFileStorage(tmp_path / "media")
    for bad_key in ("", ".", "..", "a/../b"):
        with pytest.raises(ValueError):
            store.save(b"x", key=bad_key, content_type="text/plain")

    # S3StorageBackend maps botocore-like NoSuchKey ClientError to FileNotFoundError
    class _FakeClientError(Exception):
        def __init__(self, code: str) -> None:
            self.response = {"Error": {"Code": code}}

    class _ErrorS3:
        def get_object(self, **_kw: Any) -> Any:
            raise _FakeClientError("NoSuchKey")

        def head_object(self, **_kw: Any) -> Any:
            raise _FakeClientError("404")

    s3 = S3StorageBackend("bkt", client=_ErrorS3())
    with pytest.raises(FileNotFoundError):
        s3.open("missing.bin")
    assert s3.exists("missing.bin") is False


# ---------------------------------------------------------------------------
# 9. Soft-Delete Orphan Cleanup, Trash Export & Jobs Ownership + Eviction
# ---------------------------------------------------------------------------


def test_soft_delete_orphan_cleanup_trash_export_and_jobs_security(tmp_path: Path) -> None:
    class _LifeBase(DeclarativeBase):
        pass

    class _Doc(_LifeBase):
        __tablename__ = "life_docs"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(sa.String(64), nullable=False)
        file_key: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
        deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    eng = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    _LifeBase.metadata.create_all(eng)
    file_store = LocalFileStorage(tmp_path / "docs")
    job_store = MemoryFileStorage()
    job_backend = ThreadPoolJobBackend(max_workers=1, max_history=10)

    class _DocView(ModelView):
        model = _Doc
        slug = "life-docs"
        soft_delete_column = "deleted_at"
        columns = ("id", "title", "file_key")
        searchable_columns = ("title",)
        file_fields = MappingProxyType(
            {
                "file_key": FileFieldConfig(
                    storage=file_store,
                    kind="file",
                    prefix="docs",
                    delete_orphan=True,
                )
            }
        )

        @action("slow_noop", label="Noop Async", async_job=True)
        def slow_noop(self, records: list[_Doc], _form: Any, _user: Any, job_ctx: Any) -> str:
            job_ctx.set_progress(100, "done")
            return f"Processed {len(records)}"

    try:
        auth = RBACAuthProvider(
            roles=[
                Role(name="admin", permissions=frozenset({"*"})),
                Role(name="ops_viewer", permissions=frozenset({"life-docs:view", "jobs:view_all"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="su", username="admin", roles=("admin",), is_superuser=True),
                    password="pw",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="ov", username="ops", roles=("ops_viewer",)),
                    password="pw",
                ),
            ],
        )
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            engine=eng,
            session_factory=sessionmaker(bind=eng),
            auth=auth,
            job_backend=job_backend,
            job_storage=job_store,
            auto_audit=False,
        )
        deck.register(_DocView)

        # Store a real file & create record
        stored = file_store.save(b"%PDF-1.4\nhello", key="docs/keep.pdf", content_type="application/pdf")
        with sessionmaker(bind=eng)() as sess:
            sess.add(_Doc(title="Alpha Spec", file_key=stored.key))
            sess.commit()

        c_admin = app.test_client()
        tok = login_as(c_admin, "admin", "pw")

        # Soft-delete -> file stays intact, excluded from search, included in Trash CSV export!
        r_sd = c_admin.post("/admin/life-docs/1/delete", data={"_csrf_token": tok})
        assert r_sd.status_code == 302
        assert file_store.exists(stored.key)
        assert c_admin.get("/admin/_api/search?q=Alpha").get_json()["results"] == []
        csv_trash = c_admin.get("/admin/life-docs/export.csv?trashed=1").get_data(as_text=True)
        assert "Alpha Spec" in csv_trash
        # Editing trashed record is blocked (redirects back to detail without editing!)
        r_tr_edit = c_admin.post(
            "/admin/life-docs/1/edit",
            data={"_csrf_token": tok, "title": "Hacked Trash"},
            follow_redirects=False,
        )
        assert r_tr_edit.status_code == 302
        with sessionmaker(bind=eng)() as sess:
            doc = sess.get(_Doc, 1)
            assert doc is not None and doc.title == "Alpha Spec"

        # Force-delete removes orphan file from storage!
        r_fd = c_admin.post("/admin/life-docs/1/delete", data={"_csrf_token": tok, "force": "1"})
        assert r_fd.status_code == 302
        assert not file_store.exists(stored.key)

        # Trigger background CSV export as admin -> verify ops_viewer (jobs:view_all)
        # can view status, CANNOT cancel (403) and CANNOT download artifact (403)!
        r_exp = c_admin.post(
            "/admin/life-docs/export-async",
            data={"_csrf_token": tok, "fmt": "csv"},
            follow_redirects=False,
        )
        assert r_exp.status_code == 302
        job_id = r_exp.headers["Location"].split("focus=")[-1]
        for _ in range(40):
            rec = job_backend.get(job_id)
            if rec and rec.status == "succeeded":
                break
            time.sleep(0.05)
        rec = job_backend.get(job_id)
        assert rec is not None and rec.status == "succeeded" and rec.artifact_key is not None
        first_artifact_key = rec.artifact_key
        assert job_store.exists(first_artifact_key)

        c_ops = app.test_client()
        tok_ops = login_as(c_ops, "ops", "pw")
        assert c_ops.get(f"/admin/_api/jobs/{job_id}").status_code == 200
        assert c_ops.get(f"/admin/_jobs/{job_id}/artifact").status_code == 403
        assert (
            c_ops.post(f"/admin/_jobs/{job_id}/cancel", data={"_csrf_token": tok_ops}).status_code
            == 403
        )

        # Queue 10 more jobs to trigger eviction (max_history=10) -> evicted artifact purged!
        for _ in range(10):
            r_more = c_admin.post(
                "/admin/life-docs/export-async",
                data={"_csrf_token": tok, "fmt": "csv"},
                follow_redirects=False,
            )
            jid = r_more.headers["Location"].split("focus=")[-1]
            for _ in range(40):
                cur = job_backend.get(jid)
                if cur and cur.status == "succeeded":
                    break
                time.sleep(0.05)
        assert not job_store.exists(first_artifact_key)
        deck.close()
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# 10. Formatters, Charts, i18n Edge Cases & Pure SQLAlchemy Example Smoke Test
# ---------------------------------------------------------------------------


def test_formatters_charts_i18n_edge_cases_and_example_app() -> None:
    # NaN / Inf / -0.00 guards (never raise InvalidOperation or ValueError)
    cf = CurrencyFormatter(currency="USD", divisor=1)
    assert "NaN" in str(cf.format(Decimal("NaN"), None))
    assert "inf" in str(cf.format(float("inf"), None)).lower()
    assert "-$0.00" not in str(cf.format(Decimal("-0.001"), None))

    pf = ProgressBarFormatter()
    assert "nan" in str(pf.format(float("nan"), None)).lower()

    # Negative locale decimal preserves minus sign
    assert format_locale_decimal(-1234.56, locale="de") == "-1.234,56"
    assert format_locale_decimal(-1234.56, locale="en") == "-1,234.56"

    # Symmetric future relative time
    rf = RelativeTimeFormatter()
    future_dt = datetime.now(timezone.utc) + timedelta(hours=3)
    assert "in 3h" in str(rf.format(future_dt, None)) or "in 2h" in str(rf.format(future_dt, None))

    # Charts tolerate NaN / Inf without crashing
    assert "svg" in str(render_area_chart(["a", "b"], [{"name": "s", "data": [float("nan"), 10.0]}]))
    assert "svg" in str(render_bar_chart(["a", "b"], [{"name": "s", "data": [-5.0, float("inf")]}]))
    assert "dk-chart-empty" in str(render_donut_chart(["a"], [{"name": "s", "data": [float("nan")]}]))
    assert "svg" in str(render_gauge_chart(float("nan")))

    # Pure SQLAlchemy example app boots and handles GET + POST create cleanly
    from examples.pure_sqlalchemy_app import create_app as create_example_app

    example_app = create_example_app()
    example_app.config["TESTING"] = True
    ex_client = example_app.test_client()
    tok = login_as(ex_client, "admin", "super-secret-password")
    assert ex_client.get("/admin/api-keys/").status_code == 200
    r_create = ex_client.post(
        "/admin/api-keys/new",
        data={"_csrf_token": tok, "name": "CI Key", "prefix": "dk_ci", "is_active": "true"},
        follow_redirects=False,
    )
    assert r_create.status_code == 302
