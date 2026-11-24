from __future__ import annotations

import enum
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask, Response
from sqlalchemy.orm import (
    DeclarativeBase,
    DynamicMapped,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool
from werkzeug.security import generate_password_hash

from flask_deck import (
    ColorWidget,
    Deck,
    DeckUser,
    EmptyFieldListFilter,
    FileFieldConfig,
    InlineModelView,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemoryRecordNoteStore,
    InMemorySessionStore,
    MemoryFileStorage,
    ModelView,
    RBACAccount,
    RBACAuthProvider,
    RelatedOnlyFieldListFilter,
    Role,
    SliderWidget,
    SQLAlchemyAuditStore,
    SQLAlchemyAuthProvider,
    SQLAlchemyJobBackend,
    TagInputWidget,
    VirtualField,
    action,
)
from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk
from flask_deck.api_keys import build_api_key_record
from flask_deck.audit import AuditEntry
from flask_deck.cascade import analyze_delete_impact
from flask_deck.charts import render_heatmap_chart
from flask_deck.checks import run_model_view_checks
from flask_deck.demo import create_demo_app
from flask_deck.exporter import _XLSX_INVALID_TITLE_RE
from flask_deck.i18n import BUILTIN_CATALOGS, BabelTranslator
from flask_deck.importer import commit_dry_run_import, run_dry_run_import
from flask_deck.introspection import introspect_model
from flask_deck.saved_views import render_safe_markdown
from flask_deck.sessions import SessionRecord
from flask_deck.sql_console import (
    SQLQueryResult,
    _find_sensitive_indices_from_sql,
    build_sql_chart_svg,
    introspect_engine_schema,
    validate_readonly_sql,
)
from flask_deck.storage import make_demo_png
from tests.conftest import login_as


class BHBase(DeclarativeBase):
    pass


class ItemState(enum.Enum):
    OPEN = "open"
    CLOSED = "closed"


bh_item_tags = sa.Table(
    "bh_item_tags",
    BHBase.metadata,
    sa.Column("item_id", sa.ForeignKey("bh_items.id", ondelete="CASCADE"), primary_key=True),
    sa.Column("tag_id", sa.ForeignKey("bh_tags.id", ondelete="CASCADE"), primary_key=True),
)


class BHCountry(BHBase):
    __tablename__ = "bh_countries"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(8), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    def __str__(self) -> str:
        return f"{self.code} ({self.name})"


class BHTag(BHBase):
    __tablename__ = "bh_tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    def __str__(self) -> str:
        return self.label


class BHCategory(BHBase):
    __tablename__ = "bh_categories"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(sa.ForeignKey("bh_categories.id"), nullable=True)

    parent: Mapped[BHCategory | None] = relationship(
        remote_side="BHCategory.id", foreign_keys=[parent_id]
    )

    def __str__(self) -> str:
        return self.name


class BHItem(BHBase):
    __tablename__ = "bh_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    secret_code: Mapped[str] = mapped_column(sa.String(64), default="TOP-SECRET", nullable=False)
    state: Mapped[ItemState] = mapped_column(sa.Enum(ItemState), default=ItemState.OPEN, nullable=False)
    nullable_state: Mapped[ItemState | None] = mapped_column(sa.Enum(ItemState), nullable=True)
    is_featured: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)
    scheduled_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    category_id: Mapped[int | None] = mapped_column(sa.ForeignKey("bh_categories.id"), nullable=True)
    country_code: Mapped[str | None] = mapped_column(
        sa.ForeignKey("bh_countries.code"), nullable=True
    )
    attachment_path: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    category: Mapped[BHCategory | None] = relationship()
    country: Mapped[BHCountry | None] = relationship()
    tags: Mapped[list[BHTag]] = relationship(secondary=bh_item_tags)
    children: Mapped[list[BHItemChild]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )
    dynamic_children: DynamicMapped[BHItemChild] = relationship(
        "BHItemChild", viewonly=True, overlaps="children,item"
    )

    def __str__(self) -> str:
        return self.title


class BHItemChild(BHBase):
    __tablename__ = "bh_item_children"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("bh_items.id"), nullable=False)
    category_id: Mapped[int | None] = mapped_column(sa.ForeignKey("bh_categories.id"), nullable=True)
    label: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    photo_path: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    item: Mapped[BHItem] = relationship(back_populates="children")
    category: Mapped[BHCategory | None] = relationship()


class BHCompositePair(BHBase):
    __tablename__ = "bh_composite_pairs"
    tenant_id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    seq_id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)


class BHStringKey(BHBase):
    __tablename__ = "bh_string_keys"
    code: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(64), nullable=False)


_MANAGED_ENGINES: list[sa.Engine] = []
_MANAGED_DECKS: list[Deck] = []


@pytest.fixture(autouse=True)
def _dispose_test_resources() -> Any:
    yield
    while _MANAGED_DECKS:
        d = _MANAGED_DECKS.pop()
        d.close()
    while _MANAGED_ENGINES:
        e = _MANAGED_ENGINES.pop()
        e.dispose()


def _make_engine() -> sa.Engine:
    eng = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    BHBase.metadata.create_all(eng)
    _MANAGED_ENGINES.append(eng)
    return eng


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf_token"\s+value="([^"]+)"', html)
    assert m is not None
    return m.group(1)


# ---------------------------------------------------------------------------
# 1. SQL Console Lexer Hardening, Forbidden Tables & Multi-Series SVG Charts
# ---------------------------------------------------------------------------
def test_sql_console_lexer_redaction_forbidden_tables_and_multiseries_chart() -> None:
    # SQLite/PG do NOT support \' escaping -> must detect injection after quote!
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
        validate_readonly_sql("SELECT 'a\\'; DELETE FROM bh_items; --'", dialect_name="sqlite")
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
        validate_readonly_sql(
            "SELECT 'a\\'; DELETE FROM bh_items; --'", dialect_name="postgresql"
        )
    # MySQL backslash escaping inside string literal is rejected conservatively
    with pytest.raises(ValueError, match="Backslash"):
        validate_readonly_sql("SELECT 'a\\'' FROM bh_items", dialect_name="mysql")

    # Nested block comments and MySQL conditional comments rejected
    with pytest.raises(ValueError, match="Nested"):
        validate_readonly_sql("SELECT /* /* */ 1; DROP TABLE bh_items", dialect_name="sqlite")
    with pytest.raises(ValueError, match="Conditional"):
        validate_readonly_sql("SELECT /*!50000 1 */ FROM bh_items", dialect_name="mysql")

    # PostgreSQL E'...' escape string literal rejected
    with pytest.raises(ValueError, match="Escape-string"):
        validate_readonly_sql("SELECT E'hello\\' ; DROP TABLE x'", dialect_name="postgresql")

    # PostgreSQL `#` is an operator (not a comment!), so `; DROP TABLE` after `#` is caught
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
        validate_readonly_sql("SELECT 1 # ; DROP TABLE bh_items", dialect_name="postgresql")
    assert validate_readonly_sql("SELECT 1 # 2 AS x", dialect_name="postgresql")
    # On MySQL, `#` is a line comment
    assert validate_readonly_sql("SELECT 1 # comment", dialect_name="mysql")

    # Internal IAM / security tables forbidden
    for tbl in (
        "_flask_deck_users",
        "_flask_deck_password_resets",
        "_flask_deck_groups",
        "_flask_deck_user_groups",
        "_flask_deck_user_permissions",
        "_flask_deck_import_previews",
        "_flask_deck_webhook_deliveries",
    ):
        with pytest.raises(ValueError, match=r"restricted|internal|forbidden"):
            validate_readonly_sql(f"SELECT * FROM {tbl}")

    # Schema introspection hides internal tables
    eng = _make_engine()
    SQLAlchemyAuthProvider(eng)
    schema = introspect_engine_schema(eng)
    table_names = {t["name"] for t in schema}
    assert "bh_items" in table_names
    assert "_flask_deck_users" not in table_names
    assert "_flask_deck_password_resets" not in table_names

    # Parenthesized SELECT redacts sensitive column aliases (SQL execution test)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-sql-console-secret-32-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(app, engine=eng, allow_insecure_open=True, enable_sql_console=True, auto_audit=False)
    deck.register(BHItem)
    with sessionmaker(bind=eng)() as s:
        s.add(BHItem(title="Alpha", secret_code="S3CR3T-XYZ"))
        s.commit()

    # Parenthesized SELECT (PostgreSQL/MySQL syntax) redacts sensitive aliased columns!
    assert 0 in _find_sensitive_indices_from_sql(
        "(SELECT secret_code AS x, title FROM bh_items)",
        ("x", "title"),
        (),
    )

    client = app.test_client()
    r = client.get("/admin/_sql")
    assert r.status_code == 200
    csrf = _extract_csrf(r.get_data(as_text=True))
    r_exec = client.post(
        "/admin/_sql",
        data={
            "_csrf_token": csrf,
            "sql": "SELECT secret_code AS x, title FROM bh_items",
            "output": "csv",
        },
    )
    assert r_exec.status_code == 200
    csv_body = r_exec.get_data(as_text=True)
    assert "S3CR3T-XYZ" not in csv_body
    assert "REDACTED" in csv_body

    # Multi-series chart renders grouped bar chart containing both series labels
    svg = build_sql_chart_svg(
        SQLQueryResult(
            sql="SELECT month, revenue, cost FROM t",
            columns=("month", "revenue", "cost"),
            rows=(("Jan", 120, 80), ("Feb", 150, 90)),
            row_count=2,
            truncated=False,
            redacted_columns=(),
            duration_ms=1.0,
        ),
        chart_type="bar",
    )
    assert svg is not None
    assert "revenue" in str(svg) and "cost" in str(svg)


# ---------------------------------------------------------------------------
# 2. IAM Wildcard Privilege Escalation, Impersonation & Deactivated API Keys
# ---------------------------------------------------------------------------
def test_iam_privilege_escalation_and_impersonation_guards() -> None:
    eng = _make_engine()
    iam = SQLAlchemyAuthProvider(eng, password_validators=())
    iam.create_user(
        username="superadmin",
        password="SuperPassword123!",
        email="super@acme.test",
        is_superuser=True,
    )
    delegated = iam.create_user(
        username="iam_mgr",
        password="MgrPassword123!",
        email="mgr@acme.test",
        is_superuser=False,
        direct_permissions=("iam:manage", "bh-items:view"),
    )
    priv_group = iam.create_group(
        name="super_ops",
        permissions=("iam:*",),
    )
    staff_group = iam.create_group(
        name="staff_viewers",
        permissions=("bh-items:view",),
    )
    target_user = iam.create_user(
        username="staff1",
        password="StaffPassword123!",
        email="staff1@acme.test",
        is_superuser=False,
        tenant_id="tenant-alpha",
        group_ids=(staff_group.id,),
    )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-iam-sec-secret-key-32-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        engine=eng,
        auth=iam,
        auto_audit=False,
        enable_rest_api=True,
        session_store=InMemorySessionStore(),
    )
    deck.register(BHItem)

    # Delegated IAM manager attempts wildcard privilege escalation
    c_mgr = app.test_client()
    csrf = login_as(c_mgr, "iam_mgr", "MgrPassword123!")

    for bad_perm in ("**", "*:*", "iam:*", "[i]am:manage", "iam:manage"):
        uname = f"esc_{abs(hash(bad_perm)) % 10000}"
        r_u = c_mgr.post(
            "/admin/_security/users/create",
            data={
                "_csrf_token": csrf,
                "username": uname,
                "password": "EscPassword123!",
                "direct_permissions": bad_perm,
            },
            follow_redirects=True,
        )
        assert "superuser" in r_u.get_data(as_text=True).lower()
        assert iam.get_user_by_username(uname) is None

    # Delegated IAM manager cannot assign privileged group to a user
    r_assign = c_mgr.post(
        f"/admin/_security/users/{target_user.id}/update",
        data={
            "_csrf_token": csrf,
            "display_name": "Staff 1",
            "is_active": "1",
            "group_ids": [priv_group.id],
        },
        follow_redirects=True,
    )
    assert "superuser" in r_assign.get_data(as_text=True).lower()
    reloaded = iam.get_user_record(target_user.id)
    assert reloaded is not None and priv_group.id not in reloaded.group_ids

    # Delegated IAM manager cannot create, update, or delete privileged groups
    r_gc = c_mgr.post(
        "/admin/_security/groups/create",
        data={"_csrf_token": csrf, "name": "evil_star", "extra_permissions": "*:*"},
        follow_redirects=False,
    )
    assert r_gc.status_code == 403
    assert not any(g.name == "evil_star" for g in iam.list_groups())

    r_gu = c_mgr.post(
        f"/admin/_security/groups/{priv_group.id}/update",
        data={"_csrf_token": csrf, "name": "super_ops", "extra_permissions": "bh-items:view"},
        follow_redirects=False,
    )
    assert r_gu.status_code == 403

    r_gd = c_mgr.post(
        f"/admin/_security/groups/{priv_group.id}/delete",
        data={"_csrf_token": csrf},
        follow_redirects=False,
    )
    assert r_gd.status_code == 403
    assert any(g.id == priv_group.id for g in iam.list_groups())

    # Impersonation guards on password change, sessions, passkeys, and API keys
    c_sup = app.test_client()
    sup_csrf = login_as(c_sup, "superadmin", "SuperPassword123!")
    r_imp = c_sup.post(
        "/admin/_impersonate/start",
        data={"_csrf_token": sup_csrf, "target_user_id": target_user.id},
        follow_redirects=False,
    )
    assert r_imp.status_code == 302
    assert c_sup.get("/admin/_security/password").status_code == 403
    assert c_sup.get("/admin/_security/sessions").status_code == 403
    assert c_sup.get("/admin/_security/passkeys").status_code == 403
    assert (
        c_sup.post(
            "/admin/_security/api-keys/create",
            data={"_csrf_token": sup_csrf, "name": "imp-key", "scopes": "bh-items:view"},
        ).status_code
        == 403
    )

    # Password reset token rejected when user is deactivated & cannot be replayed
    res_tok = iam.create_password_reset_token(delegated.username)
    assert res_tok is not None
    _, raw_tok = res_tok
    iam.update_user(delegated.id, is_active=False)
    ok_deact, _, _ = iam.consume_password_reset_token(raw_tok, "NewPassword456!")
    assert not ok_deact
    iam.update_user(delegated.id, is_active=True)
    ok_act, _, ok_user = iam.consume_password_reset_token(raw_tok, "NewPassword456!")
    assert ok_act and ok_user is not None and ok_user.id == delegated.id
    ok_replay, _, _ = iam.consume_password_reset_token(raw_tok, "ReplayPassword789!")
    assert not ok_replay

    # API key auth rejects deactivated SQLAlchemyAuthProvider owner
    assert deck.api_key_store is not None
    raw_key, krec = build_api_key_record(
        name="staff-key",
        owner_id=target_user.id,
        owner_name="staff1",
        scopes=("bh-items:view",),
        roles=("staff_viewers",),
    )
    deck.api_key_store.create(krec)
    r_api_ok = app.test_client().get(
        "/admin/_api/v1/bh-items",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert r_api_ok.status_code == 200
    iam.update_user(target_user.id, is_active=False)
    r_api_blocked = app.test_client().get(
        "/admin/_api/v1/bh-items",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert r_api_blocked.status_code == 401


# ---------------------------------------------------------------------------
# 3. Quick-Edit M2M Preservation, Media/Notes RBAC, Markdown & Exporter Fixes
# ---------------------------------------------------------------------------
def test_quick_edit_preserves_m2m_and_media_notes_rbac() -> None:
    eng = _make_engine()
    storage = MemoryFileStorage()
    img_stored = storage.save(make_demo_png(), key="sample.png", content_type="image/png")
    child_img_stored = storage.save(make_demo_png(), key="child.png", content_type="image/png")

    class ChildInline(InlineModelView):
        model = BHItemChild
        columns = ("label", "qty", "photo_path")
        file_fields = MappingProxyType({"photo_path": FileFieldConfig(storage=storage, kind="image")})

    class ItemView(ModelView):
        model = BHItem
        columns = ("id", "title", "state", "is_featured", "attachment_path")
        form_columns = ("title", "state", "is_featured", "tags", "attachment_path")
        searchable_columns = ("title", "^secret_code")
        filterable_columns = ("state",)
        date_hierarchy = "scheduled_at"
        soft_delete_column = "deleted_at"
        version_column = "version"
        inlines = (ChildInline,)
        file_fields = MappingProxyType({"attachment_path": FileFieldConfig(storage=storage, kind="image")})
        plural_label = "Items / Active: [2026]?"  # Invalid XLSX sheet chars!

        def can_view_record(self, obj: Any, user: DeckUser | None) -> bool:
            return not (user and not user.is_superuser and obj.locked)

        def can_edit_record(self, obj: Any, user: DeckUser | None) -> bool:
            return self.can_view_record(obj, user)

    rbac = RBACAuthProvider(
        accounts=(
            RBACAccount(
                password_hash=generate_password_hash("pass"),
                user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
            ),
            RBACAccount(
                password_hash=generate_password_hash("pass"),
                user=DeckUser(id="u-an", username="analyst", roles=("analyst",)),
            ),
        ),
        roles=(
            Role(
                name="analyst",
                permissions=("bh-items:view", "bh-items:edit", "bh-items:export", "bh-items:delete"),
                hidden_fields={"bh-items": frozenset({"secret_code", "scheduled_at"})},
            ),
        ),
    )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-m2m-media-secret-key-32-bytes"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        engine=eng,
        auth=rbac,
        auto_audit=False,
        note_store=InMemoryRecordNoteStore(),
    )
    class QuickItemProxyView(ModelView):
        model = BHItem
        slug = "bh-items-quick"
        columns = ("id", "title", "state", "is_featured")
        form_columns = ("title", "state", "is_featured", "tags")
        soft_delete_column = "deleted_at"
        version_column = "version"

    deck.register(ItemView, QuickItemProxyView, BHTag)

    with sessionmaker(bind=eng)() as s:
        t1 = BHTag(label="urgent")
        t2 = BHTag(label="vip")
        s.add_all([t1, t2])
        s.flush()
        it_open = BHItem(
            title="Public Item",
            secret_code="FINDME-999",
            state=ItemState.OPEN,
            is_featured=True,
            scheduled_at=datetime(2026, 3, 15, 10, 0),
            tags=[t1, t2],
            attachment_path=img_stored.key,
        )
        it_locked = BHItem(
            title="Secret Item",
            secret_code="FINDME-999",
            locked=True,
            attachment_path=img_stored.key,
        )
        it_trashed = BHItem(
            title="Trashed Item",
            deleted_at=datetime.now(timezone.utc),
        )
        s.add_all([it_open, it_locked, it_trashed])
        s.flush()
        ch_locked = BHItemChild(
            item_id=it_locked.id, label="c1", qty=1, photo_path=child_img_stored.key
        )
        s.add(ch_locked)
        s.commit()
        open_id, locked_id, trashed_id, ch_locked_id = (
            it_open.id,
            it_locked.id,
            it_trashed.id,
            ch_locked.id,
        )

    c_adm = app.test_client()
    adm_csrf = login_as(c_adm, "admin", "pass")

    # Quick-edit drawer updates title without wiping existing M2M tags and bumps version!
    r_qe = c_adm.post(
        f"/admin/_api/bh-items-quick/{open_id}/quick-edit-form",
        data={
            "_csrf_token": adm_csrf,
            "title": "Public Item Edited",
            "state": "open",
            "is_featured": "1",
        },
    )
    assert r_qe.status_code == 200
    with sessionmaker(bind=eng)() as s:
        refreshed = s.get(BHItem, open_id)
        assert refreshed is not None
        assert refreshed.title == "Public Item Edited"
        assert len(refreshed.tags) == 2
        assert refreshed.version == 2

    # Quick-delete on already-soft-deleted record returns 409
    r_qd = c_adm.post(
        f"/admin/_api/bh-items/{trashed_id}/quick-delete",
        headers={"X-Deck-CSRFToken": adm_csrf},
    )
    assert r_qd.status_code == 409

    # Analyst cannot access notes or media of locked record (can_view_record=False) or trashed notes
    c_an = app.test_client()
    an_csrf = login_as(c_an, "analyst", "pass")
    assert c_an.get(f"/admin/_api/bh-items/{locked_id}/notes").status_code == 403
    assert (
        c_an.post(
            f"/admin/_api/bh-items/{locked_id}/notes",
            json={"body": "snooping"},
            headers={"X-Deck-CSRFToken": an_csrf},
        ).status_code
        == 403
    )
    assert c_an.get(f"/admin/_api/bh-items/{trashed_id}/notes").status_code == 404
    assert c_an.get(f"/admin/_media/bh-items/attachment_path/{locked_id}").status_code == 403
    assert (
        c_an.get(
            f"/admin/_media/bh-items/_inline/bh-item-childs/photo_path/{ch_locked_id}"
        ).status_code
        == 403
    )

    # Facets API ignores hidden date_hierarchy field (dh=2025 must NOT filter)
    r_fac = c_an.get("/admin/_api/bh-items/facets?dh=2025")
    assert r_fac.status_code == 200
    fac_data = r_fac.get_json()["facets"]
    assert fac_data["state"]["open"] >= 1

    # Exporter blocks prefix-search `^secret_code` for analyst who has secret_code hidden
    r_exp = c_an.get("/admin/bh-items/export.csv?q=FINDME-999")
    assert r_exp.status_code == 200
    assert "Public Item Edited" not in r_exp.get_data(as_text=True)

    # XLSX sheet title regex strips all Excel-forbidden chars (/ \ ? * [ ] :)
    safe_sheet = _XLSX_INVALID_TITLE_RE.sub("_", "Items / Active: [2026]?").strip()[:31]
    assert not any(ch in safe_sheet for ch in r"/\?*[]:")
    r_xlsx = c_adm.get("/admin/bh-items/export.xlsx")
    assert r_xlsx.status_code in {200, 501}
    if r_xlsx.status_code == 200:
        assert r_xlsx.data[:2] == b"PK"

    # Markdown hardening: protocol-relative /\evil.com blocked & backticks in URL cannot break href
    md_bad_rel = str(render_safe_markdown("[bad](/\\evil.com)"))
    assert "<a " not in md_bad_rel
    md_backtick = str(render_safe_markdown("[ok](https://example.com/`x`/*y*)"))
    assert "<code>" not in md_backtick and "<em>" not in md_backtick
    assert 'href="https://example.com/`x`/*y*"' in md_backtick


# ---------------------------------------------------------------------------
# 4. Audit Revert Safety & Hash Chain Integrity
# ---------------------------------------------------------------------------
def test_audit_revert_safety_and_hash_chain() -> None:
    # Inline child audit entries are NEVER revertible onto parent record
    inline_entry = AuditEntry(
        id="e1",
        timestamp=datetime.now(timezone.utc),
        actor_id="u1",
        actor_name="Admin",
        actor_ip="127.0.0.1",
        action="update",
        model_slug="bh-items",
        model_label="Item",
        record_pk="1",
        record_repr="Item 1",
        changes={"label": {"old": "old-child", "new": "new-child"}},
        metadata={"inline_model": "BHItemChild"},
    )
    assert not inline_entry.is_revertible

    # InMemoryAuditStore hash chain stays valid after ring-buffer eviction!
    mem_store = InMemoryAuditStore(max_entries=3, hash_chain=True)
    for i in range(6):
        mem_store.record(
            AuditEntry(
                id=f"id-{i}",
                timestamp=datetime.now(timezone.utc),
                actor_id="u1",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="bh-items",
                model_label="Item",
                record_pk=str(i),
                record_repr=f"Item {i}",
            )
        )
    ok_mem, bad_id = mem_store.verify_chain()
    assert ok_mem and bad_id is None

    # SQLAlchemyAuditStore(hash_chain=False).verify_chain() returns (True, None)
    eng = _make_engine()
    sa_nochain = SQLAlchemyAuditStore(eng, hash_chain=False)
    sa_nochain.record(
        AuditEntry(
            id="nc-1",
            timestamp=datetime.now(timezone.utc),
            actor_id="u1",
            actor_name="Admin",
            actor_ip="127.0.0.1",
            action="create",
            model_slug="bh-items",
            model_label="Item",
            record_pk="1",
            record_repr="Item 1",
        )
    )
    assert sa_nochain.verify_chain() == (True, None)

    # audit_revert enforces dynamic get_readonly_fields, FK scope, soft-delete, and bumps version
    class GuardedItemView(ModelView):
        model = BHItem
        columns = ("id", "title", "category_id")
        form_columns = ("title", "category_id")
        soft_delete_column = "deleted_at"
        version_column = "version"

        def get_readonly_fields(
            self, user: DeckUser | None, obj: Any | None = None
        ) -> tuple[str, ...]:
            if obj is not None and obj.locked:
                return ("title",)
            return ()

        def formfield_for_foreignkey(
            self, field_name: str, stmt: Any, user: DeckUser | None, obj: Any | None = None
        ) -> Any:
            if field_name == "category_id":
                return stmt.where(BHCategory.is_active.is_(True))
            return stmt

    audit_store = InMemoryAuditStore(hash_chain=True)
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-audit-revert-secret-32-bytes!"
    app.config["TESTING"] = True
    deck = Deck(app, engine=eng, allow_insecure_open=True, audit_store=audit_store)
    deck.register(BHCategory, GuardedItemView)

    with sessionmaker(bind=eng)() as s:
        c_act = BHCategory(name="Active", is_active=True)
        c_inact = BHCategory(name="Inactive", is_active=False)
        s.add_all([c_act, c_inact])
        s.flush()
        it = BHItem(title="CurrentTitle", category_id=c_act.id, locked=True, version=3)
        s.add(it)
        s.commit()
        it_id, inact_id = it.id, c_inact.id

    # Record an audit entry attempting to revert dynamically readonly `title` and inactive `category_id`
    e_rev = audit_store.record(
        AuditEntry(
            id="rev-1",
            timestamp=datetime.now(timezone.utc),
            actor_id="u1",
            actor_name="Admin",
            actor_ip="127.0.0.1",
            action="update",
            model_slug="bh-items",
            model_label="Item",
            record_pk=str(it_id),
            record_repr="CurrentTitle",
            changes={
                "title": {"old": "OldTitle", "new": "CurrentTitle"},
                "category_id": {"old": inact_id, "new": 1},
            },
        )
    )
    # _sanitize_audit_entry preserves prev_hash & entry_hash
    san = deck._sanitize_audit_entry(e_rev, None)
    assert san.entry_hash == e_rev.entry_hash and san.prev_hash == e_rev.prev_hash

    client = app.test_client()
    r_aud = client.get("/admin/_audit")
    csrf = _extract_csrf(r_aud.get_data(as_text=True))
    r_post = client.post(
        f"/admin/_audit/{e_rev.id}/revert",
        data={"_csrf_token": csrf},
        follow_redirects=True,
    )
    assert r_post.status_code == 200
    with sessionmaker(bind=eng)() as s:
        after = s.get(BHItem, it_id)
        assert after is not None
        # Both readonly title and out-of-scope inactive FK were blocked!
        assert after.title == "CurrentTitle"
        assert after.category_id != inact_id


# ---------------------------------------------------------------------------
# 5. Composite Integer PK, pk: Escaping, and REST/MCP PATCH Non-Corruption
# ---------------------------------------------------------------------------
def test_composite_pk_and_rest_mcp_patch_safety() -> None:
    # encode_pk / decode_pk escapes literal "pk:" prefix
    str_meta = introspect_model(BHStringKey)
    encoded_lit = encode_pk(("pk:123",))
    assert encoded_lit != "pk:123"
    assert decode_pk(encoded_lit, str_meta) == ("pk:123",)
    assert decode_pk(encode_pk(("123",)), str_meta) == ("123",)

    eng = _make_engine()

    class ItemAPIView(ModelView):
        model = BHItem
        columns = ("id", "title", "is_featured", "scheduled_at")
        form_columns = ("title", "is_featured", "scheduled_at")

        def can_edit_record(self, obj: Any, user: DeckUser | None) -> bool:
            return not obj.locked

    rbac = RBACAuthProvider(
        accounts=(
            RBACAccount(
                password_hash=generate_password_hash("pass"),
                user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
            ),
        ),
        roles=(),
    )
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-rest-mcp-secret-key-32-bytes!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        engine=eng,
        auth=rbac,
        auto_audit=False,
        enable_rest_api=True,
        enable_mcp=True,
        default_timezone="Europe/Istanbul",
    )
    deck.register(BHCompositePair, ItemAPIView)

    # Composite integer PK: both PK columns are in form_fields & import_columns!
    pair_view = deck.get_view("bh-composite-pairs")
    assert "tenant_id" in pair_view.resolved_form_fields
    assert "seq_id" in pair_view.resolved_form_fields
    assert "tenant_id" in pair_view.resolved_import_columns
    assert "seq_id" in pair_view.resolved_import_columns

    # Dry-run + commit CSV import of composite integer PK
    csv_bytes = b"tenant_id,seq_id,name\n10,1,Alpha\n10,2,Beta\n"
    adm_user = DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True)
    with sessionmaker(bind=eng)() as s:
        prev = run_dry_run_import(
            s,
            pair_view,
            raw_bytes=csv_bytes,
            filename="pairs.csv",
            auth=rbac,
            user=adm_user,
        )
        assert prev.creates == 2 and prev.errors == 0
        c_cnt, u_cnt = commit_dry_run_import(s, pair_view, prev, user=adm_user)
        assert c_cnt == 2 and u_cnt == 0

    # REST API PATCH preserves untouched nullable boolean & naive UTC datetime (no +3h drift!)
    with sessionmaker(bind=eng)() as s:
        it = BHItem(
            title="Original",
            is_featured=True,
            scheduled_at=datetime(2026, 6, 1, 12, 0),
            locked=False,
        )
        it_locked = BHItem(title="Locked", locked=True)
        s.add_all([it, it_locked])
        s.commit()
        it_id, locked_id = it.id, it_locked.id

    assert deck.api_key_store is not None
    api_key, krec_adm = build_api_key_record(
        name="adm-key",
        owner_id="u-adm",
        owner_name="admin",
        scopes=("*:*", "mcp:*"),
        is_superuser=True,
    )
    deck.api_key_store.create(krec_adm)
    headers = {"Authorization": f"Bearer {api_key}"}

    r_patch = app.test_client().patch(
        f"/admin/_api/v1/bh-items/{it_id}",
        json={"title": "Patched Title"},
        headers=headers,
    )
    assert r_patch.status_code == 200
    with sessionmaker(bind=eng)() as s:
        refreshed = s.get(BHItem, it_id)
        assert refreshed is not None
        assert refreshed.title == "Patched Title"
        assert refreshed.is_featured is True
        assert refreshed.scheduled_at == datetime(2026, 6, 1, 12, 0)

    # REST API enforces can_edit_record on locked record -> 403
    r_locked = app.test_client().patch(
        f"/admin/_api/v1/bh-items/{locked_id}",
        json={"title": "Hacked"},
        headers=headers,
    )
    assert r_locked.status_code == 403

    # MCP propose_update -> approval execution also preserves untouched nullable boolean & UTC datetime!
    r_mcp = app.test_client().post(
        "/admin/_mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "propose_update",
                "arguments": {
                    "slug": "bh-items",
                    "pk": str(it_id),
                    "values": {"title": "MCP Updated"},
                    "reason": "test partial update",
                },
            },
        },
        headers=headers,
    )
    assert r_mcp.status_code == 200
    assert deck.approval_store is not None
    mcp_reqs = deck.approval_store.list_requests(status="pending")
    assert len(mcp_reqs) == 1
    c_adm = app.test_client()
    adm_csrf = login_as(c_adm, "admin", "pass")
    r_mcp_app = c_adm.post(
        f"/admin/_approvals/{mcp_reqs[0].id}/approve",
        data={"_csrf_token": adm_csrf, "decision_note": "approved"},
        follow_redirects=False,
    )
    assert r_mcp_app.status_code == 302
    with sessionmaker(bind=eng)() as s:
        refreshed = s.get(BHItem, it_id)
        assert refreshed is not None
        assert refreshed.title == "MCP Updated"
        assert refreshed.is_featured is True
        assert refreshed.scheduled_at == datetime(2026, 6, 1, 12, 0)


# ---------------------------------------------------------------------------
# 6. ORM Filters, Aliased Dotted Sort/Filter, Lazy Dynamic, Cascade, Inlines & Batch Edit
# ---------------------------------------------------------------------------
def test_orm_filters_cascade_inlines_and_batch_edit() -> None:
    eng = _make_engine()

    class ChildInline(InlineModelView):
        model = BHItemChild
        columns = ("label", "qty", "category_id")
        max_rows = 2

        def validate_rows(
            self,
            rows: Sequence[Mapping[str, Any]],
            parent_obj: Any,
            user: DeckUser | None,
        ) -> dict[str, list[str]]:
            total_qty = sum(int(r.get("qty") or 0) for r in rows)
            if total_qty > 10:
                return {"__all__": ["Total child qty cannot exceed 10."]}
            return {}

    class CategoryView(ModelView):
        model = BHCategory
        columns = ("id", "name", "parent_id")
        filterable_columns = ("parent.name",)
        sortable_columns = ("id", "parent.name")

        def scope_query(self, stmt: Any, user: DeckUser | None) -> Any:
            return stmt.where(BHCategory.is_active.is_(True))

    class ItemView(ModelView):
        model = BHItem
        columns = ("id", "title", "nullable_state", "is_featured", "category_id")
        form_columns = ("title", "nullable_state", "is_featured", "category_id", "country_code")
        list_filters = (
            EmptyFieldListFilter(column="nullable_state", title="State Empty"),
            RelatedOnlyFieldListFilter(column="category_id", title="Active Cat"),
        )
        inline_edit_mode = "batch"
        inline_editable_columns = ("title", "nullable_state", "is_featured", "category_id")
        inlines = (ChildInline,)

        def can_edit_record(self, obj: Any, user: DeckUser | None) -> bool:
            return not obj.locked

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-orm-filters-secret-32-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(app, engine=eng, allow_insecure_open=True, auto_audit=False)
    deck.register(BHCountry, CategoryView, ItemView)

    with sessionmaker(bind=eng)() as s:
        us = BHCountry(code="US", name="United States")
        s.add(us)
        # Create 45 categories so #45 is outside top-40 FK dropdown limit!
        cats = [BHCategory(name=f"Cat-{i:02d}", is_active=True) for i in range(1, 46)]
        c_inactive = BHCategory(name="InactiveCat", is_active=False)
        s.add_all([*cats, c_inactive])
        s.flush()
        cats[1].parent_id = cats[0].id
        # Self-referential cycle check for cascade analyzer
        cats[2].parent_id = cats[3].id
        cats[3].parent_id = cats[2].id

        it1 = BHItem(
            title="Item 1",
            nullable_state=None,
            is_featured=None,
            category_id=cats[44].id,
            country_code="US",
            locked=False,
        )
        it2 = BHItem(
            title="Locked Item",
            nullable_state=ItemState.OPEN,
            is_featured=True,
            category_id=cats[0].id,
            locked=True,
        )
        s.add_all([it1, it2])
        s.flush()
        ch1 = BHItemChild(item_id=it1.id, label="ExistingChild", qty=8, category_id=cats[0].id)
        s.add(ch1)
        s.commit()
        it1_id, it2_id, cat45_id, inact_id, us_id = (
            it1.id,
            it2.id,
            cats[44].id,
            c_inactive.id,
            us.id,
        )
        cat2_id = cats[2].id

    client = app.test_client()

    # EmptyFieldListFilter on sa.Enum works without LookupError!
    r_ef = client.get("/admin/bh-items/?cf_nullable_state__empty=1")
    assert r_ef.status_code == 200
    assert "Item 1" in r_ef.get_data(as_text=True)

    # Self-referential dotted filter & sort (parent.name) works via aliased()!
    r_self = client.get("/admin/bh-categories/?f_parent.name=Cat-01&sort=parent.name")
    assert r_self.status_code == 200
    assert "Cat-02" in r_self.get_data(as_text=True)

    # Model with lazy="dynamic" relationship renders detail without 500!
    r_det = client.get(f"/admin/bh-items/{it1_id}")
    assert r_det.status_code == 200

    # List page injects out-of-top-40 FK option (cat45_id) into batch FK select!
    r_list = client.get("/admin/bh-items/")
    html_list = r_list.get_data(as_text=True)
    assert f'value="{cat45_id}"' in html_list

    csrf = _extract_csrf(html_list)

    # Batch edit submitting untouched locked row + edited row 1 succeeds AND preserves None values!
    r_batch = client.post(
        "/admin/bh-items/batch-edit",
        data={
            "_csrf_token": csrf,
            "batch__0___pk": str(it1_id),
            "batch__0__title": "Item 1 Batch",
            "batch__0__nullable_state": "",
            "batch__0__is_featured": "",
            "batch__1___pk": str(it2_id),
            "batch__1__title": "Locked Item",
            "batch__1__nullable_state": "open",
            "batch__1__is_featured": "1",
        },
        follow_redirects=False,
    )
    assert r_batch.status_code == 302
    with sessionmaker(bind=eng)() as s:
        r1 = s.get(BHItem, it1_id)
        assert r1 is not None
        assert r1.title == "Item 1 Batch"
        assert r1.nullable_state is None
        assert r1.is_featured is None

    # Inline validate_rows & max_rows cannot be bypassed by omitting existing child _pk!
    r_inl_bypass = client.post(
        f"/admin/bh-items/{it1_id}/edit",
        data={
            "_csrf_token": csrf,
            "title": "Item 1 Batch",
            # Existing child (qty=8) omitted! Adding new child with qty=5 -> total 13 > 10!
            "inline__bh-item-childs__0__label": "NewChild",
            "inline__bh-item-childs__0__qty": "5",
        },
    )
    assert r_inl_bypass.status_code == 200
    assert "Total child qty cannot exceed 10" in r_inl_bypass.get_data(as_text=True)

    # Inline child FK target outside CategoryView.scope_query (inactive) is blocked!
    r_inl_fk = client.post(
        f"/admin/bh-items/{it1_id}/edit",
        data={
            "_csrf_token": csrf,
            "title": "Item 1 Batch",
            "inline__bh-item-childs__0__label": "BadFKChild",
            "inline__bh-item-childs__0__qty": "1",
            "inline__bh-item-childs__0__category_id": str(inact_id),
        },
    )
    assert r_inl_fk.status_code == 200
    assert "outside your allowed scope" in r_inl_fk.get_data(as_text=True)

    # Cascade impact analyzer handles non-PK unique FK (`country_code`) & self-ref cycles cleanly!
    with sessionmaker(bind=eng)() as s:
        imp_country = analyze_delete_impact(
            s,
            deck,
            deck.get_view("bh-countries"),
            sa.select(BHCountry.id).where(BHCountry.id == us_id),
            1,
            user=None,
        )
        assert imp_country.total_affected >= 1

        imp_cycle = analyze_delete_impact(
            s,
            deck,
            deck.get_view("bh-categories"),
            sa.select(BHCategory.id).where(BHCategory.id == cat2_id),
            1,
            user=None,
        )
        assert imp_cycle.total_affected <= 2  # Cycle does not inflate count!


# ---------------------------------------------------------------------------
# 7. Approvals, Actions, Widgets, Charts, Jobs, Sessions, i18n, Checks & Demo
# ---------------------------------------------------------------------------
def test_approvals_actions_widgets_ops_and_demo(tmp_path: Path) -> None:
    eng = _make_engine()
    hook_calls: list[str] = []

    class ApprovalItemView(ModelView):
        model = BHItem
        columns = ("id", "title", "version")
        form_columns = ("title",)
        version_column = "version"

        def requires_approval(
            self,
            user: DeckUser | None,
            operation: str,
            obj: Any | None = None,
            payload: Mapping[str, Any] | None = None,
        ) -> bool:
            return operation in {"edit", "action"}

        def on_model_change(self, obj: Any, *, is_created: bool, user: DeckUser | None) -> None:
            hook_calls.append(f"change:{obj.title}")

        @action("export_txt", label="Export TXT")
        def export_txt(self, records: list[Any], form: Any, user: Any) -> Response:
            return Response("ok-txt", mimetype="text/plain")

        @action("view_local_act", label="View Local Action")
        def view_local_act(self, records: list[Any], form: Any, user: Any) -> str:
            return "ran"

    rbac = RBACAuthProvider(
        accounts=(
            RBACAccount(
                password_hash=generate_password_hash("pass"),
                user=DeckUser(id="u-req", username="requester", roles=("editor",)),
            ),
            RBACAccount(
                password_hash=generate_password_hash("pass"),
                user=DeckUser(id="u-app", username="approver", roles=("admin",), is_superuser=True),
            ),
        ),
        roles=(
            Role(
                name="editor",
                permissions=(
                    "bh-items:view",
                    "bh-items:edit",
                    "bh-items:action",
                    "bh-items:action:export_txt",
                ),
            ),
        ),
    )

    @action("site_custom", label="Original Label", permission="bh-items:edit", confirm=True)
    def site_fn(records: list[Any], form: Any, user: Any) -> str:
        return f"site:{len(records)}"

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "bh-approvals-ops-secret-32-byte!"
    app.config["TESTING"] = True
    ap_store = InMemoryApprovalStore()
    deck = Deck(
        app,
        engine=eng,
        auth=rbac,
        approval_store=ap_store,
        auto_audit=False,
    )
    deck.register(ApprovalItemView)
    deck.add_action(site_fn, label="Overridden Label")
    deck.disable_action("view_local_act")

    # add_action preserves @action metadata; disable_action suppresses view-level action too!
    item_view = deck.get_view("bh-items")
    resolved_acts = item_view.get_actions(None)
    assert "view_local_act" not in resolved_acts
    assert deck._site_actions["site_custom"][0].permission == "bh-items:edit"
    assert deck._site_actions["site_custom"][0].confirm is True
    assert deck._site_actions["site_custom"][0].label == "Overridden Label"

    with sessionmaker(bind=eng)() as s:
        it = BHItem(title="V1", version=5)
        s.add(it)
        s.commit()
        it_id = it.id

    # Edit requiring approval must NOT call on_model_change prematurely AND must increment version 5 -> 6!
    c_req = app.test_client()
    req_csrf = login_as(c_req, "requester", "pass")
    r_ed = c_req.post(
        f"/admin/bh-items/{it_id}/edit",
        data={"_csrf_token": req_csrf, "title": "V2-Approved"},
        follow_redirects=False,
    )
    assert r_ed.status_code == 302
    assert hook_calls == []

    # Response-returning action queued for approval executes cleanly upon approval (no crash!)
    r_act = c_req.post(
        "/admin/bh-items/action/export_txt",
        data={"_csrf_token": req_csrf, "selected_pks": [str(it_id)]},
        follow_redirects=False,
    )
    assert r_act.status_code == 302

    pending = ap_store.list_requests(status="pending")
    assert len(pending) == 2

    c_app = app.test_client()
    app_csrf = login_as(c_app, "approver", "pass")
    for req in pending:
        r_ok = c_app.post(
            f"/admin/_approvals/{req.id}/approve",
            data={"_csrf_token": app_csrf, "decision_note": "lgtm"},
            follow_redirects=False,
        )
        assert r_ok.status_code == 302

    with sessionmaker(bind=eng)() as s:
        final_it = s.get(BHItem, it_id)
        assert final_it is not None
        assert final_it.title == "V2-Approved"
        assert final_it.version == 6  # Incremented from 5 -> 6 (NOT rolled back to 2!)
    assert hook_calls == ["change:V2-Approved"]

    # Widgets HTML attributes
    color_html = str(ColorWidget().render(name="col", field_id="fld_col", value="#f0a"))
    assert 'value="#ff00aa"' in color_html
    assert "data-color-widget" in color_html and "data-color-input" in color_html and "data-color-label" in color_html
    tag_html = str(
        TagInputWidget().render(
            name="tags", field_id="fld_tags", value=["a", "b"]
        )
    )
    assert "data-deck-tags" in tag_html and "data-tags-chips" in tag_html and "data-tags-input" in tag_html and "data-tags-hidden" in tag_html
    tag_ro_html = str(TagInputWidget().render(name="tags", field_id="fld_tags", value=["a"], readonly=True))
    assert "data-tags-input" not in tag_ro_html and " disabled" in tag_ro_html
    slider_html = str(SliderWidget(unit="%").render(name="pct", field_id="fld_pct", value=50))
    assert 'data-slider-suffix="%"' in slider_html

    # Heatmap chart tolerates None / invalid counts without TypeError
    hm_svg = render_heatmap_chart(
        [(date(2026, 3, 1), None), (date(2026, 3, 2), "bad"), (date(2026, 3, 3), 5)]  # type: ignore[list-item]
    )
    assert "<svg" in hm_svg

    # InMemorySessionStore evicts >2000 active sessions and normalizes naive/aware last_seen_at
    sstore = InMemorySessionStore()
    now_s = datetime.now(timezone.utc)
    for i in range(2005):
        sstore.register(
            SessionRecord(
                session_id=f"sid-{i}",
                user_id="u1",
                username="alice",
                ip_address="127.0.0.1",
                user_agent="pytest",
                created_at=now_s,
                last_seen_at=now_s,
            )
        )
    assert len(sstore._records) <= 2000
    sstore._records["sid-2004"].last_seen_at = datetime(2026, 1, 1, 0, 0)
    listed = sstore.list_sessions(user_id="u1")
    assert len(listed) > 0

    # BabelTranslator falls back to active locale (not hardcoded "en")
    class _FakeBabel:
        @staticmethod
        def get_locale() -> str:
            return "tr"

        @staticmethod
        def gettext(text: str) -> str:
            return text

    bt = BabelTranslator(babel_module=_FakeBabel())
    assert bt.translate("Dashboard") == BUILTIN_CATALOGS["tr"]["Dashboard"]

    # System checks: dotted filterable/sortable caught, sensitive readonly caught, VirtualField in radio_fields allowed, custom password_validators suppresses W002
    class BadChecksView(ModelView):
        model = BHItem
        filterable_columns = ("category.nonexistent",)
        sortable_columns = ("category.bad_sort",)
        readonly_fields = ("secret_code",)
        extra_form_fields = (VirtualField(name="vchoice", label="V", choices=(("a", "A"),)),)
        radio_fields = MappingProxyType({"vchoice": "horizontal"})

    iam_custom = SQLAlchemyAuthProvider(eng, password_validators=(lambda p, **_: [],))
    app2 = Flask(__name__)
    app2.config["SECRET_KEY"] = "bh-checks-secret-key-32-bytes!!!"
    app2.config["TESTING"] = True
    deck2 = Deck(app2, engine=eng, auth=iam_custom, auto_audit=False)
    deck2.register(BadChecksView)
    check_msgs = run_model_view_checks(deck2)
    codes = {m.code for m in check_msgs}
    assert "DECK-E001" in codes
    assert "DECK-E009" in codes
    assert "DECK-W002" not in codes
    assert not any("vchoice" in m.message for m in check_msgs)

    # SQLAlchemyJobBackend truncates overly long labels cleanly
    jb = SQLAlchemyJobBackend(eng)
    try:
        rec = jb.submit(
            name="demo_short",
            label="A" * 400,
            actor_id="u1",
            actor_name="Admin",
            model_slug="",
            fn=lambda ctx: {"ok": True},
        )
        assert len(rec.label) <= 255
    finally:
        jb.shutdown(wait=True)

    # Demo app: saved view query strings have no leading `?`, sq-bi-sla-risk returns rows, templates clean
    demo_app = create_demo_app(db_uri=f"sqlite:///{tmp_path / 'demo_bh.db'}", seed_profile="showcase")
    demo_deck: Deck = next(iter(demo_app.extensions["flask_deck"].values()))
    _MANAGED_DECKS.append(demo_deck)
    _MANAGED_ENGINES.append(demo_deck.adapter.get_engine())
    assert demo_deck.saved_view_store is not None
    for slug in demo_deck.views:
        for sv in demo_deck.saved_view_store.list_for_model(slug, user_id=None):
            assert not sv.query_string.startswith("?"), f"Leading ? in saved view {sv.name}"

    dc = demo_app.test_client()
    d_csrf = login_as(dc, "admin@acme.dev", "deck-demo-2026")
    # Sessions page must not contain double-escaped &amp;amp;
    r_sess = dc.get("/admin/_security/sessions")
    assert r_sess.status_code == 200
    assert "&amp;amp;" not in r_sess.get_data(as_text=True)

    # Model form (with inlines) must not contain malformed hidden=&quot;hidden&quot;
    form_slug = next(
        (s for s, v in demo_deck.views.items() if v.can_create and v.inlines),
        next(s for s, v in demo_deck.views.items() if v.can_create),
    )
    r_form = dc.get(f"/admin/{form_slug}/new")
    assert r_form.status_code == 200
    assert "hidden=&quot;hidden&quot;" not in r_form.get_data(as_text=True)

    # Login page renders flashed messages (e.g. after logout)
    r_out = dc.post("/admin/logout", data={"_csrf_token": d_csrf}, follow_redirects=True)
    assert r_out.status_code == 200
    assert "dk-toasts" in r_out.get_data(as_text=True)

    # Demo SQL preset sq-bi-sla-risk executes and returns at least 1 row!
    assert demo_deck.saved_query_store is not None
    sla_q = demo_deck.saved_query_store.get("sq-bi-sla-risk")
    assert sla_q is not None
    with demo_deck.adapter.get_engine().connect() as conn:
        sla_rows = conn.execute(sa.text(sla_q.sql)).all()
    assert len(sla_rows) >= 1

    # Every template i18n key is translated in tr, de, ar!
    pat = re.compile(r"""\b_\(\s*(['"])(.+?)\1\s*\)""")
    tpl_root = Path(__file__).resolve().parent.parent / "src" / "flask_deck" / "templates"
    used_keys = {k for p in tpl_root.rglob("*.html") for _, k in pat.findall(p.read_text())}
    for loc in ("tr", "de", "ar"):
        missing = used_keys - set(BUILTIN_CATALOGS[loc].keys())
        assert not missing, f"Missing i18n keys in {loc}: {sorted(missing)}"
