from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckUser,
    EmptyFieldListFilter,
    ModelView,
    RBACAuthProvider,
    RelatedOnlyFieldListFilter,
    Role,
    parse_search_column_spec,
    tokenize_search_query,
)
from tests.conftest import login_as


class SBase(DeclarativeBase):
    pass


class SRegion(SBase):
    __tablename__ = "v06_s_regions"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    secret_key: Mapped[str] = mapped_column(sa.String(64), default="reg-secret-999")

    def __str__(self) -> str:
        return self.code


class SOrg(SBase):
    __tablename__ = "v06_s_orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    tenant_id: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    region_id: Mapped[int | None] = mapped_column(sa.ForeignKey("v06_s_regions.id"), nullable=True)
    internal_note: Mapped[str] = mapped_column(sa.String(120), default="org-confidential")
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    region: Mapped[SRegion | None] = relationship()

    def __str__(self) -> str:
        return self.name


s_order_tag = sa.Table(
    "v06_s_order_tags",
    SBase.metadata,
    sa.Column("order_id", sa.ForeignKey("v06_s_orders.id"), primary_key=True),
    sa.Column("tag_id", sa.ForeignKey("v06_s_tags.id"), primary_key=True),
)


class STag(SBase):
    __tablename__ = "v06_s_tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    def __str__(self) -> str:
        return self.name


class SOrder(SBase):
    __tablename__ = "v06_s_orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(140), nullable=False)
    notes: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    flagged: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)
    org_id: Mapped[int | None] = mapped_column(sa.ForeignKey("v06_s_orgs.id"), nullable=True)
    tenant_id: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    org: Mapped[SOrg | None] = relationship()
    lines: Mapped[list[SOrderLine]] = relationship(back_populates="order", cascade="all, delete-orphan")
    tags: Mapped[list[STag]] = relationship(secondary=s_order_tag)

    def __str__(self) -> str:
        return self.code


class SOrderLine(SBase):
    __tablename__ = "v06_s_order_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(sa.ForeignKey("v06_s_orders.id"), nullable=False)
    sku: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    order: Mapped[SOrder] = relationship(back_populates="lines")


@pytest.fixture()
def search_app() -> Iterator[tuple[Flask, Deck]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "v06-search-test-secret-key-at-least-32b"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    with SessionLocal() as sess:
        r_eu = SRegion(code="EU-WEST", secret_key="SECRET-EU-KEY")
        r_us = SRegion(code="US-EAST", secret_key="SECRET-US-KEY")
        sess.add_all([r_eu, r_us])
        sess.flush()

        o_acme = SOrg(name="Acme Corp", tenant_id=1, region_id=r_eu.id, internal_note="SECRET-XYZ-NOTE")
        o_beta = SOrg(name="Beta Labs", tenant_id=1, region_id=r_us.id, internal_note="PUBLIC-BETA")
        o_unused = SOrg(name="Unused Org", tenant_id=1, region_id=r_eu.id)
        o_deleted = SOrg(name="Ghost Org", tenant_id=1, region_id=r_eu.id, deleted_at=now)
        o_t2 = SOrg(name="Tenant2 Org", tenant_id=2, region_id=r_us.id)
        sess.add_all([o_acme, o_beta, o_unused, o_deleted, o_t2])
        sess.flush()

        t_vip = STag(name="vip-priority")
        t_bulk = STag(name="bulk-wholesale")
        sess.add_all([t_vip, t_bulk])
        sess.flush()

        ord1 = SOrder(
            code="ORD-100",
            title="Alpha Rocket Engine",
            notes="Handle with care",
            flagged=True,
            org_id=o_acme.id,
            tenant_id=1,
            due_at=now,
            tags=[t_vip],
        )
        ord2 = SOrder(
            code="ORD-200",
            title="Beta Solar Panel",
            notes="",
            flagged=False,
            org_id=o_beta.id,
            tenant_id=1,
            due_at=now - timedelta(days=400),
            tags=[t_bulk],
        )
        ord3 = SOrder(
            code="ORD-300",
            title="Gamma Quantum Sensor",
            notes=None,
            flagged=None,
            org_id=None,
            tenant_id=1,
            due_at=None,
        )
        ord4 = SOrder(
            code="ORD-999",
            title="Tenant Two Confidential",
            notes="t2 note",
            flagged=True,
            org_id=o_t2.id,
            tenant_id=2,
            due_at=now,
        )
        sess.add_all([ord1, ord2, ord3, ord4])
        sess.flush()
        sess.add_all(
            [
                SOrderLine(order_id=ord1.id, sku="SKU-ROCKET-9"),
                SOrderLine(order_id=ord2.id, sku="SKU-SOLAR-2"),
            ]
        )
        # Add extra rows for numbered pagination test
        for idx in range(1, 22):
            sess.add(
                SOrder(
                    code=f"PAG-{idx:03d}",
                    title=f"Page Filler {idx}",
                    notes="filler",
                    flagged=False,
                    org_id=o_acme.id,
                    tenant_id=1,
                    due_at=now,
                )
            )
        sess.commit()

    class RegionView(ModelView):
        model = SRegion
        slug = "regions"

    class OrgView(ModelView):
        model = SOrg
        slug = "orgs"
        soft_delete_column = "deleted_at"

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
            if user is not None and not user.is_superuser and user.tenant_id is not None:
                return stmt.where(SOrg.tenant_id == user.tenant_id)
            return stmt

    class OrderView(ModelView):
        model = SOrder
        slug = "orders"
        page_size = 5
        show_full_result_count = True
        list_select_related = ("org", "org.region")
        columns = ("code", "title", "org", "flagged", "due_at")
        searchable_columns = (
            "^code",
            "title",
            "=org.name",
            "org.region.code",
            "org.internal_note",
            "org.region.secret_key",
            "lines.sku",
            "tags.name",
        )
        filterable_columns = ("flagged", "org_id", "due_at")
        custom_filters = (
            EmptyFieldListFilter(column="notes", title="Notes"),
            RelatedOnlyFieldListFilter(column="org_id", title="Active Org"),
        )

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
            if user is not None and not user.is_superuser and user.tenant_id is not None:
                return stmt.where(SOrder.tenant_id == user.tenant_id)
            return stmt

    class CustomSearchOrderView(ModelView):
        model = SOrder
        slug = "custom-orders"
        is_primary_view = False
        columns = ("code", "title")

        def get_search_results(
            self, stmt: sa.Select[Any], search_term: str, user: DeckUser | None
        ) -> tuple[sa.Select[Any], bool]:
            _ = user
            if search_term.startswith("magic:"):
                return stmt.where(SOrder.code == search_term.split(":", 1)[1]), False
            return stmt.where(SOrder.title.ilike(f"%{search_term}%")), True

    class JoinScopedOrderView(ModelView):
        model = SOrder
        slug = "eu-orders"
        is_primary_view = False
        columns = ("code", "title", "org")
        searchable_columns = ("code", "title")

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
            _ = user
            return stmt.join(SOrder.org).join(SOrg.region).where(SRegion.code == "EU-WEST")

    auth = RBACAuthProvider(
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="admin", username="admin", roles=("admin",), is_superuser=True),
                password="pass",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="t1", username="tenant1", roles=("t1_role",), tenant_id=1),
                password="pass",
            ),
        ],
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="t1_role",
                permissions=frozenset({"orders:view", "orgs:view", "regions:view"}),
                hidden_fields={"orgs": frozenset({"internal_note"})},
            ),
        ],
    )
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, max_search_tokens=4, max_search_length=100)
    deck.register(RegionView, OrgView, OrderView, CustomSearchOrderView, JoinScopedOrderView)
    yield app, deck
    deck.close()
    engine.dispose()


def test_tokenizer_and_prefix_spec_parser() -> None:
    assert tokenize_search_query('  alpha "beta gamma"  delta  ') == ["alpha", "beta gamma", "delta"]
    assert tokenize_search_query('"unclosed phrase here') == ["unclosed phrase here"]
    assert len(tokenize_search_query("a b c d e f g", max_tokens=3)) == 3
    assert len(tokenize_search_query("x" * 500, max_len=20)[0]) == 20
    # Pathological input completes immediately without regex backtracking
    assert len(tokenize_search_query('"' * 2000, max_tokens=5, max_len=50)) <= 5

    assert parse_search_column_spec("^code") == ("code", "startswith")
    assert parse_search_column_spec("=org.name") == ("org.name", "exact")
    assert parse_search_column_spec("@title") == ("title", "fts")
    assert parse_search_column_spec("lines.sku") == ("lines.sku", "contains")


def test_search_2_0_tokenized_prefixes_multihop_exists_and_rbac_oracle(
    search_app: tuple[Flask, Deck],
) -> None:
    app, _ = search_app
    c_admin = app.test_client()
    login_as(c_admin, "admin", "pass")

    # Multi-word AND + quoted phrase
    r = c_admin.get('/admin/orders/?q="Alpha Rocket" ORD-100')
    html = r.get_data(as_text=True)
    assert "ORD-100" in html
    assert "ORD-200" not in html
    # show_full_result_count displays filtered count + full total
    assert "of" in html and "25" in html

    # Prefix ^code matches start only (ORD- matches, 100 alone does not match ^code)
    assert "ORD-100" in c_admin.get("/admin/orders/?q=ORD-1").get_data(as_text=True)
    r_mid = c_admin.get("/admin/orders/?q=-100").get_data(as_text=True)
    assert "ORD-100" not in r_mid

    # Exact =org.name requires exact match (case-insensitive)
    assert "ORD-100" in c_admin.get('/admin/orders/?q="Acme Corp"&page_size=50').get_data(as_text=True)
    assert "ORD-100" not in c_admin.get("/admin/orders/?q=Acme&page_size=50").get_data(as_text=True)

    # 2-hop MANYTOONE search (org.region.code)
    r_2hop = c_admin.get("/admin/orders/?q=US-EAST").get_data(as_text=True)
    assert "ORD-200" in r_2hop
    assert "ORD-100" not in r_2hop

    # ONETOMANY EXISTS search (lines.sku)
    r_o2m = c_admin.get("/admin/orders/?q=SKU-ROCKET-9").get_data(as_text=True)
    assert "ORD-100" in r_o2m
    assert "ORD-200" not in r_o2m

    # MANYTOMANY EXISTS search (tags.name)
    r_m2m = c_admin.get("/admin/orders/?q=bulk-wholesale").get_data(as_text=True)
    assert "ORD-200" in r_m2m
    assert "ORD-100" not in r_m2m

    # Sensitive field on 2-hop target (org.region.secret_key) MUST NOT be searchable even for admin
    r_sec = c_admin.get("/admin/orders/?q=SECRET-EU-KEY").get_data(as_text=True)
    assert "ORD-100" not in r_sec

    # RBAC hidden field on 1-hop target (org.internal_note) MUST NOT leak to tenant1 user
    c_t1 = app.test_client()
    login_as(c_t1, "tenant1", "pass")
    r_hidden = c_t1.get("/admin/orders/?q=SECRET-XYZ-NOTE").get_data(as_text=True)
    assert "ORD-100" not in r_hidden
    # Tenant1 cannot see tenant2 orders either
    assert "ORD-999" not in c_t1.get("/admin/orders/").get_data(as_text=True)

    # Custom get_search_results hook
    r_custom = c_admin.get("/admin/custom-orders/?q=magic:ORD-300").get_data(as_text=True)
    assert "ORD-300" in r_custom
    assert "ORD-100" not in r_custom

    # scope_query with explicit .join() preserved in list query
    r_join = c_admin.get("/admin/eu-orders/").get_data(as_text=True)
    assert "ORD-100" in r_join
    assert "ORD-200" not in r_join


def test_filters_2_0_empty_related_only_nullable_presets_and_page_window(
    search_app: tuple[Flask, Deck],
) -> None:
    app, _ = search_app
    c = app.test_client()
    login_as(c, "tenant1", "pass")

    # EmptyFieldListFilter distinguishes NULL and "" from non-empty strings
    r_empty = c.get("/admin/orders/?cf_notes_empty=empty").get_data(as_text=True)
    assert "ORD-200" in r_empty
    assert "ORD-300" in r_empty
    assert "ORD-100" not in r_empty

    r_nonempty = c.get("/admin/orders/?cf_notes_empty=non_empty&page_size=50").get_data(as_text=True)
    assert "ORD-100" in r_nonempty
    assert "ORD-200" not in r_nonempty
    assert "ORD-300" not in r_nonempty

    # RelatedOnlyFieldListFilter lists ONLY referenced active scoped orgs (no Unused, Ghost, or Tenant2)
    list_html = c.get("/admin/orders/").get_data(as_text=True)
    rel_sel_start = list_html.index('id="cf_org_id_rel"')
    rel_sel_html = list_html[rel_sel_start : list_html.index("</select>", rel_sel_start)]
    assert "Acme Corp" in rel_sel_html
    assert "Beta Labs" in rel_sel_html
    assert "Unused Org" not in rel_sel_html
    assert "Ghost Org" not in rel_sel_html
    assert "Tenant2 Org" not in rel_sel_html
    # Apply RelatedOnlyFieldListFilter for Beta Labs (id=2)
    r_rel = c.get("/admin/orders/?cf_org_id_rel=2").get_data(as_text=True)
    assert "ORD-200" in r_rel
    assert "ORD-100" not in r_rel

    # Nullable boolean & nullable FK __null__ filter
    r_null_bool = c.get("/admin/orders/?f_flagged=__null__").get_data(as_text=True)
    assert "ORD-300" in r_null_bool
    assert "ORD-100" not in r_null_bool

    r_null_fk = c.get("/admin/orders/?f_org_id=__null__").get_data(as_text=True)
    assert "ORD-300" in r_null_fk
    assert "ORD-100" not in r_null_fk

    # Date presets: no_date, has_date, year
    r_nodate = c.get("/admin/orders/?f_due_at__preset=no_date").get_data(as_text=True)
    assert "ORD-300" in r_nodate
    assert "ORD-100" not in r_nodate

    r_year = c.get("/admin/orders/?f_due_at__preset=year&page_size=50").get_data(as_text=True)
    assert "ORD-100" in r_year
    assert "ORD-200" not in r_year  # 400 days ago

    # Numbered pagination page_window rendered cleanly
    assert "dk-pag-num is-active" in list_html
    assert "page=2" in list_html
    assert "page=5" in list_html
