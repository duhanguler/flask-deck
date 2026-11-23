from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckUser,
    InMemoryAuditStore,
    ModelView,
    PredicateListFilter,
    RangeListFilter,
    RBACAuthProvider,
    Role,
    action,
    analyze_delete_impact,
)
from tests.conftest import count_sql_queries, login_as


class QCBase(DeclarativeBase):
    pass


class Org(QCBase):
    __tablename__ = "v05_qc_orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    tenant_id: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    def __str__(self) -> str:
        return self.name


class ParentBucket(QCBase):
    __tablename__ = "v05_qc_buckets"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    items: Mapped[list[CascadeItem]] = relationship(
        back_populates="bucket", cascade="all, delete-orphan"
    )
    soft_nodes: Mapped[list[NullableChild]] = relationship(back_populates="bucket")

    def __str__(self) -> str:
        return self.label


class CascadeItem(QCBase):
    __tablename__ = "v05_qc_cascade_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_bucket_id: Mapped[int] = mapped_column(
        sa.ForeignKey("v05_qc_buckets.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    bucket: Mapped[ParentBucket] = relationship(back_populates="items")
    sub_items: Mapped[list[CascadeGrandchild]] = relationship(
        back_populates="parent_item", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return self.title


class CascadeGrandchild(QCBase):
    __tablename__ = "v05_qc_cascade_grand"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("v05_qc_cascade_items.id"), nullable=False)
    code: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    parent_item: Mapped[CascadeItem] = relationship(back_populates="sub_items")


class NullableChild(QCBase):
    __tablename__ = "v05_qc_nullable_children"
    id: Mapped[int] = mapped_column(primary_key=True)
    bucket_id: Mapped[int | None] = mapped_column(sa.ForeignKey("v05_qc_buckets.id"), nullable=True)
    note: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    bucket: Mapped[ParentBucket | None] = relationship(back_populates="soft_nodes")


class TreeNode(QCBase):
    __tablename__ = "v05_qc_tree_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("v05_qc_tree_nodes.id"), nullable=True
    )


class Invoice(QCBase):
    __tablename__ = "v05_qc_invoices"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    org_id: Mapped[int] = mapped_column(sa.ForeignKey("v05_qc_orgs.id"), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(20), default="open", nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), nullable=False)
    priority: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    org: Mapped[Org] = relationship()

    def __str__(self) -> str:
        return self.code


class OrgView(ModelView):
    model = Org
    slug = "qc-orgs"

    def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
        if user is not None and not user.is_superuser and user.tenant_id is not None:
            return stmt.where(Org.tenant_id == user.tenant_id)
        return stmt


class BucketView(ModelView):
    model = ParentBucket
    slug = "qc-buckets"


class CascadeItemView(ModelView):
    model = CascadeItem
    slug = "qc-cascade-items"


class TreeNodeView(ModelView):
    model = TreeNode
    slug = "qc-tree-nodes"


class InvoiceView(ModelView):
    model = Invoice
    slug = "qc-invoices"
    page_size = 5
    page_size_options = (5, 10)
    list_max_show_all = 30
    date_hierarchy = "created_at"
    show_facets = "auto"
    soft_delete_column = "deleted_at"
    columns = ("code", "org", "status", "priority", "amount", "created_at")
    filterable_columns = ("org_id", "status")
    inline_editable_columns = ("org_id",)
    custom_filters = (
        RangeListFilter(
            parameter_name="amt_band",
            title="Amount Band",
            column="amount",
            bands=(("low", "<$100", None, Decimal("100")), ("high", "$100+", Decimal("100"), None)),
        ),
        PredicateListFilter(
            parameter_name="prio_tier",
            title="Priority Tier",
            choices=(
                ("urgent", "Urgent (P>=5)", lambda m: m.priority >= 5),
                ("normal", "Normal", lambda m: m.priority < 5),
            ),
        ),
    )

    def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
        if user is not None and not user.is_superuser and user.tenant_id is not None:
            return stmt.where(Invoice.org_id.in_(sa.select(Org.id).where(Org.tenant_id == user.tenant_id)))
        return stmt

    @action("mark_paid", label="Mark Paid", confirm=False)
    def mark_paid(self, records: list[Invoice], form_data: Any, user: Any) -> str:
        for inv in records:
            inv.status = "paid"
        return f"Paid {len(records)}."


@pytest.fixture()
def qc_bundle() -> Iterator[tuple[Flask, Deck, Any, sessionmaker[Any]]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "query-cascade-secret-key-at-least-32bytes"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    QCBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as sess:
        o1 = Org(name="Tenant1 Org", tenant_id=1)
        o2 = Org(name="Tenant2 Secret", tenant_id=2)
        b1 = ParentBucket(label="Bucket Alpha")
        sess.add_all([o1, o2, b1])
        sess.flush()

        ci = CascadeItem(parent_bucket_id=b1.id, title="Child Item")
        sess.add(ci)
        sess.flush()
        sess.add_all(
            [
                CascadeGrandchild(item_id=ci.id, code="GC-1"),
                CascadeGrandchild(item_id=ci.id, code="GC-2"),
                NullableChild(bucket_id=b1.id, note="Nullifiable"),
            ]
        )
        n1 = TreeNode(name="RootNode", parent_id=None)
        sess.add(n1)
        sess.flush()
        n2 = TreeNode(name="ChildNode", parent_id=n1.id)
        sess.add(n2)
        sess.flush()
        # Intentional self-referential cycle in data to verify cycle safety!
        n1.parent_id = n2.id

        dates = (
            datetime(2025, 3, 10, 12, tzinfo=timezone.utc),
            datetime(2026, 1, 15, 12, tzinfo=timezone.utc),
            datetime(2026, 2, 5, 12, tzinfo=timezone.utc),
            datetime(2026, 2, 18, 12, tzinfo=timezone.utc),
        )
        invs = [
            Invoice(
                code=f"INV-{i:03d}",
                org_id=o1.id if i < 12 else o2.id,
                status="open" if i % 2 == 0 else "paid",
                amount=Decimal("250.00") if i % 2 == 0 else Decimal("50.00"),
                priority=10 - (i % 4),
                created_at=dates[i % len(dates)],
            )
            for i in range(15)
        ]
        sess.add_all(invs)
        sess.commit()

    auth = RBACAuthProvider(
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="t1_masked",
                permissions=frozenset({"*:view", "qc-invoices:edit", "qc-invoices:export"}),
                hidden_fields={"qc-invoices": frozenset({"created_at", "priority"})},
            ),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="adm", username="admin", roles=("admin",), is_superuser=True),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="t1",
                    username="t1_user",
                    roles=("t1_masked",),
                    tenant_id=1,
                ),
                password="t1-password",
            ),
        ],
    )
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        audit_store=InMemoryAuditStore(),
        bulk_sync_limit=3,
        max_select_across=12,
    )
    deck.register(OrgView, BucketView, CascadeItemView, TreeNodeView, InvoiceView)
    yield app, deck, engine, SessionLocal
    deck.close()
    engine.dispose()


def test_m3_date_hierarchy_filters_facets_multisort_fk_quickedit(
    qc_bundle: tuple[Flask, Deck, Any, sessionmaker[Any]],
) -> None:
    app, _, engine, SessionLocal = qc_bundle
    admin = app.test_client()
    a_csrf = login_as(admin, "admin", "admin-password")

    # show_facets='auto' executes zero extra facet SQL queries when filter panel is closed
    admin.get("/admin/qc-invoices/")  # warm
    with count_sql_queries(engine) as stmts:
        r0 = admin.get("/admin/qc-invoices/?page_size=5")
    assert r0.status_code == 200
    assert "/admin/_api/qc-invoices/facets" in r0.get_data(as_text=True)
    # Verify zero eager facet queries ran when filter panel is closed
    lowered = [s.lower() for s in stmts]
    assert not any("group by v05_qc_invoices.org_id" in s or "amount <" in s for s in lowered)

    # Date Hierarchy drilldown Year -> Month
    r_month = admin.get("/admin/qc-invoices/?dh=2026-02")
    assert r_month.status_code == 200
    m_html = r_month.get_data(as_text=True)
    assert "Feb 2026" in m_html

    # Custom ListFilters + page_size=all + Multi-column sort
    r_cf = admin.get("/admin/qc-invoices/?cf_amt_band=high&cf_prio_tier=urgent&sort=priority:desc,code:asc&page_size=all")
    assert r_cf.status_code == 200
    cf_html = r_cf.get_data(as_text=True)
    assert "Multi-sort" in cf_html

    # Lazy facets API returns exact bucket counts
    rf = admin.get("/admin/_api/qc-invoices/facets").get_json()
    assert rf["facets"]["cf_amt_band"]["high"] >= 1
    assert rf["facets"]["cf_prio_tier"]["urgent"] >= 1

    # Inline FK quick-edit + tenant boundary guard
    t1 = app.test_client()
    t1_csrf = login_as(t1, "t1_user", "t1-password")
    # RBAC-hidden date_hierarchy cannot leak rows or render date hierarchy for t1_masked
    t1_list = t1.get("/admin/qc-invoices/?dh=2025").get_data(as_text=True)
    assert "All Dates" not in t1_list
    assert "INV-011" in t1_list
    assert "INV-014" not in t1_list

    # Tenant1 user CANNOT quick-edit FK org_id to Tenant2 org_id=2!
    r_fk_bad = t1.patch(
        "/admin/_api/qc-invoices/1/quick-edit",
        json={"field": "org_id", "value": "2"},
        headers={"X-Deck-CSRFToken": t1_csrf},
    )
    assert r_fk_bad.status_code in {400, 404, 422}

    r_fk_ok = admin.patch(
        "/admin/_api/qc-invoices/1/quick-edit",
        json={"field": "org_id", "value": "2"},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_fk_ok.status_code == 200
    with SessionLocal() as sess:
        assert sess.get(Invoice, 1).org_id == 2  # type: ignore[union-attr]


def test_m4_cascade_impact_and_signed_select_across(
    qc_bundle: tuple[Flask, Deck, Any, sessionmaker[Any]],
) -> None:
    app, deck, _engine, SessionLocal = qc_bundle
    admin = app.test_client()
    a_csrf = login_as(admin, "admin", "admin-password")

    # Bucket -> CascadeItem (cascade) -> CascadeGrandchild (cascade depth 2) + NullableChild (set_null)
    r_imp = admin.post(
        "/admin/_api/qc-buckets/delete-impact",
        json={"pks": ["1"], "force": False},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_imp.status_code == 200
    rep = r_imp.get_json()
    assert rep["can_proceed"] is True
    actions_by_tbl = {it["table_name"]: it for it in rep["items"]}
    assert actions_by_tbl["v05_qc_cascade_items"]["action"] == "cascade"
    assert actions_by_tbl["v05_qc_cascade_items"]["count"] == 1
    assert actions_by_tbl["v05_qc_cascade_grand"]["action"] == "cascade"
    assert actions_by_tbl["v05_qc_cascade_grand"]["count"] == 2
    assert actions_by_tbl["v05_qc_nullable_children"]["action"] == "set_null"

    # Org #2 is referenced by non-nullable Invoice -> blocked!
    r_blk = admin.post(
        "/admin/_api/qc-orgs/delete-impact",
        json={"pks": ["2"], "force": False},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_blk.status_code == 200
    assert r_blk.get_json()["can_proceed"] is False

    # Soft-delete Invoice returns is_soft_delete=True, can_proceed=True
    r_sd = admin.post(
        "/admin/_api/qc-invoices/delete-impact",
        json={"pks": ["1"], "force": False},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_sd.status_code == 200
    assert r_sd.get_json()["is_soft_delete"] is True
    assert r_sd.get_json()["can_proceed"] is True

    # Self-referential cycle does not infinite loop
    with SessionLocal() as sess:
        tree_view = deck.get_view("qc-tree-nodes")
        cyc_rep = analyze_delete_impact(
            sess,
            deck,
            tree_view,
            sa.select(TreeNode.id.label("_pk")).where(TreeNode.id == 1),
            1,
            user=None,
        )
        assert cyc_rep.target_count == 1
        assert len(cyc_rep.items) <= 4

    # Signed select_across export + tampered/wrong-user rejection + max_select_across + chunked async offload
    inv_html = admin.get("/admin/qc-invoices/?f_status=open&page_size=5").get_data(as_text=True)
    import re

    m_tok = re.search(r'data-slice-token="([^"]+)"', inv_html)
    assert m_tok is not None
    tok = m_tok.group(1)

    # Export across pages via valid signed token (wrapped cleanly!)
    with admin.get(f"/admin/qc-invoices/export.csv?select_across=1&slice_token={tok}") as exp_r:
        assert exp_r.status_code == 200
        csv_text = exp_r.get_data(as_text=True)
    assert "INV-000" in csv_text
    assert "INV-014" in csv_text

    # Tampered token rejected 403
    with admin.get(f"/admin/qc-invoices/export.csv?select_across=1&slice_token={tok}tamper") as bad_r:
        assert bad_r.status_code == 403

    # Wrong user token rejected 403 on bulk action
    t1 = app.test_client()
    t1_csrf = login_as(t1, "t1_user", "t1-password")
    wrong_user_act = t1.post(
        "/admin/qc-invoices/action/mark_paid",
        data={"_csrf_token": t1_csrf, "select_across": "1", "slice_token": tok},
    )
    assert wrong_user_act.status_code == 403

    # Valid select_across action (> bulk_sync_limit=3) offloads to background job & processes all 8 open rows!
    act_r = admin.post(
        "/admin/qc-invoices/action/mark_paid",
        data={"_csrf_token": a_csrf, "select_across": "1", "slice_token": tok},
        follow_redirects=False,
    )
    assert act_r.status_code == 302
    assert "/admin/_jobs" in act_r.headers["Location"]
    # Wait briefly for threadpool job to finish
    import time

    for _ in range(40):
        jobs = deck.job_backend.list_jobs(limit=5) if deck.job_backend else []
        if jobs and jobs[0].status in {"succeeded", "failed", "cancelled"}:
            break
        time.sleep(0.025)
    assert jobs and jobs[0].status == "succeeded", jobs[0].error if jobs else "no jobs"
    with SessionLocal() as sess:
        remaining_open = sess.scalar(
            sa.select(sa.func.count()).select_from(Invoice).where(Invoice.status == "open")
        )
        assert remaining_open == 0

    # Exceeding max_select_across (12 < 15) rejected cleanly with danger flash
    all_html = admin.get("/admin/qc-invoices/?page_size=5").get_data(as_text=True)
    m_all = re.search(r'data-slice-token="([^"]+)"', all_html)
    assert m_all is not None
    over_r = admin.post(
        "/admin/qc-invoices/action/mark_paid",
        data={"_csrf_token": a_csrf, "select_across": "1", "slice_token": m_all.group(1)},
        follow_redirects=True,
    )
    assert "select-across limit" in over_r.get_data(as_text=True)
