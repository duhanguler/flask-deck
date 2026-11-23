from __future__ import annotations

import enum
import re
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    CurrencyFormatter,
    Deck,
    DeckUser,
    InMemorySavedQueryStore,
    ModelView,
    RBACAuthProvider,
    Role,
    SavedQueryRecord,
    SQLAlchemyAuditStore,
    SQLAlchemySavedQueryStore,
    action,
    build_sql_chart_svg,
    introspect_engine_schema,
)
from flask_deck.query import build_filter_condition
from flask_deck.security import CSRF_FORM_FIELD, CSRF_HEADER_NAME
from flask_deck.sql_console import SQLQueryResult
from tests.conftest import extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\sstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\son(?:click|change|submit|input|load)\s*=", re.IGNORECASE)


class M5Base(DeclarativeBase):
    pass


class WsTier(enum.Enum):
    STARTER = "starter"
    GROWTH = "growth"
    ENTERPRISE = "enterprise"


class WsOrg(M5Base):
    __tablename__ = "ws_orgs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    tier: Mapped[WsTier] = mapped_column(sa.Enum(WsTier), default=WsTier.STARTER, nullable=False)
    region: Mapped[str] = mapped_column(sa.String(32), default="us-east", nullable=False)
    api_token: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    internal_note: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)

    tasks: Mapped[list[WsTask]] = relationship("WsTask", back_populates="org")

    def __str__(self) -> str:
        return f"Org {self.name}"


class WsTask(M5Base):
    __tablename__ = "ws_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(sa.ForeignKey("ws_orgs.id"), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    title: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    priority: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    amount_cents: Mapped[int] = mapped_column(sa.Integer, default=1000, nullable=False)
    budget: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("10.00"))
    due_on: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    state: Mapped[WsTier] = mapped_column(sa.Enum(WsTier), default=WsTier.STARTER, nullable=False)
    notes: Mapped[str] = mapped_column(sa.Text, default="", nullable=False)
    avatar_file: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)

    org: Mapped[WsOrg] = relationship("WsOrg", back_populates="tasks")

    def __str__(self) -> str:
        return self.title


class WsOrgView(ModelView):
    model = WsOrg
    columns = ("id", "name", "tier", "region")


class WsTaskView(ModelView):
    model = WsTask
    columns = ("id", "org", "title", "priority", "amount_cents", "budget", "due_on", "is_active", "state")
    searchable_columns = ("title", "notes", "org.name")
    filterable_columns = ("title", "notes", "priority", "is_active", "org.tier", "org.region", "org.api_token", "org.internal_note")
    inline_editable_columns = ("title", "priority", "budget", "due_on", "is_active", "state")
    column_formatters = MappingProxyType({"amount_cents": CurrencyFormatter(currency="USD", divisor=100)})
    column_aggregates = MappingProxyType({"amount_cents": "sum"})
    aggregate_scope = "all"
    page_size = 2
    default_sort = ("id", "asc")
    soft_delete_column = "deleted_at"
    calendar_date_field = "due_on"
    calendar_title_field = "title"
    gallery_image_field = "avatar_file"
    gallery_subtitle_field = "org"
    tree_parent_field = "parent_id"
    tree_title_field = "title"
    kanban_column = "state"

    @action("escalate", label="Escalate", row_action=True, bulk_action=True)
    def act_escalate(self, records: list[WsTask], params: dict[str, Any], user: DeckUser | None) -> str:
        for r in records:
            r.priority = 99
        return f"Escalated {len(records)}"


def _assert_strict_csp(resp: Any) -> None:
    html = resp.get_data(as_text=True)
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert not _INLINE_STYLE_RE.search(html)
    assert not _INLINE_HANDLER_RE.search(html)
    assert "<style" not in html.lower()


def _build_ws_env(tmp_path: Path, *, aggregate_scope: str = "all"):
    db_file = tmp_path / "ws.sqlite3"
    eng = sa.create_engine(
        f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False}, future=True
    )
    bind2_file = tmp_path / "analytics.sqlite3"
    eng2 = sa.create_engine(
        f"sqlite:///{bind2_file.as_posix()}", connect_args={"check_same_thread": False}, future=True
    )
    deck: Deck | None = None
    try:
        M5Base.metadata.create_all(eng)
        with Session_bind(eng2) as conn:
            conn.execute(sa.text("CREATE TABLE daily_metrics (day TEXT, orders INTEGER, revenue INTEGER)"))
            conn.execute(sa.text("INSERT INTO daily_metrics VALUES ('2026-11-01', 12, 420), ('2026-11-02', 19, 690)"))
            conn.commit()

        sf = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        today = datetime.now(timezone.utc).date()
        with sf() as s:
            org_ent = WsOrg(name="Acme Corp", tier=WsTier.ENTERPRISE, region="eu-west", api_token="tok_secret", internal_note="vip note")
            org_start = WsOrg(name="Indie Lab", tier=WsTier.STARTER, region="us-east", api_token="tok_indie", internal_note="small")
            s.add_all([org_ent, org_start])
            s.flush()

            t1 = WsTask(org_id=org_ent.id, parent_id=None, title="Root Launch", priority=1, amount_cents=1000, due_on=today, notes="urgent production invoice check", created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=5))
            s.add(t1)
            s.flush()
            t2 = WsTask(org_id=org_ent.id, parent_id=t1.id, title="Child Review", priority=2, amount_cents=2000, due_on=today, notes="annual renewal review")
            t3 = WsTask(org_id=org_start.id, parent_id=t1.id, title="Sibling Audit", priority=3, amount_cents=3000, due_on=today, notes="urgent security compliance")
            t4 = WsTask(org_id=org_ent.id, parent_id=None, title="Null Prio Item", priority=None, amount_cents=4000, due_on=today, notes="quarterly budget planning")
            t5 = WsTask(org_id=org_start.id, parent_id=None, title="Trashed Task", priority=5, amount_cents=9900, due_on=today, deleted_at=datetime.now(timezone.utc).replace(tzinfo=None))
            s.add_all([t2, t3, t4, t5])
            s.commit()

        class ScopedTaskView(WsTaskView):
            pass

        ScopedTaskView.aggregate_scope = aggregate_scope

        auth = RBACAuthProvider(
            roles=[
                Role(name="admin", permissions=frozenset({"*"})),
                Role(
                    name="analyst",
                    permissions=frozenset(
                        {
                            "ws-tasks:view",
                            "ws-tasks:edit",
                            "ws-tasks:action:escalate",
                            "sql:query",
                            "ws-orgs:view",
                        }
                    ),
                    masked_fields={
                        "ws-orgs": frozenset({"internal_note"}),
                        "ws-tasks": frozenset({"amount_cents"}),
                    },
                    hidden_fields={"ws-orgs": frozenset({"region"})},
                    readonly_fields={"ws-tasks": frozenset({"title"})},
                ),
                Role(
                    name="restricted",
                    permissions=frozenset({"ws-tasks:view"}),
                    hidden_fields={"ws-tasks": frozenset({"due_on"})},
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-admin", username="admin", roles=("admin",), is_superuser=True),
                    password="pass",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-analyst", username="analyst", roles=("analyst",)),
                    password="pass",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-restricted", username="restricted", roles=("restricted",)),
                    password="pass",
                ),
            ],
        )

        app = Flask(__name__)
        app.secret_key = "m5-flask-secret"
        app.testing = True

        audit_store = SQLAlchemyAuditStore(eng)
        sq_store = SQLAlchemySavedQueryStore(eng)
        deck = Deck(
            app,
            session_factory=sf,
            engine=eng,
            binds={"analytics": eng2},
            auth=auth,
            audit_store=audit_store,
            saved_query_store=sq_store,
            enable_sql_console=True,
            page_size=2,
        )
        deck.register(WsOrgView, ScopedTaskView)
        return app, deck, eng, eng2, sf, today
    except Exception:
        if deck is not None:
            deck.close()
        eng.dispose()
        eng2.dispose()
        raise


class Session_bind:
    def __init__(self, eng: sa.Engine) -> None:
        self._eng = eng
        self._conn: Any = None

    def __enter__(self) -> Any:
        self._conn = self._eng.connect()
        return self._conn

    def __exit__(self, *args: object) -> None:
        if self._conn is not None:
            self._conn.close()


def test_multi_view_modes_calendar_gallery_tree_and_cycle_safety(tmp_path: Path) -> None:
    app, deck, eng, eng2, sf, today = _build_ws_env(tmp_path)
    try:
        # Inject a pure cycle (t6 <-> t7) to verify cycle-safe DFS
        with sf() as s:
            org = s.scalars(sa.select(WsOrg)).first()
            assert org is not None
            t6 = WsTask(org_id=org.id, parent_id=999, title="Cycle A")
            t7 = WsTask(org_id=org.id, parent_id=998, title="Cycle B")
            s.add_all([t6, t7])
            s.flush()
            t6.parent_id = t7.id
            t7.parent_id = t6.id
            s.commit()

        client = app.test_client()
        login_as(client, "admin", "pass")

        # 1. Table view shows all 5 view switcher buttons
        resp_tbl = client.get("/admin/ws-tasks/")
        assert resp_tbl.status_code == 200
        _assert_strict_csp(resp_tbl)
        tbl_html = resp_tbl.get_data(as_text=True)
        for mode in ("Board", "Calendar", "Gallery", "Tree"):
            assert mode in tbl_html

        # 2. Calendar view
        m_str = today.strftime("%Y-%m")
        resp_cal = client.get(f"/admin/ws-tasks/?view=calendar&month={m_str}")
        assert resp_cal.status_code == 200
        _assert_strict_csp(resp_cal)
        cal_html = resp_cal.get_data(as_text=True)
        assert "Root Launch" in cal_html
        assert "Trashed Task" not in cal_html

        # 3. Gallery view
        resp_gal = client.get("/admin/ws-tasks/?view=gallery")
        assert resp_gal.status_code == 200
        _assert_strict_csp(resp_gal)
        assert "dk-gallery-card" in resp_gal.get_data(as_text=True)

        # 4. Tree view renders nested depth classes + cyclic nodes without infinite recursion
        resp_tree = client.get("/admin/ws-tasks/?view=tree")
        assert resp_tree.status_code == 200
        _assert_strict_csp(resp_tree)
        tree_html = resp_tree.get_data(as_text=True)
        assert "dk-tree-d0" in tree_html
        assert "dk-tree-d1" in tree_html
        assert "Cycle A" in tree_html
        assert "Cycle B" in tree_html

        # 5. Restricted user with due_on hidden falls back cleanly from calendar to table
        client_r = app.test_client()
        login_as(client_r, "restricted", "pass")
        resp_cal_denied = client_r.get(f"/admin/ws-tasks/?view=calendar&month={m_str}")
        assert resp_cal_denied.status_code == 200
        assert "Calendar" not in resp_cal_denied.get_data(as_text=True)
    finally:
        deck.close()
        eng.dispose()
        eng2.dispose()


def test_universal_inline_edit_row_actions_links_and_subtables(tmp_path: Path) -> None:
    app, deck, eng, eng2, sf, _today = _build_ws_env(tmp_path)
    try:
        client = app.test_client()
        login_as(client, "admin", "pass")

        resp_list = client.get("/admin/ws-tasks/")
        assert resp_list.status_code == 200
        html = resp_list.get_data(as_text=True)
        csrf = extract_csrf(html)
        assert "data-deck-quick-input" in html
        assert 'name="selected_pks"' in html
        assert "Escalate" in html
        assert "dk-link" in html  # clickable FK badge link to /admin/ws-orgs/<id>

        # Inline edit scalar fields: string, integer, decimal, date, enum, boolean
        updates = [
            ("title", "Updated Root"),
            ("priority", "7"),
            ("budget", "249.50"),
            ("due_on", "2027-01-15"),
            ("state", "enterprise"),
            ("is_active", False),
        ]
        for field_name, val in updates:
            r2 = client.patch(
                "/admin/_api/ws-tasks/1/quick-edit",
                json={"field": field_name, "value": val},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r2.status_code == 200, r2.get_data(as_text=True)
            data = r2.get_json()
            assert data["ok"] is True

        with sf() as s:
            t1 = s.get(WsTask, 1)
            assert t1 is not None
            assert t1.title == "Updated Root"
            assert t1.priority == 7
            assert t1.budget == Decimal("249.50")
            assert t1.due_on == date(2027, 1, 15)
            assert t1.state == WsTier.ENTERPRISE
            assert t1.is_active is False

        # Audit log recorded inline_edit
        assert deck.audit_store is not None
        entries, _ = deck.audit_store.list_entries(model_slug="ws-tasks", limit=20)
        assert any(e.action == "inline_edit" for e in entries)

        # Row-level action executes cleanly with selected_pks
        r_act = client.post(
            "/admin/ws-tasks/action/escalate",
            data={CSRF_FORM_FIELD: csrf, "selected_pks": "1"},
            follow_redirects=True,
        )
        assert r_act.status_code == 200
        with sf() as s:
            t1 = s.get(WsTask, 1)
            assert t1 is not None and t1.priority == 99

        # Detail & Drawer render clickable FK links and 1-to-N subtable on parent Org detail
        r_org = client.get("/admin/ws-orgs/1")
        assert r_org.status_code == 200
        _assert_strict_csp(r_org)
        org_html = r_org.get_data(as_text=True)
        assert "Updated Root" in org_html
        assert "/admin/ws-tasks/1" in org_html

        r_drawer = client.get("/admin/_api/ws-tasks/1/drawer")
        assert r_drawer.status_code == 200
        _assert_strict_csp(r_drawer)
        assert "/admin/ws-orgs/1" in r_drawer.get_data(as_text=True)

        # Analyst has readonly_fields={'title'}: cannot quick-edit title
        client_a = app.test_client()
        csrf2 = login_as(client_a, "analyst", "pass")
        r_ro = client_a.patch(
            "/admin/_api/ws-tasks/1/quick-edit",
            json={"field": "title", "value": "Hack"},
            headers={CSRF_HEADER_NAME: csrf2},
        )
        assert r_ro.status_code == 403
        # Restricted user without ws-orgs:view should NOT see clickable /admin/ws-orgs/ links
        client_r = app.test_client()
        login_as(client_r, "restricted", "pass")
        r_no_link = client_r.get("/admin/ws-tasks/1")
        assert r_no_link.status_code == 200
        assert "/admin/ws-orgs/" not in r_no_link.get_data(as_text=True)
    finally:
        deck.close()
        eng.dispose()
        eng2.dispose()


def test_aggregates_all_dotted_filters_in_not_in_and_fts(tmp_path: Path) -> None:
    app, deck, eng, eng2, _sf, _today = _build_ws_env(tmp_path, aggregate_scope="all")
    try:
        client = app.test_client()
        login_as(client, "admin", "pass")

        # 1. aggregate_scope='all' sums ALL 4 active records (1000+2000+3000+4000 = $100.00) despite page_size=2!
        r_all = client.get("/admin/ws-tasks/")
        assert r_all.status_code == 200
        all_html = r_all.get_data(as_text=True)
        assert "All Filtered Summary" in all_html
        assert "$100.00" in all_html

        # 2. Dotted FK filter (single + multi dotted filters deduplicating outerjoin on org)
        r_dot = client.get("/admin/ws-tasks/?f_org.tier=enterprise&f_org.region=eu-west")
        assert r_dot.status_code == 200
        dot_html = r_dot.get_data(as_text=True)
        assert "Root Launch" in dot_html
        assert "Sibling Audit" not in dot_html
        # Filtered aggregate updates over entire filtered subset (1000+2000+4000 = $70.00)
        assert "$70.00" in dot_html

        # 3. __in and __not_in (note __not_in includes NULL priority row!)
        r_in = client.get("/admin/ws-tasks/?f_priority__in=1,3")
        assert r_in.status_code == 200
        in_html = r_in.get_data(as_text=True)
        assert "Root Launch" in in_html
        assert "Sibling Audit" in in_html
        assert "Child Review" not in in_html

        r_nin = client.get("/admin/ws-tasks/?f_priority__not_in=1,2")
        assert r_nin.status_code == 200
        nin_html = r_nin.get_data(as_text=True)
        assert "Sibling Audit" in nin_html
        assert "Null Prio Item" in nin_html
        assert "Root Launch" not in nin_html

        # 4. __fts on SQLite fallback
        r_fts = client.get("/admin/ws-tasks/?f_notes__fts=urgent+compliance")
        assert r_fts.status_code == 200
        fts_html = r_fts.get_data(as_text=True)
        assert "Sibling Audit" in fts_html
        assert "Root Launch" not in fts_html

        # Also verify PostgreSQL dialect compilation for __fts uses to_tsvector + plainto_tsquery
        task_view = deck.get_view("ws-tasks")
        pg_cond = build_filter_condition(
            task_view.meta, "notes", "urgent compliance", op="fts", dialect_name="postgresql"
        )
        assert pg_cond is not None
        compiled = str(pg_cond.compile(dialect=postgresql.dialect()))
        assert "to_tsvector" in compiled
        assert "plainto_tsquery" in compiled

        # 5. RBAC safety on dotted FK filters: sensitive, masked, and hidden target fields MUST be blocked
        r_sens = client.get("/admin/ws-tasks/?f_org.api_token=tok_secret&page_size=10")
        assert r_sens.status_code == 200
        assert "Sibling Audit" in r_sens.get_data(as_text=True)  # filter ignored, unfiltered rows shown

        client_a = app.test_client()
        login_as(client_a, "analyst", "pass")
        # analyst has internal_note masked and region hidden on WsOrg
        r_masked_f = client_a.get("/admin/ws-tasks/?f_org.internal_note=vip+note&page_size=10")
        assert r_masked_f.status_code == 200
        assert "Sibling Audit" in r_masked_f.get_data(as_text=True)
        r_hidden_f = client_a.get("/admin/ws-tasks/?f_org.region=eu-west&page_size=10")
        assert r_hidden_f.status_code == 200
        assert "Sibling Audit" in r_hidden_f.get_data(as_text=True)
    finally:
        deck.close()
        eng.dispose()
        eng2.dispose()


def test_sql_workbench_bi_multi_bind_explain_charts_save_pin_and_dashboard(tmp_path: Path) -> None:
    app, deck, eng, eng2, _sf, _today = _build_ws_env(tmp_path)
    try:
        # Unit check schema introspection & SVG chart builder
        schema_b2 = introspect_engine_schema(eng2)
        assert schema_b2 == [{"name": "daily_metrics", "columns": [{"name": "day", "type": "TEXT"}, {"name": "orders", "type": "INTEGER"}, {"name": "revenue", "type": "INTEGER"}]}]

        sample_res = SQLQueryResult(
            sql="SELECT tier, COUNT(*) AS cnt FROM ws_orgs GROUP BY tier",
            columns=("tier", "cnt"),
            rows=(("starter", 4), ("enterprise", 9)),
            row_count=2,
            truncated=False,
            redacted_columns=(),
            duration_ms=1.2,
        )
        bar_svg = build_sql_chart_svg(sample_res, chart_type="bar")
        line_svg = build_sql_chart_svg(sample_res, chart_type="line")
        assert bar_svg is not None and "<svg" in str(bar_svg)
        assert line_svg is not None and "<svg" in str(line_svg)

        # InMemorySavedQueryStore round-trip check
        mem_sq = InMemorySavedQueryStore()
        created_sq = mem_sq.create(
            SavedQueryRecord(
                id="", name="M1", sql="SELECT 1", owner_id="u1", owner_name="U1"
            )
        )
        assert mem_sq.toggle_pin(created_sq.id) is not None
        assert mem_sq.delete(created_sq.id, actor_id="other", is_superuser=False) is False
        assert mem_sq.delete(created_sq.id, actor_id="u1", is_superuser=False) is True

        client = app.test_client()
        login_as(client, "analyst", "pass")

        # 1. Multi-bind SQL Console: schema browser switches to analytics bind
        r_b2 = client.get("/admin/_sql?bind_key=analytics")
        assert r_b2.status_code == 200
        _assert_strict_csp(r_b2)
        b2_html = r_b2.get_data(as_text=True)
        assert "daily_metrics" in b2_html
        csrf = extract_csrf(b2_html)

        # 2. Execute query on analytics bind -> Bar SVG chart renders cleanly
        r_run = client.post(
            "/admin/_sql",
            data={
                CSRF_FORM_FIELD: csrf,
                "bind_key": "analytics",
                "chart_type": "bar",
                "output": "table",
                "sql": "SELECT day, orders, revenue FROM daily_metrics ORDER BY day",
            },
        )
        assert r_run.status_code == 200
        _assert_strict_csp(r_run)
        run_html = r_run.get_data(as_text=True)
        assert "<svg" in run_html
        assert "690" in run_html

        # 3. EXPLAIN mode & SQLite read-only enforcement
        r_exp = client.post(
            "/admin/_sql",
            data={
                CSRF_FORM_FIELD: csrf,
                "bind_key": "",
                "output": "explain",
                "sql": "SELECT title FROM ws_tasks WHERE priority = 1",
            },
        )
        assert r_exp.status_code == 200
        assert "SCAN" in r_exp.get_data(as_text=True) or "SEARCH" in r_exp.get_data(as_text=True)

        # 4. Save & pin BI query to Dashboard
        r_save = client.post(
            "/admin/_sql/save",
            data={
                CSRF_FORM_FIELD: csrf,
                "name": "Daily Analytics Orders",
                "sql": "SELECT day, orders FROM daily_metrics ORDER BY day",
                "bind_key": "analytics",
                "chart_type": "line",
                "pin": "1",
            },
            follow_redirects=True,
        )
        assert r_save.status_code == 200
        save_html = r_save.get_data(as_text=True)
        assert "Daily Analytics Orders" in save_html
        assert "PINNED" in save_html

        # 5. Dashboard renders range_days=30 trend + pinned SQL BI widget cleanly!
        r_dash = client.get("/admin/?range=30d")
        assert r_dash.status_code == 200
        _assert_strict_csp(r_dash)
        dash_html = r_dash.get_data(as_text=True)
        assert "30-Day Record Activity" in dash_html
        assert "Daily Analytics Orders" in dash_html

        # 6. Admin can unpin & delete saved query
        assert deck.saved_query_store is not None
        sq_list = deck.saved_query_store.list_queries()
        assert len(sq_list) == 1
        qid = sq_list[0].id
        client_adm = app.test_client()
        csrf_adm = login_as(client_adm, "admin", "pass")
        r_unpin = client_adm.post(
            f"/admin/_sql/{qid}/pin",
            data={CSRF_FORM_FIELD: csrf_adm},
            follow_redirects=True,
        )
        assert r_unpin.status_code == 200
        r_del = client_adm.post(
            f"/admin/_sql/{qid}/delete",
            data={CSRF_FORM_FIELD: csrf_adm},
            follow_redirects=True,
        )
        assert r_del.status_code == 200
        assert deck.saved_query_store.list_queries() == []
    finally:
        deck.close()
        eng.dispose()
        eng2.dispose()
