"""Behavioral & security tests for cascade delete impact, streaming exporter, CSP/CSRF/rate-limit primitives, rich form context, and approval execution."""

from __future__ import annotations

import enum
import json
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, ClassVar

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    Deck,
    DeckUser,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemoryRecordNoteStore,
    InMemorySavedViewStore,
    InMemorySessionStore,
    ModelView,
    OpenAuthProvider,
    QuickTab,
    RBACAuthProvider,
    Role,
    VirtualField,
    action,
    display,
)
from flask_deck.approvals import make_approval_request
from flask_deck.cascade import analyze_delete_impact
from flask_deck.exporter import _serialize_export_value, iter_export_chunks
from flask_deck.introspection import introspect_model
from flask_deck.query import (
    apply_base_stmt_extras,
    build_search_clause,
    execute_list_query,
)
from flask_deck.saved_views import SavedViewRecord
from flask_deck.security import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    LoginRateLimiter,
    RedisRateLimitStore,
    SQLAlchemyRateLimitStore,
    apply_security_headers,
    build_csp_header,
    is_safe_display_url,
    is_valid_csp_img_source,
    redact_mapping,
    validate_csrf,
)
from flask_deck.widgets import FormWidget
from tests._backends import sqlite_memory_engine


class CasState(enum.Enum):
    OPEN = "open"
    DONE = "done"


class CasBase(DeclarativeBase):
    pass


cas_item_tags = sa.Table(
    "cas_item_tags",
    CasBase.metadata,
    sa.Column("item_id", sa.Integer, sa.ForeignKey("cas_items.id", ondelete="CASCADE"), primary_key=True),
    sa.Column("tag_id", sa.Integer, sa.ForeignKey("cas_tags.id", ondelete="CASCADE"), primary_key=True),
)


class CasCountry(CasBase):
    __tablename__ = "cas_countries"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(8), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)


class CasCity(CasBase):
    __tablename__ = "cas_cities"
    id: Mapped[int] = mapped_column(primary_key=True)
    country_code: Mapped[str] = mapped_column(
        sa.String(8), sa.ForeignKey("cas_countries.code", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)


class CasTag(CasBase):
    __tablename__ = "cas_tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    def __str__(self) -> str:
        return self.name


class CasParent(CasBase):
    __tablename__ = "cas_parents"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    secret_code: Mapped[str | None] = mapped_column(sa.String(60), nullable=True)
    items: Mapped[list[CasItem]] = relationship(back_populates="parent", cascade="all, delete-orphan")
    nullable_refs: Mapped[list[CasNullableRef]] = relationship(back_populates="parent")
    blocked_refs: Mapped[list[CasBlockedRef]] = relationship(back_populates="parent")


class CasItem(CasBase):
    __tablename__ = "cas_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("cas_parents.id", ondelete="CASCADE"), nullable=True
    )
    title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    state: Mapped[CasState] = mapped_column(sa.Enum(CasState), default=CasState.OPEN, nullable=False)
    due_on: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    meta_json: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    restricted: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    parent: Mapped[CasParent | None] = relationship(back_populates="items")
    tags: Mapped[list[CasTag]] = relationship(secondary=cas_item_tags)
    leaves: Mapped[list[CasLeaf]] = relationship(back_populates="item", cascade="all, delete-orphan")


class CasLeaf(CasBase):
    __tablename__ = "cas_leaves"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("cas_items.id", ondelete="CASCADE"), nullable=False)
    note: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    item: Mapped[CasItem] = relationship(back_populates="leaves")


class CasNullableRef(CasBase):
    __tablename__ = "cas_nullable_refs"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("cas_parents.id", ondelete="SET NULL"), nullable=True
    )
    label: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    parent: Mapped[CasParent | None] = relationship(back_populates="nullable_refs")


class CasBlockedRef(CasBase):
    __tablename__ = "cas_blocked_refs"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int] = mapped_column(
        sa.ForeignKey("cas_parents.id", ondelete="RESTRICT"), nullable=False
    )
    label: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    parent: Mapped[CasParent] = relationship(back_populates="blocked_refs")


class CasSelfNode(CasBase):
    __tablename__ = "cas_self_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("cas_self_nodes.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(sa.String(40), nullable=False)


class CasComposite(CasBase):
    __tablename__ = "cas_composites"
    k1: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    k2: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(40), nullable=False)


class _SimpleFakeRedis:
    """Minimal key-value client WITHOUT `.eval` to exercise RedisRateLimitStore fallback."""

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        _ = ex
        self.data[key] = value.encode("utf-8")

    def delete(self, *keys: str) -> int:
        deleted = 0
        for k in keys:
            if k in self.data:
                del self.data[k]
                deleted += 1
        return deleted


def _extract_csrf(client: Any, url: str = "/admin/login") -> str:
    resp = client.get(url, follow_redirects=True)
    html = resp.get_data(as_text=True)
    marker = f'name="{CSRF_FORM_FIELD}" value="'
    idx = html.find(marker)
    if idx != -1:
        start = idx + len(marker)
        return html[start : html.find('"', start)]
    meta = 'name="csrf-token" content="'
    idx = html.find(meta)
    assert idx != -1
    start = idx + len(meta)
    return html[start : html.find('"', start)]


def _login(client: Any, username: str, password: str) -> str:
    csrf = _extract_csrf(client, "/admin/login")
    r = client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert r.status_code == 302
    return _extract_csrf(client, "/admin/")


def test_security_csp_csrf_redaction_and_rate_limit_fallback_primitives() -> None:
    # 1. CSP img-src token validation & security header caching modes
    assert is_valid_csp_img_source("https://cdn.example.com/img/") is True
    assert is_valid_csp_img_source("blob:") is True
    assert is_valid_csp_img_source("https://*.evil.test") is False
    assert is_valid_csp_img_source("javascript:alert(1)") is False
    assert is_valid_csp_img_source("https://a.test; script-src *") is False
    assert is_valid_csp_img_source("bad\nline") is False
    csp = build_csp_header("valid-nonce-1234", extra_img_sources=("https://cdn.example.com", "javascript:bad"))
    assert "https://cdn.example.com" in csp and "javascript:" not in csp

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "sec-prims-secret-32-bytes-long!!"
    with app.test_request_context("/admin/test", method="POST"):
        from flask import Response, session

        resp_static = apply_security_headers(Response("ok"), nonce="abcdefgh1234", is_static=True, has_version_hash=False)
        assert "max-age=3600" in resp_static.headers["Cache-Control"]
        resp_imm = apply_security_headers(Response("ok"), nonce="abcdefgh1234", is_static=True, has_version_hash=True)
        assert "immutable" in resp_imm.headers["Cache-Control"]

        # JSON body CSRF token + Origin: null handling
        session["_deck_csrf_token"] = "a" * 40
    with app.test_request_context(
        "/admin/test",
        method="POST",
        json={CSRF_FORM_FIELD: "a" * 40},
        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
    ):
        from flask import request, session

        session["_deck_csrf_token"] = "a" * 40
        assert validate_csrf(request) is True
    with app.test_request_context(
        "/admin/test",
        method="POST",
        headers={"Origin": "http://[::1:badport"},
    ):
        from flask import request, session

        session["_deck_csrf_token"] = "a" * 40
        assert validate_csrf(request) is False

    # URL safety & redaction helpers (including malformed IPv6 URLs)
    assert is_safe_display_url(None) is False
    assert is_safe_display_url("   ") is False
    assert is_safe_display_url("https://ok.test\x00") is False
    assert is_safe_display_url("http://[::1") is False
    assert is_valid_csp_img_source("http://[::1") is False
    redacted = redact_mapping({"username": "ada", "api_token": "secret", "custom": "val"}, sensitive_fields=("custom",))
    assert redacted == {"username": "ada", "api_token": "[REDACTED]", "custom": "[REDACTED]"}

    # LoginRateLimiter eviction & expiry + SQLAlchemyRateLimitStore corrupt JSON + Redis fallback without .eval
    rl = LoginRateLimiter(max_attempts=1, window_seconds=60, lockout_seconds=60, max_keys=2)
    rl.record_failure("1.1.1.1", "u1")
    rl.record_failure("2.2.2.2", "u2")
    rl.record_failure("3.3.3.3", "u3")
    # Force an expired lockout entry to verify cleanup branch
    rl._lockouts["pair:9.9.9.9:old"] = time.monotonic() - 10
    assert rl.is_locked("9.9.9.9", "old") == (False, 0)
    assert rl.is_locked("3.3.3.3", "")[0] is False

    with sqlite_memory_engine() as eng:
        sql_rl = SQLAlchemyRateLimitStore(eng, max_attempts=2, window_seconds=60, lockout_seconds=60)
        with eng.begin() as conn:
            conn.execute(
                sql_rl._table.insert().values(
                    bucket_key="pair:10.0.0.1:corrupt",
                    attempts_json="{not-valid-json",
                    locked_until=None,
                )
            )
        sql_rl.record_failure("10.0.0.1", "corrupt")
        assert sql_rl.is_locked("10.0.0.1", "corrupt")[0] is False

    fake_r = _SimpleFakeRedis()
    fake_r.set("rl:pair:10.0.0.2:bad", "{not-json")
    rrl = RedisRateLimitStore(fake_r, max_attempts=2, window_seconds=60, lockout_seconds=60, key_prefix="rl:")
    assert rrl.is_locked("10.0.0.2", "bad") == (False, 0)
    rrl.record_failure("10.0.0.2", "bad")
    rrl.record_failure("10.0.0.2", "bad")
    assert rrl.is_locked("10.0.0.2", "bad")[0] is True
    rrl.record_success("10.0.0.2", "bad")
    assert rrl.is_locked("10.0.0.2", "bad")[0] is False


def test_cascade_impact_exporter_and_multihop_search_cursor_fallback() -> None:
    class ParentView(ModelView):
        model = CasParent
        slug = "parents"

    class ItemView(ModelView):
        model = CasItem
        slug = "items"
        searchable_columns = ("title", "parent.name", "parent.secret_code")
        filterable_columns = ("state", "parent.name")
        quick_tabs = (QuickTab("all", "All"), QuickTab("open", "Open", {"state": "open"}))

        def get_search_results(
            self, stmt: sa.Select[Any], search_term: str, user: Any
        ) -> tuple[sa.Select[Any], bool]:
            _ = user
            return stmt.where(CasItem.title.ilike(f"%{search_term}%")), True

    class CompositeView(ModelView):
        model = CasComposite
        slug = "composites"

    class CountryView(ModelView):
        model = CasCountry
        slug = "countries"

    class SelfNodeView(ModelView):
        model = CasSelfNode
        slug = "nodes"

    with sqlite_memory_engine() as eng:
        CasBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            p1 = CasParent(name="Parent One", secret_code="topsecret")
            s.add(p1)
            s.flush()
            it1 = CasItem(parent_id=p1.id, title="=CMD() Alpha", state=CasState.OPEN, meta_json={"k": 1})
            it2 = CasItem(parent_id=p1.id, title="Beta Item", state=CasState.DONE)
            s.add_all([it1, it2])
            s.flush()
            s.add(CasLeaf(item_id=it1.id, note="Grandchild leaf"))
            s.add(CasNullableRef(parent_id=p1.id, label="Nullable ref"))
            s.add(CasBlockedRef(parent_id=p1.id, label="Blocked ref"))
            s.add(CasCountry(code="TR", name="Turkiye"))
            s.flush()
            s.add(CasCity(country_code="TR", name="Istanbul"))
            n1 = CasSelfNode(id=1, parent_id=None, name="Root")
            n2 = CasSelfNode(id=2, parent_id=1, name="Child")
            n3 = CasSelfNode(id=3, parent_id=2, name="Grandchild")
            s.add_all([n1, n2, n3])
            s.add_all([CasComposite(k1="a", k2="1", label="C1"), CasComposite(k1="a", k2="2", label="C2")])
            s.commit()
            p1_id = p1.id

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "cascade-exp-secret-32-bytes-long!"
        app.config["TESTING"] = True
        deck = Deck(app, session_factory=SessionLocal, engine=eng, auth=OpenAuthProvider(), audit_store=False)
        deck.register(ParentView, ItemView, CompositeView, CountryView, SelfNodeView)

        try:
            with app.test_request_context("/admin/"), SessionLocal() as s:
                # 1. Cascade delete impact: zero target, multi-level cascade + set_null + blocked, non-PK unique FK, self-ref cascade
                empty_rep = analyze_delete_impact(
                    s, deck, deck.views["parents"], sa.select(CasParent.id).where(CasParent.id == -1), 0, user=None
                )
                assert empty_rep.can_proceed is True and empty_rep.total_affected == 0

                rep = analyze_delete_impact(
                    s, deck, deck.views["parents"], sa.select(CasParent.id).where(CasParent.id == p1_id), 1, user=None, force=True
                )
                rep_dict = rep.to_dict()
                actions = {it["table_name"]: it["action"] for it in rep_dict["items"]}
                assert actions["cas_items"] == "cascade"
                assert actions["cas_leaves"] == "cascade"  # depth 2 via cascade
                assert actions["cas_nullable_refs"] == "set_null"
                assert actions["cas_blocked_refs"] == "blocked"
                assert rep.can_proceed is False

                # Non-PK unique FK target (CasCity.country_code -> CasCountry.code)
                c_rep = analyze_delete_impact(
                    s, deck, deck.views["countries"], sa.select(CasCountry.id), 1, user=None, force=True
                )
                assert c_rep.can_proceed is False and c_rep.items[0].table_name == "cas_cities"

                # Self-referential cascade (Root -> Child -> Grandchild)
                s_rep = analyze_delete_impact(
                    s, deck, deck.views["nodes"], sa.select(CasSelfNode.id).where(CasSelfNode.id == 1), 1, user=None, force=True
                )
                assert sum(i.count for i in s_rep.items) >= 2

                # 2. Streaming exporter (JSONL, JSON, CSV with custom search + dedup + composite PK + dotted filter)
                assert _serialize_export_value(object()).startswith("<object")
                chunks_csv, _, _ = iter_export_chunks(
                    s,
                    deck.views["items"],
                    fmt="csv",
                    auth=OpenAuthProvider(),
                    user=None,
                    search_term="Alpha",
                    filter_params=[("parent.name", "Parent One")],
                    active_tab_key="open",
                    extra_where=[CasItem.id > 0],
                    custom_filter_appliers=[lambda q: q],
                    views_by_model=deck._views_by_model,
                )
                csv_out = "".join(chunks_csv)
                assert "'=CMD() Alpha" in csv_out

                chunks_jsonl, _, _ = iter_export_chunks(
                    s,
                    deck.views["composites"],
                    fmt="jsonl",
                    auth=OpenAuthProvider(),
                    user=None,
                    selected_pks=[("a", "1")],
                )
                jsonl_lines = [line for line in "".join(chunks_jsonl).splitlines() if line.strip()]
                assert len(jsonl_lines) == 1 and json.loads(jsonl_lines[0])["label"] == "C1"

                # Exporter auto-derived searchable_columns with unregistered target model & hidden fields
                class LeafNoCustomView(ModelView):
                    model = CasLeaf
                    slug = "leaves"
                    searchable_columns = ("note", "item.title")

                lv = LeafNoCustomView()
                chunks_j, _, _ = iter_export_chunks(
                    s, lv, fmt="json", auth=OpenAuthProvider(), user=None, search_term="Alpha"
                )
                assert "Grandchild leaf" in "".join(chunks_j)

                # 3. Query engine: 2-hop dotted search + apply_base_stmt_extras join/options + backward cursor deleted fallback
                leaf_meta = introspect_model(CasLeaf)
                s_clause, _s_joins = build_search_clause(
                    leaf_meta,
                    ("=item.parent.name", "^note", "@note", "item.state"),
                    '"Parent One"',
                    dialect_name="sqlite",
                )
                assert s_clause is not None
                matched_leaves = list(s.scalars(sa.select(CasLeaf).where(s_clause)).all())
                assert len(matched_leaves) == 1 and matched_leaves[0].note == "Grandchild leaf"

                joined_base = sa.select(CasItem).outerjoin(CasParent, CasItem.parent_id == CasParent.id)
                copied_stmt = apply_base_stmt_extras(sa.select(CasItem), joined_base, include_options=True)
                assert list(s.scalars(copied_stmt).all())

                # Backward cursor when preceding rows were deleted falls back cleanly to page 1
                item_meta = introspect_model(CasItem)
                sec = b"fallback-cursor-sec"
                p_first = execute_list_query(
                    s,
                    item_meta,
                    base_stmt=sa.select(CasItem),
                    displayed_columns=("id", "title"),
                    searchable_columns=("title",),
                    filterable_columns=frozenset(),
                    sortable_columns=frozenset({"id"}),
                    quick_tabs=(),
                    active_tab_key=None,
                    search_term="",
                    filter_params=(),
                    sort_by="id",
                    sort_dir="asc",
                    default_sort=None,
                    page=1,
                    page_size=1,
                    max_page_size=20,
                    pagination_mode="cursor",
                    cursor_secret=sec,
                )
                p_second = execute_list_query(
                    s,
                    item_meta,
                    base_stmt=sa.select(CasItem),
                    displayed_columns=("id", "title"),
                    searchable_columns=("title",),
                    filterable_columns=frozenset(),
                    sortable_columns=frozenset({"id"}),
                    quick_tabs=(),
                    active_tab_key=None,
                    search_term="",
                    filter_params=(),
                    sort_by="id",
                    sort_dir="asc",
                    default_sort=None,
                    page=1,
                    page_size=1,
                    max_page_size=20,
                    pagination_mode="cursor",
                    after_cursor=p_first.next_cursor,
                    cursor_secret=sec,
                )
                assert p_second.prev_cursor is not None
                # Delete the first row so `before_cursor` has 0 preceding rows -> clean fallback!
                s.delete(p_first.items[0])
                s.flush()
                p_fallback = execute_list_query(
                    s,
                    item_meta,
                    base_stmt=sa.select(CasItem),
                    displayed_columns=("id", "title"),
                    searchable_columns=("title",),
                    filterable_columns=frozenset(),
                    sortable_columns=frozenset({"id"}),
                    quick_tabs=(),
                    active_tab_key=None,
                    search_term="",
                    filter_params=(),
                    sort_by="id",
                    sort_dir="asc",
                    default_sort=None,
                    page=1,
                    page_size=1,
                    max_page_size=20,
                    pagination_mode="cursor",
                    before_cursor=p_second.prev_cursor,
                    cursor_secret=sec,
                )
                assert len(p_fallback.items) == 1 and p_fallback.has_prev is False
                s.rollback()
        finally:
            deck.close()


def test_rich_form_context_approval_delete_action_and_html_notes_saved_views() -> None:
    class DemoWidget(FormWidget):
        template = "text"

        def render(self, *, name: str, field_id: str, value: Any, **kw: Any) -> str:
            _ = kw
            return f'<input id="{field_id}" name="{name}" value="{value or ""}">'

    class TagView(ModelView):
        model = CasTag
        slug = "tags"
        soft_delete_column = "deleted_at"

    class RichItemView(ModelView):
        model = CasItem
        slug = "items"
        soft_delete_column = "deleted_at"
        m2m_mode = "async"
        readonly_fields = ("computed_badge",)
        extra_form_fields = (
            VirtualField(name="v_flag", field_type="boolean", default=True),
            VirtualField(name="v_date", field_type="date", default=date(2026, 1, 2)),
            VirtualField(name="v_dt", field_type="datetime", default=datetime(2026, 1, 2, 10, 0, tzinfo=timezone.utc)),
            VirtualField(name="v_json", field_type="json", default={"a": 1}, widget=DemoWidget()),
        )

        @display(label="Computed Badge", tone="ok")
        def computed_badge(self, obj: Any) -> str:
            return f"#{obj.id}:{obj.title}"

        def can_view_record(self, obj: Any, user: Any) -> bool:
            return not (obj.restricted and user is not None and not user.is_superuser)

        @action("mark_done", label="Mark Done")
        def mark_done(self, records: Any, form: Any, user: Any) -> str:
            _ = (form, user)
            for r in records:
                r.state = CasState.DONE
            return f"Marked {len(records)}"

    with sqlite_memory_engine() as eng:
        CasBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            t1 = CasTag(name="Urgent")
            it1 = CasItem(title="Active Item", due_on=date(2026, 3, 4), meta_json={"x": 1}, tags=[t1])
            it2 = CasItem(title="Delete Target")
            it_rest = CasItem(title="Restricted", restricted=True)
            it_trash = CasItem(title="Trashed", deleted_at=datetime.now(timezone.utc))
            s.add_all([t1, it1, it2, it_rest, it_trash])
            s.commit()
            t1_id, it1_id, it2_id, it_rest_id, it_trash_id = t1.id, it1.id, it2.id, it_rest.id, it_trash.id

        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role("reviewer", permissions=frozenset({"items:view", "approvals:view", "approvals:review"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
                    password="AdminPassword1!",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-rev", username="reviewer", roles=("reviewer",)),
                    password="ReviewerPassword1!",
                ),
            ],
        )

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "rich-forms-secret-32-bytes-long!"
        app.config["TESTING"] = True

        approvals = InMemoryApprovalStore()
        saved_views = InMemorySavedViewStore()
        notes = InMemoryRecordNoteStore()

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            approval_store=approvals,
            saved_view_store=saved_views,
            note_store=notes,
            session_store=InMemorySessionStore(),
        )
        deck.register(TagView, RichItemView)

        try:
            c = app.test_client()
            csrf = _login(c, "admin", "AdminPassword1!")
            rc = app.test_client()
            csrf_r = _login(rc, "reviewer", "ReviewerPassword1!")

            # 1. Rich form rendering on create (VirtualFields + @display obj=None) & edit (submitted async M2M hydration + @display obj!=None)
            assert c.get("/admin/items/new").status_code == 200
            assert c.get(f"/admin/items/{it1_id}/edit").status_code == 200
            # POST edit with validation failure (empty title) + submitted async M2M tag + virtual fields re-renders form context!
            r_err_edit = c.post(
                f"/admin/items/{it1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "title": "",
                    "tags": [str(t1_id)],
                    "v_flag": "1",
                    "v_date": "2026-02-03",
                },
            )
            assert r_err_edit.status_code == 200

            # 2. Approval execution: soft delete, action execution, and unknown action error rollback
            req_sdel = approvals.create(
                make_approval_request(
                    model_slug="items",
                    model_label="Item",
                    operation="delete",
                    record_pk=str(it2_id),
                    record_repr="Delete Target",
                    payload={"force": False},
                    diff={},
                    reason="Soft delete via approval",
                    requester_id="u-adm",
                    requester_name="admin",
                )
            )
            req_act = approvals.create(
                make_approval_request(
                    model_slug="items",
                    model_label="Item",
                    operation="action",
                    record_pk=str(it1_id),
                    record_repr="Mark Done (1)",
                    payload={"action_name": "mark_done", "pks": [str(it1_id)], "params": {"reason": "ok"}},
                    diff={},
                    reason="Run action via approval",
                    requester_id="u-adm",
                    requester_name="admin",
                )
            )
            req_bad_act = approvals.create(
                make_approval_request(
                    model_slug="items",
                    model_label="Item",
                    operation="action",
                    record_pk=str(it1_id),
                    record_repr="Missing Action",
                    payload={"action_name": "no_such_action", "pks": [str(it1_id)]},
                    diff={},
                    reason="Should fail cleanly",
                    requester_id="u-adm",
                    requester_name="admin",
                )
            )
            assert rc.post(f"/admin/_approvals/{req_sdel.id}/approve", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert rc.post(f"/admin/_approvals/{req_act.id}/approve", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert rc.post(f"/admin/_approvals/{req_bad_act.id}/approve", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            with SessionLocal() as s:
                assert s.get(CasItem, it2_id).deleted_at is not None  # type: ignore[union-attr]
                assert s.get(CasItem, it1_id).state == CasState.DONE  # type: ignore[union-attr]

            # 3. HTML (non-JSON) Record Notes & Saved Views form endpoints + ACL guards
            # Empty note flashes & redirects; valid note redirects; reviewer without edit/notes:write -> 403; restricted -> 403; trashed -> 404
            assert c.post(f"/admin/_api/items/{it1_id}/notes", data={"body": "", CSRF_FORM_FIELD: csrf}).status_code == 302
            assert c.post(f"/admin/_api/items/{it1_id}/notes", data={"body": "HTML Note", CSRF_FORM_FIELD: csrf}).status_code == 302
            assert rc.post(f"/admin/_api/items/{it1_id}/notes", data={"body": "No Perm", CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert rc.post(f"/admin/_api/items/{it_rest_id}/notes", data={"body": "Restr", CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert c.post(f"/admin/_api/items/{it_trash_id}/notes", data={"body": "Trashed", CSRF_FORM_FIELD: csrf}).status_code == 404

            n_id = notes.list_notes("items", str(it1_id))[0].id
            assert c.post(f"/admin/_api/items/{it1_id}/notes/{n_id}/pin", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert c.post(f"/admin/_api/items/{it1_id}/notes/missing/pin", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert rc.post(f"/admin/_api/items/{it1_id}/notes/{n_id}/pin", data={CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert c.post(f"/admin/_api/items/{it_trash_id}/notes/{n_id}/pin", data={CSRF_FORM_FIELD: csrf}).status_code == 404

            assert rc.post(f"/admin/_api/items/{it1_id}/notes/{n_id}/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert c.post(f"/admin/_api/items/{it1_id}/notes/missing/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert c.post(f"/admin/_api/items/{it_trash_id}/notes/{n_id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert c.post(f"/admin/_api/items/{it1_id}/notes/{n_id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302

            sv = saved_views.create(
                SavedViewRecord(
                    id="",
                    model_slug="items",
                    name="Admin View",
                    query_string="q=test",
                    scope="personal",
                    owner_id="u-adm",
                    owner_name="admin",
                )
            )
            assert rc.post(f"/admin/_api/items/saved-views/{sv.id}/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert c.post("/admin/_api/items/saved-views/missing/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert c.post(f"/admin/_api/items/saved-views/{sv.id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
        finally:
            deck.close()


def test_cascade_exporter_dashboard_crud_fk_and_inline_template_regressions() -> None:
    from flask_deck import InlineModelView
    from flask_deck.dashboard import build_default_dashboard

    # 1. Cascade regressions: mutual FK cycle RESTRICT, joined-table inheritance, ON DELETE SET DEFAULT
    class _CasRegBase(DeclarativeBase):
        pass

    class _CycleA(_CasRegBase):
        __tablename__ = "reg_cycle_a"
        id: Mapped[int] = mapped_column(primary_key=True)
        b_id: Mapped[int | None] = mapped_column(sa.ForeignKey("reg_cycle_b.id", ondelete="RESTRICT"), nullable=True)

    class _CycleB(_CasRegBase):
        __tablename__ = "reg_cycle_b"
        id: Mapped[int] = mapped_column(primary_key=True)
        a_id: Mapped[int | None] = mapped_column(sa.ForeignKey("reg_cycle_a.id", ondelete="CASCADE"), nullable=True)

    class _BasePerson(_CasRegBase):
        __tablename__ = "reg_base_people"
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str] = mapped_column(sa.String(20), nullable=False)
        __mapper_args__: ClassVar[dict[str, Any]] = {"polymorphic_identity": "base", "polymorphic_on": "kind"}

    class _Employee(_BasePerson):
        __tablename__ = "reg_employees"
        id: Mapped[int] = mapped_column(sa.ForeignKey("reg_base_people.id"), primary_key=True)
        title: Mapped[str] = mapped_column(sa.String(40), nullable=False)
        __mapper_args__: ClassVar[dict[str, Any]] = {"polymorphic_identity": "emp"}

    class _PersonBadge(_CasRegBase):
        __tablename__ = "reg_person_badges"
        id: Mapped[int] = mapped_column(primary_key=True)
        person_id: Mapped[int] = mapped_column(sa.ForeignKey("reg_base_people.id", ondelete="RESTRICT"), nullable=False)

    class _DefaultParent(_CasRegBase):
        __tablename__ = "reg_def_parents"
        id: Mapped[int] = mapped_column(primary_key=True)

    class _DefaultChild(_CasRegBase):
        __tablename__ = "reg_def_children"
        id: Mapped[int] = mapped_column(primary_key=True)
        parent_id: Mapped[int] = mapped_column(
            sa.ForeignKey("reg_def_parents.id", ondelete="SET DEFAULT"), nullable=False, server_default="1"
        )

    with sqlite_memory_engine() as eng_cas:
        _CasRegBase.metadata.create_all(eng_cas)
        SL = sessionmaker(bind=eng_cas, autoflush=False, expire_on_commit=False)
        with SL() as s:
            a1 = _CycleA(id=1)
            b1 = _CycleB(id=1, a_id=1)
            s.add_all([a1, b1])
            s.flush()
            a1.b_id = 1
            s.add(_CycleA(id=2, b_id=1))  # second _CycleA row referencing _CycleB(1) via RESTRICT
            emp = _Employee(id=10, title="Staff")
            s.add(emp)
            s.flush()
            s.add(_PersonBadge(id=100, person_id=10))
            s.add(_DefaultParent(id=2))
            s.add(_DefaultChild(id=20, parent_id=2))
            s.commit()

        app_cas = Flask(__name__)
        app_cas.config["SECRET_KEY"] = "cas-reg-secret-32-bytes-long!!!!"
        deck_cas = Deck(app_cas, session_factory=SL, engine=eng_cas, allow_insecure_open=True, audit_store=False)
        deck_cas.register(_CycleA, _CycleB, _Employee, _PersonBadge, _DefaultParent, _DefaultChild)
        try:
            with SL() as s:
                # Cycle: deleting A cascades to B, which is referenced by A via RESTRICT
                imp_cyc = analyze_delete_impact(
                    s,
                    deck_cas,
                    deck_cas.get_view(introspect_model(_CycleA).slug),
                    sa.select(_CycleA.id).where(_CycleA.id == 1),
                    1,
                    user=None,
                )
                assert imp_cyc.can_proceed is False
                # Joined-table inheritance: deleting _Employee detects _PersonBadge referencing base table
                imp_inh = analyze_delete_impact(
                    s,
                    deck_cas,
                    deck_cas.get_view(introspect_model(_Employee).slug),
                    sa.select(_Employee.id).where(_Employee.id == 10),
                    1,
                    user=None,
                )
                assert imp_inh.can_proceed is False
                # ON DELETE SET DEFAULT on non-nullable FK is classified as 'set_null' (not 'blocked')
                imp_def = analyze_delete_impact(
                    s,
                    deck_cas,
                    deck_cas.get_view(introspect_model(_DefaultParent).slug),
                    sa.select(_DefaultParent.id).where(_DefaultParent.id == 2),
                    1,
                    user=None,
                )
                assert imp_def.can_proceed is True
                assert any(n.action == "set_null" for n in imp_def.items)
        finally:
            deck_cas.close()

    # 2. Exporter regressions: can_view_record filtering, negative Decimal preserved, CSV header sanitized
    class _ExpBase(DeclarativeBase):
        pass

    class _ExpRow(_ExpBase):
        __tablename__ = "reg_exp_rows"
        id: Mapped[int] = mapped_column(primary_key=True)
        label: Mapped[str] = mapped_column(sa.String(60), nullable=False)
        balance: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), nullable=False)
        hidden_row: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    class _ExpView(ModelView):
        model = _ExpRow
        slug = "exp-rows"
        columns = ("label", "balance")
        export_columns = ("=formula_col", "label", "balance")

        def can_view_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.hidden_row

    with sqlite_memory_engine() as eng_exp:
        _ExpBase.metadata.create_all(eng_exp)
        SL_exp = sessionmaker(bind=eng_exp, autoflush=False, expire_on_commit=False)
        with SL_exp() as s:
            s.add_all(
                [
                    _ExpRow(label="=SUM(A1)", balance=Decimal("-12.50"), hidden_row=False),
                    _ExpRow(label="SecretRow", balance=Decimal("99.00"), hidden_row=True),
                ]
            )
            s.commit()

        view_exp = _ExpView()
        view_exp.resolved_export_columns = ("=formula_col", "label", "balance")
        with SL_exp() as s:
            chunks, _ct, _ext = iter_export_chunks(
                s,
                view_exp,
                fmt="csv",
                auth=OpenAuthProvider(),
                user=None,
            )
            csv_body = "".join(chunks)
        assert "'=formula_col" in csv_body
        assert "'=SUM(A1)" in csv_body
        assert "-12.50" in csv_body and "'-12.50" not in csv_body
        assert "SecretRow" not in csv_body

    # 3. Dashboard scope_query join preservation + CRUD/Quick-Edit/FK/Inline template regressions
    class _UiBase(DeclarativeBase):
        pass

    class _UiRegion(_UiBase):
        __tablename__ = "ui_regions"
        code: Mapped[str] = mapped_column(sa.String(32), primary_key=True)  # PK with '/'
        iso_key: Mapped[str] = mapped_column(sa.String(16), unique=True, nullable=False)  # non-PK unique FK target
        name: Mapped[str] = mapped_column(sa.String(60), nullable=False)
        active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
        hubs: Mapped[list[_UiHub]] = relationship(back_populates="region")
        notes: Mapped[list[_UiRegionNote]] = relationship(back_populates="region")

        def __str__(self) -> str:
            return self.name

    class _UiHub(_UiBase):
        __tablename__ = "ui_hubs"
        id: Mapped[int] = mapped_column(primary_key=True)
        region_iso: Mapped[str] = mapped_column(sa.ForeignKey("ui_regions.iso_key"), nullable=False)
        name: Mapped[str] = mapped_column(sa.String(60), nullable=False)
        version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
        locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
        deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
        created_at: Mapped[datetime] = mapped_column(
            sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
        )
        region: Mapped[_UiRegion] = relationship(back_populates="hubs")

    class _UiRegionNote(_UiBase):
        __tablename__ = "ui_region_notes"
        id: Mapped[int] = mapped_column(primary_key=True)
        region_code: Mapped[str] = mapped_column(sa.ForeignKey("ui_regions.code"), nullable=False)
        body: Mapped[str] = mapped_column(sa.String(80), nullable=False)
        region: Mapped[_UiRegion] = relationship(back_populates="notes")

    class _CustomInlineWidget(FormWidget):
        def render(self, *, name: str, field_id: str, value: Any, **kw: Any) -> Any:
            from markupsafe import Markup

            _ = kw
            return Markup(f'<input data-custom-inline-widget="1" id="{field_id}" name="{name}" value="{value or ""}">')

    class _RegionNoteInline(InlineModelView):
        model = _UiRegionNote
        fk_column = "region_code"
        columns = ("body",)
        field_widgets: ClassVar[dict[str, str | FormWidget]] = {"body": _CustomInlineWidget()}

    class _UiRegionView(ModelView):
        model = _UiRegion
        slug = "regions"
        form_layout = "wizard"
        save_on_top = True
        fieldsets = (("Step 1", ("code", "iso_key", "name")), ("Step 2", ("active",)))
        inlines = (_RegionNoteInline,)

    hook_calls: list[str] = []

    class _UiHubView(ModelView):
        model = _UiHub
        slug = "hubs"
        plural_name = "Active Hubs"
        soft_delete_column = "deleted_at"
        version_column = "version"
        inline_editable_fields = ("name",)
        inline_edit_mode = "batch"
        save_as = True

        def scope_query(self, stmt: Any, user: Any) -> Any:
            _ = user
            return stmt.join(_UiRegion, _UiHub.region_iso == _UiRegion.iso_key).where(_UiRegion.active.is_(True))

        def can_edit_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.locked

    class _GovHubView(ModelView):
        model = _UiHub
        slug = "gov-hubs"
        plural_name = "Governed Hubs"
        save_as = True
        approval_required = ("create",)

        def on_model_change(self, obj: Any, *, is_created: bool, user: Any) -> None:
            _ = (obj, user)
            hook_calls.append(f"change:{is_created}")

    with sqlite_memory_engine() as eng_ui:
        _UiBase.metadata.create_all(eng_ui)
        SL_ui = sessionmaker(bind=eng_ui, autoflush=False, expire_on_commit=False)
        with SL_ui() as s:
            r_act = _UiRegion(code="us/east", iso_key="ISO-USE", name="US East", active=True)
            r_inact = _UiRegion(code="eu/west", iso_key="ISO-EUW", name="EU West", active=False)
            h_live = _UiHub(region_iso="ISO-USE", name="Hub 1")
            h_trash_locked = _UiHub(
                region_iso="ISO-USE", name="Locked Trash", locked=True, deleted_at=datetime.now(timezone.utc)
            )
            h_hidden = _UiHub(region_iso="ISO-EUW", name="Inactive Hub")
            s.add_all([r_act, r_inact, h_live, h_trash_locked, h_hidden])
            s.commit()
            h_live_id, h_trash_id = h_live.id, h_trash_locked.id

        app_ui = Flask(__name__)
        app_ui.config["SECRET_KEY"] = "ui-reg-secret-32-bytes-long!!!!!"
        app_ui.config["TESTING"] = True
        deck_ui = Deck(
            app_ui,
            session_factory=SL_ui,
            engine=eng_ui,
            allow_insecure_open=True,
            approval_store=InMemoryApprovalStore(),
            audit_store=False,
        )
        deck_ui.register(_UiRegionView, _UiHubView, _GovHubView)
        try:
            c = app_ui.test_client()
            csrf = _extract_csrf(c, "/admin/")

            # Dashboard preserves scope_query join + WHERE + soft-delete across count AND sparkline
            with app_ui.test_request_context("/admin/"):
                from flask_deck.dashboard import DashboardContext

                widgets = build_default_dashboard(
                    deck_ui,
                    DashboardContext(
                        deck=deck_ui,
                        session=deck_ui.get_session(),
                        user=deck_ui.auth.get_current_user(),
                    ),
                )
                hub_kpis = [w for w in widgets if w.title == "Active Hubs" and hasattr(w, "value")]
                assert len(hub_kpis) == 1
                assert getattr(hub_kpis[0], "value", "") == "1"
                assert sum(getattr(hub_kpis[0], "sparkline", ())) == 1.0

            # Single-record restore enforces can_edit_record -> 403 on locked trashed record
            assert c.post(f"/admin/hubs/{h_trash_id}/restore", data={CSRF_FORM_FIELD: csrf}).status_code == 403

            # save_as on approval-required view queues approval WITHOUT firing on_model_change hook
            assert c.post(
                f"/admin/gov-hubs/{h_live_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "region_iso": "ISO-USE",
                    "name": "Cloned Hub",
                    "_save_action": "save_as",
                },
            ).status_code == 302
            assert hook_calls == []

            # api_quick_edit_form enforces _deck_version OCC (409 on stale, 200 on current)
            r_qe_get = c.get(f"/admin/_api/hubs/{h_live_id}/quick-edit-form")
            assert r_qe_get.status_code == 200 and 'name="_deck_version"' in r_qe_get.get_data(as_text=True)
            assert c.post(
                f"/admin/_api/hubs/{h_live_id}/quick-edit-form",
                data={CSRF_FORM_FIELD: csrf, "region_iso": "ISO-USE", "name": "Stale", "_deck_version": "999"},
            ).status_code == 409
            r_qe_ok = c.post(
                f"/admin/_api/hubs/{h_live_id}/quick-edit-form",
                data={CSRF_FORM_FIELD: csrf, "region_iso": "ISO-USE", "name": "Fresh", "_deck_version": "1"},
            )
            assert r_qe_ok.status_code == 200 and r_qe_ok.get_json()["ok"] is True

            # model_batch_edit rejects non-object JSON payload cleanly with 400
            assert c.post(
                "/admin/hubs/batch-edit",
                data="[1]",
                content_type="application/json",
                headers={CSRF_HEADER_NAME: csrf},
            ).status_code == 400

            # FK dropdown options use non-PK target column value ('ISO-USE', not encoded PK)
            r_fk = c.get("/admin/_api/fk/regions?owner_slug=hubs&field_name=region_iso")
            assert r_fk.status_code == 200
            fk_ids = {item["id"] for item in r_fk.get_json()["items"]}
            assert "ISO-USE" in fk_ids
            assert c.get("/admin/_api/fk/regions?page=999999999").status_code == 200

            # Slash-containing PK edit form: wizard hides save_on_top, inline <template> renders custom FormWidget,
            # and submitting a new inline note saves cleanly against PK 'us/east'
            from urllib.parse import quote

            from flask_deck.adapters.sqlalchemy import encode_pk

            enc_reg_pk = encode_pk(("us/east",))
            url_reg_pk = quote(enc_reg_pk, safe="")
            r_reg_form = c.get(f"/admin/regions/{url_reg_pk}/edit")
            assert r_reg_form.status_code == 200
            reg_html = r_reg_form.get_data(as_text=True)
            assert "dk-form-actions-top" not in reg_html
            assert 'data-custom-inline-widget="1"' in reg_html

            inline_slug = introspect_model(_UiRegionNote).slug
            r_reg_post = c.post(
                f"/admin/regions/{url_reg_pk}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "us/east",
                    "iso_key": "ISO-USE",
                    "name": "US East Updated",
                    "active": "1",
                    f"inline__{inline_slug}__0__body": "Note on slash PK",
                },
            )
            assert r_reg_post.status_code == 302
            with SL_ui() as s:
                saved_notes = list(s.scalars(sa.select(_UiRegionNote).where(_UiRegionNote.region_code == "us/east")))
                assert len(saved_notes) == 1 and saved_notes[0].body == "Note on slash PK"
        finally:
            deck_ui.close()
