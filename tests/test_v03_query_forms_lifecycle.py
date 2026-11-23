from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckEvent,
    ModelView,
    RBACAuthProvider,
    Role,
    WebhookSink,
    pydantic_validator,
)
from flask_deck.events import is_ssrf_safe_url, sign_webhook_payload
from flask_deck.introspection import introspect_model
from flask_deck.query import (
    build_filter_condition,
    build_pg_reltuples_statement,
    execute_list_query,
)
from flask_deck.security import CSRF_FORM_FIELD, CSRF_SESSION_KEY


class QBase(DeclarativeBase):
    pass


class Dept(QBase):
    __tablename__ = "v03_depts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)


class Employee(QBase):
    __tablename__ = "v03_employees"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    dept_id: Mapped[int] = mapped_column(sa.ForeignKey("v03_depts.id"), nullable=False)


class TicketRecord(QBase):
    __tablename__ = "v03_tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(32), unique=True, nullable=False)
    bucket: Mapped[str] = mapped_column(sa.String(20), nullable=False)  # duplicate sort values!
    score: Mapped[int] = mapped_column(sa.Integer, default=50, nullable=False)
    meta_json: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)


class PgModel(DeclarativeBase):
    pass


class PgArticle(PgModel):
    __tablename__ = "pg_articles"

    id: Mapped[int] = mapped_column(primary_key=True)
    tags: Mapped[list[str]] = mapped_column(postgresql.ARRAY(sa.String), nullable=False)
    props: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)


class SecondaryBase(DeclarativeBase):
    pass


class MetricEvent(SecondaryBase):
    __tablename__ = "v03_metrics"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)


def _csrf(client: Any) -> str:
    with client.session_transaction() as sess:
        tok = sess.get(CSRF_SESSION_KEY)
        if not tok:
            tok = "c" * 48
            sess[CSRF_SESSION_KEY] = tok
        return str(tok)


def test_keyset_cursor_pagination_forward_backward_duplicate_keys_and_tampering() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    QBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    # 15 records sharing only 3 bucket values -> tests composite (bucket, id) tie-breaking!
    with SessionLocal() as sess:
        for i in range(1, 16):
            sess.add(
                TicketRecord(
                    code=f"TK-{i:03d}",
                    bucket=("alpha", "beta", "gamma")[i % 3],
                    score=i * 10,
                    meta_json={"region": "eu-west" if i % 2 == 0 else "us-east", "tier": "pro"},
                )
            )
        sess.commit()

    meta = introspect_model(TicketRecord)
    secret = b"cursor-hmac-secret-key-32-bytes!"

    try:
        with SessionLocal() as sess:
            seen_ids: list[int] = []
            cursor: str | None = None
            pages_fwd: list[list[int]] = []
            for _ in range(10):
                res = execute_list_query(
                    sess,
                    meta,
                    base_stmt=sa.select(TicketRecord),
                    displayed_columns=("code", "bucket", "score"),
                    searchable_columns=("code",),
                    filterable_columns=frozenset({"bucket", "score", "meta_json"}),
                    sortable_columns=frozenset({"id", "bucket", "score"}),
                    quick_tabs=(),
                    active_tab_key=None,
                    search_term="",
                    filter_params={},
                    sort_by="bucket",
                    sort_dir="asc",
                    default_sort=None,
                    page=1,
                    page_size=4,
                    max_page_size=50,
                    pagination_mode="cursor",
                    count_mode="none",
                    after_cursor=cursor,
                    cursor_secret=secret,
                )
                assert not res.total_known
                page_ids = [r.id for r in res.items]
                pages_fwd.append(page_ids)
                seen_ids.extend(page_ids)
                if not res.has_next:
                    break
                cursor = res.next_cursor
                assert cursor is not None

            # Disjoint union of all 15 records with ZERO skips and ZERO duplicates!
            assert len(seen_ids) == 15
            assert len(set(seen_ids)) == 15
            assert len(pages_fwd) == 4  # 4 + 4 + 4 + 3

            # Now walk backward from page 4 -> page 3 using before_cursor
            prev_res = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(TicketRecord),
                displayed_columns=("code", "bucket", "score"),
                searchable_columns=("code",),
                filterable_columns=frozenset({"bucket"}),
                sortable_columns=frozenset({"id", "bucket"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="bucket",
                sort_dir="asc",
                default_sort=None,
                page=1,
                page_size=4,
                max_page_size=50,
                pagination_mode="cursor",
                before_cursor=res.prev_cursor,
                cursor_secret=secret,
            )
            assert [r.id for r in prev_res.items] == pages_fwd[2]

            # Tampered HMAC cursor safely resets to first page (fail-closed)
            tampered = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(TicketRecord),
                displayed_columns=("code",),
                searchable_columns=(),
                filterable_columns=frozenset(),
                sortable_columns=frozenset({"id", "bucket"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={},
                sort_by="bucket",
                sort_dir="asc",
                default_sort=None,
                page=1,
                page_size=4,
                max_page_size=50,
                pagination_mode="cursor",
                after_cursor="eyJ2IjoxfQ.forgedsignature123456789",
                cursor_secret=secret,
            )
            assert [r.id for r in tampered.items] == pages_fwd[0]
    finally:
        engine.dispose()


def test_postgresql_array_jsonb_sql_compilation_and_sqlite_json_filters() -> None:
    # 1. PostgreSQL dialect compilation checks (no live PG server needed!)
    pg_meta = introspect_model(PgArticle)
    assert pg_meta.fields_by_name["tags"].field_type == "array"
    assert pg_meta.fields_by_name["tags"].array_item_type == "string"
    assert pg_meta.fields_by_name["props"].is_jsonb is True

    pg_dialect = postgresql.dialect()

    c_arr = build_filter_condition(pg_meta, "tags", "flask", op="array_contains", dialect_name="postgresql")
    assert c_arr is not None
    assert "@>" in str(c_arr.compile(dialect=pg_dialect))

    c_any = build_filter_condition(pg_meta, "tags", "flask,python", op="array_any", dialect_name="postgresql")
    assert c_any is not None
    assert "&&" in str(c_any.compile(dialect=pg_dialect))

    c_has = build_filter_condition(pg_meta, "props", "region", op="has_key", dialect_name="postgresql")
    assert c_has is not None
    assert "?" in str(c_has.compile(dialect=pg_dialect))

    c_path = build_filter_condition(pg_meta, "props", "env.region=eu-west", op="path", dialect_name="postgresql")
    assert c_path is not None
    compiled_path = str(c_path.compile(dialect=pg_dialect))
    assert "#>>" in compiled_path or "->>" in compiled_path

    c_jcont = build_filter_condition(
        pg_meta, "props", '{"tier":"enterprise"}', op="json_contains", dialect_name="postgresql"
    )
    assert c_jcont is not None
    assert "@>" in str(c_jcont.compile(dialect=pg_dialect))

    # Malicious JSON path injection must be rejected (returns None)
    assert build_filter_condition(pg_meta, "props", "a'); DROP TABLE--=x", op="path", dialect_name="postgresql") is None
    assert build_filter_condition(pg_meta, "props", "bad$key", op="has_key", dialect_name="sqlite") is None

    # reltuples statement check (schema-aware via pg_namespace)
    rel_sql = str(build_pg_reltuples_statement("pg_articles").compile(dialect=pg_dialect))
    assert "reltuples" in rel_sql and "pg_namespace" in rel_sql
    rel_sch_sql = str(
        build_pg_reltuples_statement("pg_articles", schema="billing").compile(dialect=pg_dialect)
    )
    assert "pg_namespace" in rel_sch_sql and "nspname" in rel_sch_sql

    # 2. Functional SQLite JSON filter execution + multi-operator rules
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    QBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with SessionLocal() as sess:
            sess.add_all(
                [
                    TicketRecord(code="J-1", bucket="a", score=10, meta_json={"region": "eu-west", "vip": True}),
                    TicketRecord(code="J-2", bucket="b", score=80, meta_json={"region": "us-east"}),
                    TicketRecord(code="J-3", bucket="c", score=95, meta_json={"other": 1}),
                ]
            )
            sess.commit()
            meta = introspect_model(TicketRecord)
            res_has = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(TicketRecord),
                displayed_columns=("code",),
                searchable_columns=(),
                filterable_columns=frozenset({"meta_json", "score", "code"}),
                sortable_columns=frozenset({"id"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={"meta_json__has_key": "region", "score__gt": "50"},
                sort_by="id",
                sort_dir="asc",
                default_sort=None,
                page=1,
                page_size=10,
                max_page_size=50,
            )
            assert [r.code for r in res_has.items] == ["J-2"]

            res_path = execute_list_query(
                sess,
                meta,
                base_stmt=sa.select(TicketRecord),
                displayed_columns=("code",),
                searchable_columns=(),
                filterable_columns=frozenset({"meta_json"}),
                sortable_columns=frozenset({"id"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params={"meta_json__path": "region=eu-west"},
                sort_by="id",
                sort_dir="asc",
                default_sort=None,
                page=1,
                page_size=10,
                max_page_size=50,
            )
            assert [r.code for r in res_path.items] == ["J-1"]
    finally:
        engine.dispose()


def test_soft_delete_history_diff_wizard_cascading_fk_multibind_and_ssrf_webhooks() -> None:
    eng_main = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    eng_metrics = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    QBase.metadata.create_all(eng_main)
    SecondaryBase.metadata.create_all(eng_metrics)
    MainSession = sessionmaker(bind=eng_main, autoflush=False, expire_on_commit=False)

    with MainSession() as sess:
        d1 = Dept(name="Engineering")
        d2 = Dept(name="Finance")
        sess.add_all([d1, d2])
        sess.flush()
        sess.add_all(
            [
                Employee(name="Ada Eng", dept_id=d1.id),
                Employee(name="Bob Fin", dept_id=d2.id),
            ]
        )
        sess.add(TicketRecord(code="SD-1", bucket="open", score=40))
        sess.commit()

    with sessionmaker(bind=eng_metrics)() as msess:
        msess.add(MetricEvent(name="cpu_spike"))
        msess.commit()

    # Fake Pydantic v2 schema verifying pydantic_validator bridge
    class _FakePydanticErr(Exception):
        def errors(self) -> list[dict[str, Any]]:
            return [{"loc": ("score",), "msg": "Score must be <= 100"}]

    class FakeTicketSchema:
        @classmethod
        def model_validate(cls, data: dict[str, Any]) -> None:
            if int(data.get("score", 0)) > 100:
                raise _FakePydanticErr()

    class TicketView(ModelView):
        model = TicketRecord
        soft_delete_column = "deleted_at"
        form_excluded_columns = ("deleted_at",)
        form_layout = "wizard"
        fieldsets = (
            ("Step 1", ("code", "bucket")),
            ("Step 2", ("score", "meta_json")),
        )
        field_conditions = MappingProxyType({"meta_json": ("bucket", "neq", "closed")})
        form_validator = staticmethod(pydantic_validator(FakeTicketSchema))

    class MetricView(ModelView):
        model = MetricEvent
        bind_key = "metrics"

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "v03-lifecycle-secret-key-thirty-two!!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        session_factory=MainSession,
        engine=eng_main,
        binds={"metrics": eng_metrics},
        allow_insecure_open=True,
        auto_audit=True,
    )
    try:
        deck.register(Dept, Employee, TicketView, MetricView)

        captured_events: list[DeckEvent] = []

        @deck.on("*")
        def _cap(ev: DeckEvent) -> None:
            captured_events.append(ev)

        client = app.test_client()
        tok = _csrf(client)

        # 1. Multi-bind secondary engine list works seamlessly
        m_resp = client.get("/admin/metric-events/")
        assert m_resp.status_code == 200
        assert b"cpu_spike" in m_resp.data

        # 2. Cascading FK endpoint scopes employees by dept_id
        fk_resp = client.get("/admin/_api/fk/employees?dep_col=dept_id&dep_val=1")
        assert fk_resp.status_code == 200
        items = fk_resp.get_json()["items"]
        assert len(items) == 1 and items[0]["label"] == "Ada Eng"

        # 3. Wizard form HTML + conditional data-show-when + pydantic_validator rejection
        new_page = client.get("/admin/ticket-records/new")
        assert b"data-deck-wizard" in new_page.data
        assert b"data-show-when=" in new_page.data

        bad_val = client.post(
            "/admin/ticket-records/new",
            data={CSRF_FORM_FIELD: tok, "code": "SD-2", "bucket": "open", "score": "999"},
        )
        assert bad_val.status_code == 200
        assert b"Score must be &lt;= 100" in bad_val.data

        # 4. Edit record -> generates revision -> inspect Side-by-Side Diff (/history)
        edit_resp = client.post(
            "/admin/ticket-records/1/edit",
            data={CSRF_FORM_FIELD: tok, "code": "SD-1", "bucket": "closed", "score": "85"},
            follow_redirects=False,
        )
        assert edit_resp.status_code == 302
        hist_resp = client.get("/admin/ticket-records/1/history")
        assert hist_resp.status_code == 200
        assert b"Revision Diff" in hist_resp.data
        assert b"closed" in hist_resp.data

        # 5. Soft-delete moves record to Trash -> hidden in normal list -> visible in ?trashed=1 -> Restore brings it back!
        del_resp = client.post("/admin/ticket-records/1/delete", data={CSRF_FORM_FIELD: tok})
        assert del_resp.status_code == 302
        after_del = client.get("/admin/ticket-records/").data
        assert b"Moved Ticket Record (SD-1) to Trash." in after_del
        assert b"No ticket records match" in after_del
        assert b"SD-1" in client.get("/admin/ticket-records/?trashed=1").data

        rest_resp = client.post("/admin/ticket-records/1/restore", data={CSRF_FORM_FIELD: tok})
        assert rest_resp.status_code == 302
        assert b"SD-1" in client.get("/admin/ticket-records/").data
        assert any(ev.name == "record.restored" for ev in captured_events)

        # 6. Force delete permanently removes record
        force_resp = client.post(
            "/admin/ticket-records/1/delete",
            data={CSRF_FORM_FIELD: tok, "force": "1"},
        )
        assert force_resp.status_code == 302
        assert b"No ticket records match" in client.get("/admin/ticket-records/?trashed=1").data

        # 7. SSRF Webhook Security Firewall + HMAC Signature Verification
        for blocked_url in (
            "http://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/hook",
            "https://10.0.0.5/internal",
            "https://localhost/hook",
            "http://example.com/insecure",
        ):
            safe, _reason = is_ssrf_safe_url(blocked_url)
            assert not safe, f"Expected SSRF guard to block {blocked_url}"

        delivered: list[tuple[str, bytes, dict[str, str]]] = []
        sink = WebhookSink(
            "https://93.184.216.34/webhook",
            secret="webhook-signing-secret-32-bytes!",
            events=("record.created",),
            transport=lambda u, b, h, _t: (delivered.append((u, b, h)) or 200),
        )
        ev = DeckEvent(name="record.created", model_slug="orders", record_pk="42")
        sink(ev)
        assert len(delivered) == 1
        url_sent, body_sent, hdrs = delivered[0]
        assert url_sent == "https://93.184.216.34/webhook"
        assert hdrs["X-Deck-Signature"] == sign_webhook_payload(body_sent, "webhook-signing-secret-32-bytes!")
        assert hdrs["X-Deck-Event"] == "record.created"
        _ = (RBACAuthProvider, Role, parse_qs, urlsplit, pytest)
    finally:
        deck.close()
