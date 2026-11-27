"""Live PostgreSQL 16 dialect, query engine, SQL firewall, and showcase integration tests."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import Deck, ModelView, SQLAlchemyAuditStore, SQLAlchemyAuthProvider
from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk
from flask_deck.cascade import analyze_delete_impact
from flask_deck.demo import create_demo_app
from flask_deck.filters import compute_date_hierarchy
from flask_deck.introspection import introspect_model
from flask_deck.query import estimate_table_rows, execute_list_query
from flask_deck.sql_console import execute_readonly_sql, validate_readonly_sql
from tests._backends import isolated_postgres_engine

pytestmark = pytest.mark.postgres


class PGDeployState(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    FAILED = "failed"


class PGBase(DeclarativeBase):
    pass


class PGCluster(PGBase):
    __tablename__ = "pg_clusters"
    id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), sa.ForeignKey("pg_clusters.id"), nullable=True
    )
    state: Mapped[PGDeployState] = mapped_column(
        sa.Enum(PGDeployState, name="pg_deploy_state"), default=PGDeployState.RUNNING, nullable=False
    )
    budget: Mapped[Decimal] = mapped_column(sa.Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    labels: Mapped[list[str]] = mapped_column(postgresql.ARRAY(sa.String(40)), nullable=False)
    meta_jsonb: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)
    legacy_json: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False)
    summary: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    parent: Mapped[PGCluster | None] = relationship(
        remote_side="PGCluster.id", foreign_keys=[parent_id]
    )
    nodes: Mapped[list[PGNode]] = relationship(
        back_populates="cluster", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return self.name


class PGNode(PGBase):
    __tablename__ = "pg_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("pg_clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(sa.String(80), nullable=False)

    cluster: Mapped[PGCluster] = relationship(back_populates="nodes")


class PGClusterView(ModelView):
    model = PGCluster
    columns = ("id", "name", "state", "budget", "labels", "created_at")
    searchable_columns = ("@summary", "^name", "parent.name")
    filterable_columns = ("state", "labels", "meta_jsonb", "legacy_json", "summary", "parent.name")
    sortable_columns = ("name", "budget", "created_at", "parent.name")
    date_hierarchy = "created_at"
    pagination_mode = "cursor"
    count_mode = "estimated"


def _run_list(sess: Any, view: ModelView, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "base_stmt": sa.select(PGCluster),
        "displayed_columns": view.columns,
        "searchable_columns": view.searchable_columns,
        "filterable_columns": frozenset(view.filterable_columns),
        "sortable_columns": frozenset(view.sortable_columns),
        "quick_tabs": (),
        "active_tab_key": None,
        "search_term": "",
        "filter_params": (),
        "sort_by": None,
        "sort_dir": "asc",
        "default_sort": None,
        "page": 1,
        "page_size": 25,
        "max_page_size": 100,
    }
    kwargs.update(overrides)
    return execute_list_query(sess, view.meta, **kwargs)


def test_postgres_jsonb_array_fts_reltuples_date_hierarchy_cursor_and_cascade() -> None:
    with isolated_postgres_engine() as (eng, schema):
        PGBase.metadata.create_all(eng)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "pg-dialect-integration-secret-32!"
        app.config["TESTING"] = True
        deck = Deck(app, engine=eng, allow_insecure_open=True, auto_audit=False)
        deck.register(PGClusterView, PGNode)
        view = deck.get_view("pg-clusters")

        c1_id = uuid.uuid4()
        c2_id = uuid.uuid4()
        c3_id = uuid.uuid4()
        SessionLocal = sessionmaker(bind=eng, expire_on_commit=False)

        with SessionLocal() as sess:
            c1 = PGCluster(
                id=c1_id,
                name="eu-core-primary",
                state=PGDeployState.RUNNING,
                budget=Decimal("12500.50"),
                labels=["gpu", "tier1", "eu"],
                meta_jsonb={"region": "eu-central-1", "tier": {"rank": "gold", "nullable": None}, "nullable": None},
                legacy_json={"region": "eu-central-1", "nullable": None},
                summary="High throughput Kubernetes inference cluster with NVMe storage",
                created_at=datetime(2025, 11, 10, 9, 0, tzinfo=timezone.utc),
            )
            c2 = PGCluster(
                id=c2_id,
                name="us-edge-worker",
                parent_id=c1_id,
                state=PGDeployState.PENDING,
                budget=Decimal("4200.00"),
                labels=["edge", "us"],
                meta_jsonb={"region": "us-east-1", "tier": {"rank": "silver"}},
                legacy_json={"region": "us-east-1", "other": "x"},
                summary="Low latency edge routing mesh and CDN caching pool",
                created_at=datetime(2026, 3, 15, 14, 30, tzinfo=timezone.utc),
            )
            c3 = PGCluster(
                id=c3_id,
                name="ap-analytics-lake",
                parent_id=c1_id,
                state=PGDeployState.FAILED,
                budget=Decimal("9800.75"),
                labels=["gpu", "analytics"],
                meta_jsonb={"region": "ap-southeast-1", "tier": {"rank": "gold"}},
                legacy_json={"region": "ap-southeast-1"},
                summary="Distributed PostgreSQL warehouse for financial telemetry",
                created_at=datetime(2026, 3, 22, 18, 0, tzinfo=timezone.utc),
            )
            sess.add_all([c1, c2, c3])
            sess.flush()
            sess.add_all([PGNode(cluster_id=c1_id, hostname="gpu-eu-01"), PGNode(cluster_id=c1_id, hostname="gpu-eu-02")])
            sess.commit()

        # UUID PK encode/decode round-trip
        meta = introspect_model(PGCluster)
        assert decode_pk(encode_pk((c1_id,)), meta) == (c1_id,)

        with SessionLocal() as sess:
            # 1. JSONB native operators (?, @>, ->>, #>>) & nested/sa.JSON has_key with null values
            res_has = _run_list(sess, view, filter_params=[("meta_jsonb__has_key", "nullable")])
            assert [r.id for r in res_has.items] == [c1_id]

            res_nested_has = _run_list(sess, view, filter_params=[("meta_jsonb__has_key", "tier.nullable")])
            assert [r.id for r in res_nested_has.items] == [c1_id]

            res_legacy_has = _run_list(sess, view, filter_params=[("legacy_json__has_key", "nullable")])
            assert [r.id for r in res_legacy_has.items] == [c1_id]

            res_path = _run_list(sess, view, filter_params=[("meta_jsonb__path", "tier.rank=gold")])
            assert {r.id for r in res_path.items} == {c1_id, c3_id}

            res_contains = _run_list(
                sess,
                view,
                filter_params=[("meta_jsonb__json_contains", '{"region": "eu-central-1", "nullable": null}')],
            )
            assert [r.id for r in res_contains.items] == [c1_id]

            # Non-JSONB sa.JSON null-value match (verifies our json_typeof fix!)
            res_json_null = _run_list(
                sess,
                view,
                filter_params=[("legacy_json__json_contains", '{"nullable": null}')],
            )
            assert [r.id for r in res_json_null.items] == [c1_id]

            # 2. PostgreSQL ARRAY operators (@>, &&)
            res_arr = _run_list(sess, view, filter_params=[("labels__array_contains", "gpu")])
            assert {r.id for r in res_arr.items} == {c1_id, c3_id}

            res_any = _run_list(sess, view, filter_params=[("labels__array_any", "edge,analytics")])
            assert {r.id for r in res_any.items} == {c2_id, c3_id}

            # 3. Native PostgreSQL Full-Text Search (to_tsvector @@ plainto_tsquery)
            res_fts = _run_list(sess, view, search_term="kubernetes storage")
            assert [r.id for r in res_fts.items] == [c1_id]

            # 4. Self-referential dotted filter & sort (aliased)
            res_self = _run_list(
                sess,
                view,
                filter_params=[("parent.name", "eu-core-primary")],
                sort_by="parent.name",
                sort_dir="asc",
            )
            assert {r.id for r in res_self.items} == {c2_id, c3_id}

            # 5. pg_class.reltuples O(1) estimate (after ANALYZE, verifies psycopg3 fix!)
            sess.execute(sa.text(f'ANALYZE "{schema}".pg_clusters'))
            est = estimate_table_rows(sess, view.meta)
            assert est == 3

            # 6. PostgreSQL EXTRACT() date_hierarchy (Year -> Month -> Day)
            dh_years, _ = compute_date_hierarchy(
                sess,
                view.meta,
                column_name="created_at",
                field_label="Created At",
                dh_value="",
                where_clauses=(),
            )
            assert dh_years is not None
            assert {c["dh"]: c["count"] for c in dh_years.choices} == {"2025": 1, "2026": 2}

            dh_months, _ = compute_date_hierarchy(
                sess,
                view.meta,
                column_name="created_at",
                field_label="Created At",
                dh_value="2026",
                where_clauses=(),
            )
            assert dh_months is not None
            assert [(c["dh"], c["count"]) for c in dh_months.choices] == [("2026-03", 2)]

            dh_days, _ = compute_date_hierarchy(
                sess,
                view.meta,
                column_name="created_at",
                field_label="Created At",
                dh_value="2026-03",
                where_clauses=(),
            )
            assert dh_days is not None
            assert {c["dh"] for c in dh_days.choices} == {"2026-03-15", "2026-03-22"}

            # 7. HMAC Keyset Cursor forward & backward pagination on PG
            p1 = _run_list(
                sess,
                view,
                page_size=2,
                pagination_mode="cursor",
                count_mode="estimated",
                cursor_secret=b"pg-cursor-secret-32-bytes-long!!",
            )
            assert len(p1.items) == 2 and p1.next_cursor is not None
            assert p1.total == 3 and p1.total_is_estimated is True

            p2 = _run_list(
                sess,
                view,
                page_size=2,
                pagination_mode="cursor",
                after_cursor=p1.next_cursor,
                cursor_secret=b"pg-cursor-secret-32-bytes-long!!",
            )
            assert len(p2.items) == 1 and p2.prev_cursor is not None
            assert {r.id for r in p1.items}.isdisjoint({r.id for r in p2.items})

            p_back = _run_list(
                sess,
                view,
                page_size=2,
                pagination_mode="cursor",
                before_cursor=p2.prev_cursor,
                cursor_secret=b"pg-cursor-secret-32-bytes-long!!",
            )
            assert [r.id for r in p_back.items] == [r.id for r in p1.items]

            # 8. Cascade Delete Impact on PostgreSQL (UUID FK + self-ref children)
            impact = analyze_delete_impact(
                sess,
                deck,
                view,
                sa.select(PGCluster.id).where(PGCluster.id == c1_id),
                1,
                user=None,
            )
            assert impact.total_affected >= 4  # 2 PGNode rows + 2 child PGCluster rows

        # 9. Default dashboard (CAST(created_at AS DATE) sparkline aggregation) on live PostgreSQL
        assert app.test_client().get("/admin/").status_code == 200

        deck.close()


def test_postgres_sql_console_read_only_enforcement_and_lexer() -> None:
    with isolated_postgres_engine() as (eng, _schema):
        PGBase.metadata.create_all(eng)
        # PostgreSQL `#` bitwise XOR operator executes cleanly
        res_xor = execute_readonly_sql(eng, "SELECT 5 # 3 AS xor_val")
        assert res_xor.error is None
        assert res_xor.rows == ((6,),)

        # PostgreSQL E'...' escape string & `# ; DROP` blocked by lexer
        with pytest.raises(ValueError, match="Escape-string"):
            validate_readonly_sql("SELECT E'x\\'; DROP TABLE pg_clusters'", dialect_name="postgresql")
        with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
            validate_readonly_sql("SELECT 1 # ; DROP TABLE pg_clusters", dialect_name="postgresql")

        # EXPLAIN works on PostgreSQL
        res_explain = execute_readonly_sql(eng, "SELECT 1 AS ok", explain=True)
        assert res_explain.error is None and res_explain.row_count >= 1

        # Defense-in-depth: DB-level SET TRANSACTION READ ONLY rejects sneaky writes via function!
        with eng.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE pg_ro_probe (id INT); "
                    "CREATE OR REPLACE FUNCTION pg_try_write() RETURNS INT LANGUAGE plpgsql AS $$ "
                    "BEGIN INSERT INTO pg_ro_probe VALUES (1); RETURN 1; END; $$;"
                )
            )
        res_mut = execute_readonly_sql(eng, "SELECT pg_try_write() AS sneaky")
        assert res_mut.error is not None
        assert "read-only" in res_mut.error.lower()
        with eng.connect() as conn:
            assert conn.execute(sa.text("SELECT COUNT(*) FROM pg_ro_probe")).scalar() == 0


def test_postgres_showcase_demo_full_boot_reset_and_multiworker_iam() -> None:
    with isolated_postgres_engine() as (eng, schema):
        pg_url = str(eng.url.render_as_string(hide_password=False))
        # Ensure create_demo_app runs cleanly inside our isolated PG schema
        # by injecting options via connect_args / search_path on a dedicated app
        app = create_demo_app(
            db_uri=f"{pg_url}?options=-csearch_path%3D{schema}%2Cpublic"
            if "?" not in pg_url
            else f"{pg_url}&options=-csearch_path%3D{schema}%2Cpublic",
            seed_profile="showcase",
            demo_safe_mode=False,
        )
        deck: Deck = next(iter(app.extensions["flask_deck"].values()))
        try:
            # Verify dashboard + orders + SQL preset sq-bi-sla-risk on live PostgreSQL!
            client = app.test_client()
            login_page = client.get("/admin/login")
            assert login_page.status_code == 200
            assert deck.saved_query_store is not None
            sla_q = deck.saved_query_store.get("sq-bi-sla-risk")
            assert sla_q is not None
            res_sla = execute_readonly_sql(deck.adapter.get_engine(), sla_q.sql)
            assert res_sla.error is None and res_sla.row_count >= 1

            # Verify PostgreSQL TRUNCATE ... RESTART IDENTITY CASCADE reset works cleanly!
            reset_fn = app.extensions["flask_deck_demo_reset"]
            out = reset_fn(force=True)
            assert out["reset"] is True

            # Verify multi-worker IAM & Audit Hash Chain across two independent PG engines
            auth_b = SQLAlchemyAuthProvider(eng)
            audit_b = SQLAlchemyAuditStore(eng, hash_chain=True)
            assert auth_b.get_user_by_username("admin@acme.dev") is not None
            ok_chain, bad_id = audit_b.verify_chain()
            assert ok_chain and bad_id is None
        finally:
            deck.close()
            if deck.adapter is not None:
                deck.adapter.dispose()
