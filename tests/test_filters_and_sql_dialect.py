"""Behavioral & security tests for ListFilters, date hierarchy, SQL Console lexer/charts, and ORMAdapter."""

from __future__ import annotations

import enum
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    Deck,
    DeckUser,
    EmptyFieldListFilter,
    ListFilter,
    ModelView,
    PredicateListFilter,
    RangeListFilter,
    RBACAuthProvider,
    RelatedOnlyFieldListFilter,
    Role,
)
from flask_deck.adapters.sqlalchemy import (
    FlaskSQLAlchemyAdapter,
    ORMAdapter,
    PureSQLAlchemyAdapter,
    coerce_pk_value,
    decode_pk,
    encode_pk,
    resolve_adapter,
)
from flask_deck.exceptions import InvalidPKError
from flask_deck.filters import (
    _dh_bucket_expr,
    build_date_hierarchy_predicate,
    collect_shared_facet_exprs,
    compute_date_hierarchy,
    compute_filter_facets,
)
from flask_deck.introspection import introspect_model
from flask_deck.query import build_filter_condition
from flask_deck.sql_console import (
    InMemorySavedQueryStore,
    SavedQueryRecord,
    SQLAlchemySavedQueryStore,
    SQLQueryResult,
    _find_sensitive_indices_from_sql,
    _strip_sql_comments_and_literals,
    build_sql_chart_svg,
    execute_readonly_sql,
    extract_sql_chart_data,
    format_sql_result_csv,
    introspect_engine_schema,
    validate_readonly_sql,
)
from tests._backends import sqlite_memory_engine


class FltTier(enum.Enum):
    FREE = "free"
    PRO = "pro"


class FltBase(DeclarativeBase):
    pass


class FltOrg(FltBase):
    __tablename__ = "flt_orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    def __str__(self) -> str:
        return self.name


class FltOrder(FltBase):
    __tablename__ = "flt_orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(sa.ForeignKey("flt_orgs.id"), nullable=True)
    tier: Mapped[FltTier] = mapped_column(sa.Enum(FltTier), default=FltTier.FREE, nullable=False)
    amount: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    active: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)
    note: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    secret_token: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    order_date: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    org: Mapped[FltOrg | None] = relationship()


class PkRichModel(FltBase):
    __tablename__ = "pk_rich"
    id_uuid: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    id_enum: Mapped[FltTier] = mapped_column(sa.Enum(FltTier), primary_key=True)
    id_date: Mapped[date] = mapped_column(sa.Date, primary_key=True)
    id_dt: Mapped[datetime] = mapped_column(sa.DateTime, primary_key=True)
    id_dec: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), primary_key=True)


class PkSingleStr(FltBase):
    __tablename__ = "pk_single_str"
    slug: Mapped[str] = mapped_column(sa.String(80), primary_key=True)


class ComplexOrgActiveFilter(ListFilter):
    """Custom ListFilter without facet_predicate (forces join subquery facet path)."""

    parameter_name = "active_org"
    title = "Org State"

    def lookups(self, session: Any, view: Any, user: Any) -> list[tuple[str, str]]:
        _ = (session, view, user)
        return [("yes", "Active Org"), ("no", "Inactive Org")]

    def apply(self, stmt: Any, value: str, session: Any, view: Any, user: Any) -> Any:
        _ = (session, view, user)
        return stmt.join(FltOrg, FltOrder.org_id == FltOrg.id).where(FltOrg.active.is_(value == "yes"))


class FltOrderView(ModelView):
    model = FltOrder
    slug = "flt-orders"
    filterable_columns = ("tier", "active", "org_id", "created_at")


def test_filters_facets_date_hierarchy_and_dialect_compilation() -> None:
    with sqlite_memory_engine() as eng:
        FltBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "filters-test-secret-32-bytes!!"

        auth = RBACAuthProvider(
            roles=[
                Role("superadmin", permissions=frozenset({"*"})),
                Role(
                    "restricted",
                    permissions=frozenset({"flt-orders:view"}),
                    hidden_fields={"flt-orders": frozenset({"note", "org_id"})},
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="su", username="su", roles=("superadmin",), is_superuser=True),
                    password="pass1234",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="rs", username="rs", roles=("restricted",)),
                    password="pass1234",
                ),
            ],
        )
        deck = Deck(app, session_factory=SessionLocal, engine=eng, auth=auth, auto_audit=False)
        deck.register(FltOrderView, FltOrg)
        view = deck.get_view("flt-orders")
        su_user = auth.get_user_by_id("su")
        rs_user = auth.get_user_by_id("rs")

        try:
            with app.app_context(), SessionLocal() as sess:
                o1 = FltOrg(name="Alpha", active=True)
                o2 = FltOrg(name="Beta", active=False)
                o3 = FltOrg(name="Unused", active=True)
                sess.add_all([o1, o2, o3])
                sess.flush()
                sess.add_all(
                    [
                        FltOrder(org_id=o1.id, tier=FltTier.PRO, amount=200, active=True, note="vip", order_date=date(2026, 2, 10), created_at=datetime(2026, 2, 10, 12, tzinfo=timezone.utc)),
                        FltOrder(org_id=o2.id, tier=FltTier.FREE, amount=50, active=False, note="", order_date=date(2026, 12, 3), created_at=datetime(2026, 12, 3, 8, tzinfo=timezone.utc)),
                        FltOrder(org_id=None, tier=FltTier.FREE, amount=500, active=None, note=None, order_date=date(2025, 6, 15), created_at=datetime(2025, 6, 15, 8, tzinfo=timezone.utc)),
                    ]
                )
                sess.commit()

                # RangeListFilter, PredicateListFilter, EmptyFieldListFilter (string + non-string + RBAC restricted)
                rf = RangeListFilter(
                    parameter_name="amt",
                    title="Amount",
                    column="amount",
                    bands=[("low", "Low", None, 100), ("mid", "Mid", 100, 300), ("high", "High", 300, None), ("open", "Open", None, None)],
                )
                assert rf.facet_predicate("open", FltOrder) is None
                assert rf.facet_predicate("unknown", FltOrder) is None
                assert len(sess.scalars(rf.apply(sa.select(FltOrder), "mid", sess, view, su_user)).all()) == 1

                pf = PredicateListFilter(
                    parameter_name="big",
                    title="Big",
                    choices=[("yes", "Yes", lambda m: m.amount >= 200)],
                )
                assert len(sess.scalars(pf.apply(sa.select(FltOrder), "yes", sess, view, su_user)).all()) == 2

                ef_str = EmptyFieldListFilter(column="note")
                assert len(sess.scalars(ef_str.apply(sa.select(FltOrder), "empty", sess, view, su_user)).all()) == 2
                assert len(sess.scalars(ef_str.apply(sa.select(FltOrder), "non_empty", sess, view, su_user)).all()) == 1
                assert ef_str.facet_predicate("bogus", FltOrder) is None
                assert ef_str.lookups(sess, view, rs_user) == ()  # hidden field blocked
                assert ef_str.apply(sa.select(FltOrder), "empty", sess, view, rs_user).compile().string == sa.select(FltOrder).compile().string

                ef_non_str = EmptyFieldListFilter(column="order_date")
                assert len(sess.scalars(ef_non_str.apply(sa.select(FltOrder), "non_empty", sess, view, su_user)).all()) == 3
                assert len(sess.scalars(ef_non_str.apply(sa.select(FltOrder), "empty", sess, view, su_user)).all()) == 0
                assert EmptyFieldListFilter(column="secret_token").lookups(sess, view, su_user) == ()

                # RelatedOnlyFieldListFilter: omits unused org o3, includes __null__, respects RBAC restriction & pk: prefix
                rel_f = RelatedOnlyFieldListFilter(column="org_id")
                rel_choices = dict(rel_f.lookups(sess, view, su_user))
                assert "Unused" not in rel_choices.values()
                assert "__null__" in rel_choices
                assert rel_f.lookups(sess, view, rs_user) == ()
                assert len(sess.scalars(rel_f.apply(sa.select(FltOrder), f"pk:{o1.id}", sess, view, su_user)).all()) == 1
                assert RelatedOnlyFieldListFilter(column="amount").lookups(sess, view, su_user) == ()

                # Date hierarchy: date column + datetime column + invalid bounds + dialect bucket compilation
                assert build_date_hierarchy_predicate(view.meta, "amount", "2026") is None
                assert build_date_hierarchy_predicate(view.meta, "created_at", "bad-date") is None
                assert build_date_hierarchy_predicate(view.meta, "created_at", "1800") is None
                assert build_date_hierarchy_predicate(view.meta, "created_at", "2026-13") is None
                assert build_date_hierarchy_predicate(view.meta, "created_at", "2026-02-30") is None
                assert build_date_hierarchy_predicate(view.meta, "order_date", "2026-12") is not None
                assert build_date_hierarchy_predicate(view.meta, "order_date", "2026-02-10") is not None

                dh_yr, _ = compute_date_hierarchy(sess, view.meta, column_name="created_at", field_label="Created", dh_value="", where_clauses=())
                assert dh_yr is not None and len(dh_yr.choices) == 2
                dh_mo, _ = compute_date_hierarchy(sess, view.meta, column_name="created_at", field_label="Created", dh_value="2026", where_clauses=())
                assert dh_mo is not None and {c["dh"] for c in dh_mo.choices} == {"2026-02", "2026-12"}
                dh_ex, pred_ex = compute_date_hierarchy(sess, view.meta, column_name="order_date", field_label="Date", dh_value="2026-02-10", where_clauses=())
                assert dh_ex is not None and dh_ex.level == "exact_day" and pred_ex is not None
                assert compute_date_hierarchy(sess, view.meta, column_name="amount", field_label="Amt", dh_value="", where_clauses=()) == (None, None)

                # Dialect compilation checks for SQLite, MySQL, PostgreSQL
                col = FltOrder.created_at
                assert "strftime" in str(_dh_bucket_expr(col, level="year", dialect_name="sqlite").compile(dialect=sqlite.dialect()))
                assert "date_format" in str(_dh_bucket_expr(col, level="month", dialect_name="mysql").compile(dialect=mysql.dialect())).lower()
                assert "extract" in str(_dh_bucket_expr(col, level="day", dialect_name="postgresql").compile(dialect=postgresql.dialect())).lower()

                # collect_shared_facet_exprs + compute_filter_facets (including self-filtered, FK nullable, and complex join custom filter)
                specs = [
                    {"name": "active", "type": "boolean", "nullable": True},
                    {"name": "tier", "type": "enum", "choices": [("free", "Free"), ("pro", "Pro")]},
                    {"name": "org_id", "type": "fk", "nullable": True},
                    {"name": "org.name", "type": "string"},
                ]
                complex_f = ComplexOrgActiveFilter()
                shared = collect_shared_facet_exprs(
                    sess,
                    view,
                    filter_specs=specs,
                    custom_filters=(pf, complex_f),
                    build_condition_fn=build_filter_condition,
                    user=su_user,
                    dialect_name="sqlite",
                )
                assert any(g == "cf_big" for g, _, _ in shared)
                assert not any(g == "cf_active_org" for g, _, _ in shared)

                facets = compute_filter_facets(
                    sess,
                    view,
                    base_where=(),
                    joins=(),
                    filter_specs=specs,
                    custom_filters=(pf, complex_f),
                    custom_appliers_by_param={"big": lambda s: pf.apply(s, "yes", sess, view, su_user)},
                    filter_where_by_field={"tier": [FltOrder.tier == FltTier.PRO]},
                    build_condition_fn=build_filter_condition,
                    user=su_user,
                    dialect_name="sqlite",
                )
                assert facets["active"]["__null__"] == 0  # excluded by tier==PRO
                assert facets["tier"]["free"] == 1  # self-filter excluded when counting own choices!
                assert facets["cf_active_org"]["yes"] == 1
        finally:
            deck.close()


def test_sql_console_lexer_redaction_charts_and_saved_query_stores() -> None:
    # 1. Lexer security edge cases across dialects
    assert _strip_sql_comments_and_literals("SELECT 1 # comment\n", dialect_name="mysql")[0].strip() == "SELECT 1"
    with pytest.raises(ValueError, match="Conditional SQL"):
        _strip_sql_comments_and_literals("SELECT /*!50000 1 */")
    with pytest.raises(ValueError, match="Nested block"):
        _strip_sql_comments_and_literals("SELECT /* a /* b */ */ 1")
    with pytest.raises(ValueError, match="Unterminated block"):
        _strip_sql_comments_and_literals("SELECT /* oops")
    with pytest.raises(ValueError, match="Backslash escapes"):
        _strip_sql_comments_and_literals("SELECT 'a\\'b'", dialect_name="mysql")
    with pytest.raises(ValueError, match="Unterminated string"):
        _strip_sql_comments_and_literals("SELECT 'unterminated")
    assert "''" in _strip_sql_comments_and_literals("SELECT $tag$hello; DROP$tag$ AS v", dialect_name="postgresql")[0]
    with pytest.raises(ValueError, match="Unterminated dollar-quoted"):
        _strip_sql_comments_and_literals("SELECT $tag$oops", dialect_name="postgresql")
    norm_q, idents = _strip_sql_comments_and_literals('SELECT "col""1", `b` FROM t')
    assert idents == ['col"1', "b"] and 'col"1' in norm_q
    with pytest.raises(ValueError, match="Unterminated quoted"):
        _strip_sql_comments_and_literals('SELECT "oops')

    # 2. Sensitive column detection with wildcards, multi-wildcards, and fail-closed mismatches
    assert 0 in _find_sensitive_indices_from_sql("SELECT password_hash AS safe_alias, * FROM u", ("safe_alias", "id", "name"), ())
    assert 2 in _find_sensitive_indices_from_sql("SELECT *, api_secret AS out_v FROM u", ("id", "name", "out_v"), ())
    # Multiple wildcards with aliased sensitive expression catches matching alias, and fails closed when unmatched
    assert 2 in _find_sensitive_indices_from_sql("SELECT a.*, b.*, password_hash AS leak FROM a, b", ("id", "x", "leak"), ())
    assert _find_sensitive_indices_from_sql("SELECT a.*, b.*, lower(password_hash) FROM a, b", ("id", "x", "c"), ()) == {0, 1, 2}
    # Mismatched non-wildcard arity fails closed on unaliased sensitive expr
    assert _find_sensitive_indices_from_sql("SELECT password_hash + 1 FROM u", ("a", "b"), ()) == {0, 1}

    # 3. Validation limits & CTE sensitive block
    with pytest.raises(ValueError, match="Enter a SQL"):
        validate_readonly_sql("   ")
    with pytest.raises(ValueError, match="10,000"):
        validate_readonly_sql("SELECT " + "1" * 10001)
    with pytest.raises(ValueError, match="Enter a SQL"):
        validate_readonly_sql("-- only a comment")
    with pytest.raises(ValueError, match="CTE or subquery"):
        validate_readonly_sql("WITH x AS (SELECT password_hash AS p FROM u) SELECT p FROM x")

    # 4. Execution, EXPLAIN, CSV export, schema introspection, and SVG charts
    with sqlite_memory_engine() as eng:
        FltBase.metadata.create_all(eng)
        res_bad = execute_readonly_sql(eng, "SELECT * FROM nonexistent_table_xyz")
        assert res_bad.error is not None and "SQL execution error" in res_bad.error

        res_exp = execute_readonly_sql(eng, "SELECT 1 AS a", explain=True)
        assert res_exp.error is None and res_exp.row_count >= 1

        csv_out = format_sql_result_csv(["col", "val"], [["=CMD()", 42]])
        assert "'=CMD()" in csv_out

        schema_tbls = introspect_engine_schema(eng)
        assert any(t["name"] == "flt_orders" for t in schema_tbls)

        # Chart extraction & rendering (error/empty, all-numeric, single bar, grouped bar, line)
        assert extract_sql_chart_data(res_bad) is None
        assert build_sql_chart_svg(res_bad) is None
        res_all_num = SQLQueryResult("SELECT", ("x", "y"), ((1, 10), (2, 20)), 2, False, (), 1.0)
        assert extract_sql_chart_data(res_all_num) is not None
        res_bool_only = SQLQueryResult("SELECT", ("a", "b"), (("k", True),), 1, False, (), 1.0)
        assert extract_sql_chart_data(res_bool_only) is None

        res_multi = SQLQueryResult("SELECT", ("plan", "rev", "seats"), (("pro", 100, 10), ("free", 20, "bad")), 2, False, (), 1.0)
        assert "<svg" in str(build_sql_chart_svg(res_multi, chart_type="bar"))
        assert "<svg" in str(build_sql_chart_svg(res_multi, chart_type="line"))

        # SavedQueryStore edge cases (in-memory & SQLAlchemy)
        for store in (InMemorySavedQueryStore(), SQLAlchemySavedQueryStore(eng)):
            assert store.get("missing") is None
            assert store.toggle_pin("missing") is None
            assert store.delete("missing", actor_id="u1") is False
            rec = store.create(SavedQueryRecord(id="", name="Q1", sql="SELECT 1", owner_id="u1", owner_name="U1"))
            assert store.get(rec.id) is not None
            toggled = store.toggle_pin(rec.id, chart_type="line")
            assert toggled is not None and toggled.is_pinned_to_dashboard is True and toggled.chart_type == "line"
            assert store.delete(rec.id, actor_id="other", is_superuser=False) is False
            assert store.delete(rec.id, actor_id="u1", is_superuser=False) is True


def test_orm_adapters_multibind_teardown_and_pk_codecs() -> None:
    app = Flask(__name__)
    with sqlite_memory_engine() as eng1, sqlite_memory_engine() as eng2:
        # PureSQLAlchemyAdapter validation, multi-bind, unknown bind, engine inference, teardown rollback
        with pytest.raises(ValueError, match="Provide either"):
            PureSQLAlchemyAdapter()

        sf_only = sessionmaker(bind=eng1)
        pure = PureSQLAlchemyAdapter(session_factory=sf_only, binds={"analytics": eng2})
        pure.register_teardown(app)
        with app.app_context():
            assert pure.get_engine() is eng1
            assert set(pure.get_engines()) == {"default", "analytics"}
            s_def = pure.get_session_for_bind("default")
            s_ana = pure.get_session_for_bind("analytics")
            assert s_def is not s_ana
            with pytest.raises(KeyError, match="Unknown SQLAlchemy bind_key"):
                pure.get_session_for_bind("missing")

        # resolve_adapter branches
        assert resolve_adapter(pure) is pure
        assert isinstance(resolve_adapter(eng1), PureSQLAlchemyAdapter)
        assert isinstance(resolve_adapter(sf_only), PureSQLAlchemyAdapter)
        with pytest.raises(TypeError, match="Unsupported db argument"):
            resolve_adapter("not-a-db")

        # Mock Flask-SQLAlchemy object multi-bind + outside-app-context get_engine/get_engines/dispose
        class _FakeFSA:
            def __init__(self, flask_app: Flask, default_eng: Any, bind_eng: Any) -> None:
                self.app = flask_app
                self._default_eng = default_eng
                self.engines = {None: default_eng, "reporting": bind_eng}
                self.session = sessionmaker(bind=default_eng)()

            @property
            def engine(self) -> Any:
                return self._default_eng

        fake_fsa = _FakeFSA(app, eng1, eng2)
        fsa_adapter = resolve_adapter(fake_fsa)
        assert isinstance(fsa_adapter, FlaskSQLAlchemyAdapter)
        assert isinstance(fsa_adapter, ORMAdapter)
        fsa_adapter.register_teardown(app)
        assert fsa_adapter.get_engine() is eng1
        assert set(fsa_adapter.get_engines()) == {"default", "reporting"}
        with app.app_context():
            s_rep = fsa_adapter.get_session_for_bind("reporting")
            assert s_rep.get_bind() is eng2
            with pytest.raises(KeyError, match="Unknown SQLAlchemy bind_key"):
                fsa_adapter.get_session_for_bind("nope")
        fake_fsa.session.close()
        fsa_adapter.dispose()

        # Rich PK codec round-trip (UUID, Enum value & name, date, datetime, Decimal) + error cases
        rich_meta = introspect_model(PkRichModel)
        uid = uuid.uuid4()
        pk_tuple = (uid, FltTier.PRO, date(2026, 4, 5), datetime(2026, 4, 5, 10, 30), Decimal("12.34"))
        encoded = encode_pk(pk_tuple)
        assert encoded.startswith("ck:")
        assert decode_pk(encoded, rich_meta) == pk_tuple

        # Enum coercion by member name, bool rejection for int, non-finite Decimal rejection, empty/malformed PK
        assert coerce_pk_value("PRO", rich_meta.fields_by_name["id_enum"]) is FltTier.PRO
        assert coerce_pk_value(FltTier.FREE, rich_meta.fields_by_name["id_enum"]) is FltTier.FREE
        assert coerce_pk_value(uid, rich_meta.fields_by_name["id_uuid"]) == uid
        with pytest.raises(InvalidPKError):
            coerce_pk_value("", rich_meta.fields_by_name["id_uuid"])
        with pytest.raises(InvalidPKError):
            coerce_pk_value("NaN", rich_meta.fields_by_name["id_dec"])
        with pytest.raises(InvalidPKError):
            coerce_pk_value(True, introspect_model(FltOrg).primary_keys[0])
        with pytest.raises(InvalidPKError):
            decode_pk("", rich_meta)
        with pytest.raises(InvalidPKError):
            decode_pk("not-ck", rich_meta)
        with pytest.raises(InvalidPKError):
            decode_pk("ck:!!!bad!!!", rich_meta)
        with pytest.raises(InvalidPKError):
            decode_pk(encode_pk((1, 2)), rich_meta)  # arity mismatch (2 vs 5)

        # Single PK with slash / reserved prefix escaping
        str_meta = introspect_model(PkSingleStr)
        raw_slug = "pk:team/alpha"
        enc_slug = encode_pk((raw_slug,))
        assert enc_slug.startswith("pk:")
        assert decode_pk(enc_slug, str_meta) == (raw_slug,)


def test_sql_console_lexer_redaction_and_query_dialect_regressions() -> None:
    from flask_deck.query import build_search_clause

    # 1. SQL Console dialect-specific lexer bypass & redaction regressions
    # SQLite [...] bracket-quoted identifier containing '--' must NOT comment out trailing SQL
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only|forbidden|sensitive"):
        validate_readonly_sql(
            "SELECT 1 AS [--] ; DROP TABLE flt_orders",
            dialect_name="sqlite",
        )
    with pytest.raises(ValueError, match=r"read-only|forbidden|sensitive|blocked"):
        validate_readonly_sql(
            "SELECT 1 AS [--] UNION SELECT password_hash FROM _flask_deck_users",
            dialect_name="sqlite",
        )

    # Dollar-quoting is rejected on non-PostgreSQL dialects and mid-identifier on PostgreSQL
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
        validate_readonly_sql("SELECT $q$; DROP TABLE flt_orders$q$", dialect_name="sqlite")
    with pytest.raises(ValueError, match=r"Multiple SQL|read-only"):
        validate_readonly_sql("SELECT a$x$; DROP TABLE flt_orders$x$", dialect_name="postgresql")

    # MySQL \" escape inside double-quoted literal/identifier rejected
    with pytest.raises(ValueError, match=r"Backslash|escape|Multiple SQL|read-only"):
        validate_readonly_sql('SELECT "a\\" ; DROP TABLE flt_orders"', dialect_name="mysql")

    # PostgreSQL U&'...' / U&"..." Unicode escape literals/identifiers rejected
    with pytest.raises(ValueError, match="Unicode escape"):
        validate_readonly_sql("SELECT U&'abc'", dialect_name="postgresql")
    with pytest.raises(ValueError, match="Unicode escape"):
        validate_readonly_sql('SELECT U&"abc"', dialect_name="postgresql")

    # Space-padded mysql . user and dangerous MySQL functions blocked
    with pytest.raises(ValueError, match="security table"):
        validate_readonly_sql("SELECT * FROM mysql . user", dialect_name="mysql")
    for fn_sql in (
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT SLEEP(5)",
        "SELECT BENCHMARK(100000, SHA1('a'))",
    ):
        with pytest.raises(ValueError, match="Blocked"):
            validate_readonly_sql(fn_sql, dialect_name="mysql")

    # Column names ending in '_from' must not truncate SELECT projection redaction scanning
    assert _find_sensitive_indices_from_sql(
        "SELECT valid_from, password_hash AS x FROM flt_orders",
        ("valid_from", "x"),
        (),
    ) == {1}

    # 2. Query dialect compilation & coercion bounds regressions
    class _DialectBase(DeclarativeBase):
        pass

    class _DialectRow(_DialectBase):
        __tablename__ = "dialect_rows"
        id: Mapped[int] = mapped_column(primary_key=True)
        payload_json: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
        payload_jsonb: Mapped[dict[str, Any] | None] = mapped_column(postgresql.JSONB, nullable=True)
        score: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
        amount: Mapped[Decimal | None] = mapped_column(sa.Numeric(10, 2), nullable=True)
        created_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    d_meta = introspect_model(_DialectRow)

    # PostgreSQL has_key on sa.JSON & nested JSONB compiles json_typeof / jsonb_typeof IS NOT NULL
    pg_json_hk = build_filter_condition(
        d_meta, "payload_json", "nullable", op="has_key", dialect_name="postgresql"
    )
    assert pg_json_hk is not None
    pg_json_sql = str(pg_json_hk.compile(dialect=postgresql.dialect())).lower()
    assert "json_typeof" in pg_json_sql and "is not null" in pg_json_sql

    pg_nested_hk = build_filter_condition(
        d_meta, "payload_jsonb", "tier.nullable", op="has_key", dialect_name="postgresql"
    )
    assert pg_nested_hk is not None
    pg_nested_sql = str(pg_nested_hk.compile(dialect=postgresql.dialect())).lower()
    assert "jsonb_typeof" in pg_nested_sql and "is not null" in pg_nested_sql

    # MySQL json_contains with None & hyphenated segment quotes path segments and checks JSON_TYPE = 'NULL'
    my_null = build_filter_condition(
        d_meta, "payload_json", '{"foo-bar": null}', op="json_contains", dialect_name="mysql"
    )
    assert my_null is not None
    my_null_compiled = my_null.compile(
        dialect=mysql.dialect(), compile_kwargs={"literal_binds": True}
    )
    my_null_sql = str(my_null_compiled)
    assert '$."foo-bar"' in my_null_sql and "json_type" in my_null_sql.lower() and "'NULL'" in my_null_sql

    # 9999-12-31 lte filter on DateTime must not raise OverflowError
    max_dt_cond = build_filter_condition(d_meta, "created_at", "9999-12-31", op="lte")
    assert max_dt_cond is not None

    # Signed 64-bit integer overflow and non-finite float/Decimal rejected safely
    assert build_filter_condition(d_meta, "id", str(2**63), op="eq") is None
    assert build_filter_condition(d_meta, "id", str(-(2**63) - 1), op="eq") is None
    assert build_filter_condition(d_meta, "score", "nan", op="eq") is None
    assert build_filter_condition(d_meta, "score", "inf", op="eq") is None
    assert build_filter_condition(d_meta, "amount", "NaN", op="eq") is None
    assert build_filter_condition(d_meta, "amount", "Infinity", op="eq") is None

    # Oversized integer search tokens do not crash or bind int64 overflow (yields safe false predicate)
    search_clause, _ = build_search_clause(d_meta, ("id",), str(2**80))
    assert search_clause is not None
    assert str(search_clause.compile(dialect=sqlite.dialect())).strip().lower() in {"0 = 1", "false", "0"}

    # PK coercion & comma-containing PK encoding
    rich_meta = introspect_model(PkRichModel)
    with pytest.raises(InvalidPKError):
        coerce_pk_value("not-a-decimal", rich_meta.fields_by_name["id_dec"])
    with pytest.raises(InvalidPKError):
        coerce_pk_value(str(2**63), d_meta.primary_keys[0])

    str_meta = introspect_model(PkSingleStr)
    enc_comma = encode_pk(("NY,US",))
    assert enc_comma.startswith("pk:") and "," not in enc_comma
    assert decode_pk(enc_comma, str_meta) == ("NY,US",)


def test_search_scalar_predicate_modes_and_filter_operator_matrix() -> None:
    from flask_deck.query import build_search_clause, tokenize_search_query

    class _MatBase(DeclarativeBase):
        pass

    class _MatRow(_MatBase):
        __tablename__ = "mat_rows"
        id: Mapped[int] = mapped_column(primary_key=True)
        uid: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
        name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
        tier: Mapped[FltTier] = mapped_column(sa.Enum(FltTier), default=FltTier.FREE, nullable=False)
        active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
        score: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
        amount: Mapped[Decimal | None] = mapped_column(sa.Numeric(10, 2), nullable=True)
        tags: Mapped[list[str] | None] = mapped_column(postgresql.ARRAY(sa.String(32)), nullable=True)
        order_date: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
        created_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
        secret_key: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    m_meta = introspect_model(_MatRow)

    # 1. Tokenizer: quoted phrases, embedded spaces, max_tokens bound
    assert tokenize_search_query('alpha "hello world" beta') == ["alpha", "hello world", "beta"]
    assert tokenize_search_query('"unclosed quote', max_tokens=5) == ["unclosed quote"]
    assert len(tokenize_search_query("a b c d e f g", max_tokens=3)) == 3

    # 2. Scalar search modes (=exact, ^startswith, @fts, default contains) across all field types
    sample_uid = uuid.uuid4()
    for cols, term, dialect in (
        (("id", "=id"), "42", "sqlite"),
        (("id",), "not-an-int", "sqlite"),
        (("active",), "true", "sqlite"),
        (("active",), "false", "sqlite"),
        (("active",), "maybe", "sqlite"),
        (("uid", "=uid", "^uid"), str(sample_uid), "sqlite"),
        (("uid", "^uid"), "dead-beef", "sqlite"),
        (("=uid",), "partial-not-uuid", "sqlite"),
        (("tier", "=tier", "^tier"), "pro", "sqlite"),
        (("tier", "=tier", "^tier"), "FR", "sqlite"),
        (("name", "=name", "^name"), "Acme", "sqlite"),
        (("@name",), "distributed cluster", "postgresql"),
        (("amount", "=amount", "^amount"), "12.50", "sqlite"),
        (("secret_key",), "should-skip", "sqlite"),
    ):
        clause, _ = build_search_clause(m_meta, cols, term, dialect_name=dialect)
        assert clause is not None or cols == ("secret_key",)

    # 3. Filter operator matrix across null, array, bool, date/datetime, string, numeric, uuid, enum
    assert build_filter_condition(m_meta, "score", "1", op="null") is not None
    assert build_filter_condition(m_meta, "score", "0", op="null") is not None
    assert build_filter_condition(m_meta, "score", "invalid", op="null") is None
    assert build_filter_condition(m_meta, "tags", "gpu", op="array_contains", dialect_name="postgresql") is not None
    assert build_filter_condition(m_meta, "tags", "gpu", op="array_contains", dialect_name="sqlite") is not None
    assert build_filter_condition(m_meta, "tags", "gpu,edge", op="array_any", dialect_name="postgresql") is not None
    assert build_filter_condition(m_meta, "tags", "gpu,edge", op="array_any", dialect_name="sqlite") is not None
    assert build_filter_condition(m_meta, "tags", "   ", op="array_contains", dialect_name="sqlite") is None
    assert build_filter_condition(m_meta, "active", "true", op="eq") is not None
    assert build_filter_condition(m_meta, "active", "false", op="neq") is not None
    assert build_filter_condition(m_meta, "uid", str(sample_uid), op="eq") is not None
    assert build_filter_condition(m_meta, "tier", "pro", op="in") is not None
    assert build_filter_condition(m_meta, "tier", "free", op="not_in") is not None
    for op_name, val in (
        ("eq", "Acme"),
        ("neq", "Acme"),
        ("icontains", "cm"),
        ("istartswith", "Ac"),
        ("iendswith", "me"),
        ("in", "Acme,Beta"),
        ("not_in", "Gamma"),
    ):
        assert build_filter_condition(m_meta, "name", val, op=op_name) is not None
    for op_name, val in (
        ("gt", "10"),
        ("gte", "10"),
        ("lt", "50"),
        ("lte", "50"),
    ):
        assert build_filter_condition(m_meta, "amount", val, op=op_name) is not None
    for op_name, val in (
        ("gt", "2026-01-01"),
        ("gte", "2026-01-01"),
        ("lt", "2026-12-31"),
        ("lte", "2026-12-31"),
    ):
        assert build_filter_condition(m_meta, "order_date", val, op=op_name) is not None
        assert build_filter_condition(m_meta, "created_at", val, op=op_name) is not None
    assert build_filter_condition(m_meta, "nonexistent", "x", op="eq") is None
