"""Behavioral tests for query engine operators/pagination/views, IAM policies, MFA cipher rotation, i18n, formatters, and Deck guards."""

from __future__ import annotations

import enum
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    Deck,
    DeckConfig,
    DeckUser,
    ModelURL,
    ModelView,
    OpenAuthProvider,
    QuickTab,
    RBACAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
    display,
)
from flask_deck.exceptions import ConfigurationError, SecurityConfigurationError
from flask_deck.formatters import (
    CurrencyFormatter,
    DateTimeFormatter,
    FileFormatter,
    ImageFormatter,
    LinkFormatter,
    ProgressBarFormatter,
    RelativeTimeFormatter,
)
from flask_deck.i18n import (
    BabelTranslator,
    DictTranslator,
    format_locale_decimal,
    from_user_timezone,
    is_rtl_locale,
    is_valid_timezone,
    normalize_locale,
    to_user_timezone,
)
from flask_deck.iam import (
    CommonPasswordValidator,
    ComplexityValidator,
    MinimumLengthValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
)
from flask_deck.introspection import introspect_model
from flask_deck.mfa import (
    InMemoryMFAStore,
    MFAEnrollment,
    MFAStore,
    SecretCipher,
    SQLAlchemyMFAStore,
    compute_totp,
    generate_recovery_codes,
    generate_totp_secret,
)
from flask_deck.query import (
    build_dotted_filter_condition,
    build_filter_condition,
    compute_all_aggregates,
    compute_page_aggregates,
    compute_page_window,
    decode_cursor,
    encode_cursor,
    execute_calendar_query,
    execute_kanban_query,
    execute_list_query,
    execute_tree_query,
    tokenize_search_query,
)
from tests._backends import sqlite_memory_engine


class QState(enum.Enum):
    NEW = "new"
    DONE = "done"


class QBase(DeclarativeBase):
    pass


class QGroup(QBase):
    __tablename__ = "q_groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    tier: Mapped[str] = mapped_column(sa.String(30), nullable=False)
    api_secret: Mapped[str | None] = mapped_column(sa.String(60), nullable=True)


class QRecord(QBase):
    __tablename__ = "q_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    group_id: Mapped[int | None] = mapped_column(sa.ForeignKey("q_groups.id"), nullable=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    state: Mapped[QState] = mapped_column(sa.Enum(QState), default=QState.NEW, nullable=False)
    score: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("0.00"), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    due_on: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    meta: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)

    group: Mapped[QGroup | None] = relationship()


class QPgModel(QBase):
    __tablename__ = "q_pg_only"
    id: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[dict[str, Any] | None] = mapped_column(postgresql.JSONB, nullable=True)
    nums: Mapped[list[int] | None] = mapped_column(postgresql.ARRAY(sa.Integer), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(sa.ARRAY(sa.String(30)), nullable=True)


def test_query_engine_operators_cursor_pagination_aggregates_and_views() -> None:
    # 1. Tokenizer & cursor safety
    assert tokenize_search_query('hello "quoted phrase" world', max_tokens=2) == ["hello", "quoted phrase"]
    assert tokenize_search_query("") == []
    assert compute_page_window(1, 1) == ()
    assert compute_page_window(5, 8) == (1, 2, 3, 4, 5, 6, 7, 8)
    win = compute_page_window(10, 20)
    assert win[0] == 1 and None in win and win[-1] == 20

    sec = b"cursor-test-secret"
    tok = encode_cursor({"s": "id", "d": "desc", "pk": 5}, secret=sec)
    assert decode_cursor(tok, secret=sec) == {"s": "id", "d": "desc", "pk": 5}
    assert decode_cursor(tok + "tamper", secret=sec) is None
    assert decode_cursor("not-dotted", secret=sec) is None
    assert decode_cursor("x" * 5000, secret=sec) is None
    assert decode_cursor("!!!.000000000000000000000000", secret=sec) is None

    # 2. Filter condition compilation across SQLite / PostgreSQL / MySQL dialect variants
    meta = introspect_model(QRecord)
    pg_meta = introspect_model(QPgModel)

    assert build_filter_condition(meta, "unknown", "1") is None
    assert build_filter_condition(meta, "score", "1", op="null") is not None
    assert build_filter_condition(meta, "score", "0", op="null") is not None
    assert build_filter_condition(meta, "score", "bogus", op="null") is None
    assert build_filter_condition(meta, "score", "__null__", op="eq") is not None

    # JSON ops across dialects
    for dialect in ("sqlite", "postgresql", "mysql"):
        assert build_filter_condition(meta, "meta", "env=prod", op="path", dialect_name=dialect) is not None
        assert build_filter_condition(meta, "meta", "flag=true", op="path", dialect_name=dialect) is not None
        assert build_filter_condition(meta, "meta", "env", op="has_key", dialect_name=dialect) is not None
        assert build_filter_condition(
            meta, "meta", '{"env":"prod","nested":{"k":null}}', op="json_contains", dialect_name=dialect
        ) is not None
    assert build_filter_condition(meta, "meta", "no-equals", op="path") is None
    assert build_filter_condition(meta, "meta", "{bad-json", op="json_contains") is None
    assert build_filter_condition(meta, "meta", '{"a":[1,2]}', op="json_contains", dialect_name="sqlite") is None
    assert build_filter_condition(meta, "meta", '{"a":{}}', op="json_contains", dialect_name="sqlite") is None
    assert build_filter_condition(meta, "meta", "needle", op="contains") is not None
    assert build_filter_condition(meta, "meta", "x", op="unknown") is None
    assert build_filter_condition(pg_meta, "payload", "k", op="has_key", dialect_name="postgresql") is not None
    assert build_filter_condition(pg_meta, "payload", '{"a":1}', op="json_contains", dialect_name="postgresql") is not None

    # ARRAY ops across SQLite & PG
    assert build_filter_condition(pg_meta, "tags", "vip", op="array_contains", dialect_name="sqlite") is not None
    assert build_filter_condition(pg_meta, "tags", "vip,ops", op="array_any", dialect_name="sqlite") is not None
    assert build_filter_condition(pg_meta, "nums", "42", op="array_contains", dialect_name="postgresql") is not None
    assert build_filter_condition(pg_meta, "nums", "1,2", op="array_any", dialect_name="postgresql") is not None
    assert build_filter_condition(pg_meta, "nums", "notint", op="array_contains", dialect_name="postgresql") is None

    # Date presets, ranges, in/not_in, fts, neq, multi-select
    for preset in ("today", "7d", "30d", "month", "year", "no_date", "has_date"):
        assert build_filter_condition(meta, "created_at", preset, op="preset") is not None
        assert build_filter_condition(meta, "due_on", preset, op="preset") is not None
    assert build_filter_condition(meta, "created_at", "invalid", op="preset") is None
    assert build_filter_condition(meta, "created_at", "2026-01-15", op="lte") is not None
    for op in ("gt", "gte", "lt", "lte", "neq"):
        assert build_filter_condition(meta, "score", "10", op=op) is not None
    assert build_filter_condition(meta, "score", ["1", "2"], op="in") is not None
    assert build_filter_condition(meta, "score", "1,2", op="not_in") is not None
    assert build_filter_condition(meta, "name", "alpha beta", op="fts", dialect_name="sqlite") is not None
    assert build_filter_condition(meta, "name", "alpha", op="fts", dialect_name="postgresql") is not None
    assert build_filter_condition(meta, "name", "pre", op="startswith") is not None
    assert build_filter_condition(meta, "state", "new,done", op="eq") is not None

    # Dotted filter RBAC/sensitive barrier
    class GroupView(ModelView):
        model = QGroup
        slug = "groups"

    gv = GroupView()
    rbac = RBACAuthProvider(
        roles=[Role("limited", permissions=frozenset({"*"}), hidden_fields={"groups": frozenset({"tier"})})]
    )
    u_lim = DeckUser(id="u1", username="lim", roles=("limited",))
    cond_blocked, _ = build_dotted_filter_condition(
        meta, "group.tier", "pro", views_by_model={QGroup: gv}, user=u_lim, auth=rbac
    )
    assert cond_blocked is None
    cond_sens, _ = build_dotted_filter_condition(meta, "group.api_secret", "x")
    assert cond_sens is None
    alias_cache: dict[str, Any] = {}
    cond_ok, join_ok = build_dotted_filter_condition(meta, "group.tier", "pro", alias_cache=alias_cache)
    assert cond_ok is not None and join_ok is not None

    # 3. Live SQLite execution: cursor pagination (forward + backward + deleted fallback), aggregates, kanban, calendar, tree
    with sqlite_memory_engine() as eng:
        # Exclude PG-only table when creating SQLite tables
        QGroup.__table__.create(eng)
        QRecord.__table__.create(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        now = datetime.now(timezone.utc)
        with SessionLocal() as s:
            g1 = QGroup(tier="enterprise")
            s.add(g1)
            s.flush()
            recs = [
                QRecord(
                    id=1,
                    parent_id=None,
                    group_id=g1.id,
                    name="Root Node",
                    state=QState.NEW,
                    score=10,
                    amount=Decimal("10.00"),
                    created_at=now,
                    due_on=date(2026, 5, 10),
                    meta={"env": "prod"},
                ),
                QRecord(
                    id=2,
                    parent_id=1,
                    group_id=g1.id,
                    name="Child Node",
                    state=QState.DONE,
                    score=20,
                    amount=Decimal("20.00"),
                    created_at=now,
                    due_on=date(2026, 5, 11),
                ),
                QRecord(
                    id=3,
                    parent_id=4,  # cycle 3 <-> 4
                    group_id=g1.id,
                    name="Cycle A",
                    state=QState.NEW,
                    score=None,
                    amount=Decimal("30.00"),
                    created_at=now,
                    due_on=date(2026, 5, 12),
                ),
                QRecord(
                    id=4,
                    parent_id=3,  # cycle 3 <-> 4
                    group_id=g1.id,
                    name="Cycle B",
                    state=QState.DONE,
                    score=40,
                    amount=Decimal("40.00"),
                    created_at=now,
                    due_on=date(2026, 5, 13),
                ),
            ]
            s.add_all(recs)
            s.commit()

        class RecView(ModelView):
            model = QRecord
            slug = "records"

            @display(label="Weighted", ordering=lambda m: m.score)
            def weighted(self, obj: Any) -> int:
                return int(obj.score or 0) * 2

        rv = RecView()
        with SessionLocal() as s:
            # Cursor forward & backward with nullable sort column (score) + count_mode='none' & 'estimated'
            p1 = execute_list_query(
                s,
                meta,
                base_stmt=sa.select(QRecord),
                displayed_columns=("id", "name", "score"),
                searchable_columns=("^name", "=group.tier", "@name"),
                filterable_columns=frozenset({"state", "score", "group.tier", "meta"}),
                sortable_columns=frozenset({"id", "score", "weighted", "group.tier"}),
                quick_tabs=(QuickTab("all", "All"), QuickTab("done", "Done", {"state": "done"})),
                active_tab_key=None,
                search_term="",
                filter_params=(),
                sort_by="score",
                sort_dir="desc",
                default_sort=None,
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="none",
                cursor_secret=sec,
                show_full_result_count=True,
            )
            assert p1.pagination_mode == "cursor" and p1.has_next and p1.next_cursor is not None
            assert p1.total_known is False

            p2 = execute_list_query(
                s,
                meta,
                base_stmt=sa.select(QRecord),
                displayed_columns=("id", "name", "score"),
                searchable_columns=("name",),
                filterable_columns=frozenset({"state"}),
                sortable_columns=frozenset({"id", "score"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params=(),
                sort_by="score",
                sort_dir="desc",
                default_sort=None,
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="estimated",
                after_cursor=p1.next_cursor,
                cursor_secret=sec,
            )
            assert len(p2.items) == 2 and p2.has_prev and p2.prev_cursor is not None

            # Backward cursor navigation
            p_back = execute_list_query(
                s,
                meta,
                base_stmt=sa.select(QRecord),
                displayed_columns=("id", "name", "score"),
                searchable_columns=("name",),
                filterable_columns=frozenset({"state"}),
                sortable_columns=frozenset({"id", "score"}),
                quick_tabs=(),
                active_tab_key=None,
                search_term="",
                filter_params=(),
                sort_by="score",
                sort_dir="desc",
                default_sort=None,
                page=1,
                page_size=2,
                max_page_size=50,
                pagination_mode="cursor",
                count_mode="exact",
                before_cursor=p2.prev_cursor,
                cursor_secret=sec,
            )
            assert [x.id for x in p_back.items] == [x.id for x in p1.items]

            # Offset mode with @display callable ordering, dotted search, and show_full_result_count
            p_off = execute_list_query(
                s,
                meta,
                base_stmt=sa.select(QRecord),
                displayed_columns=("id", "name", "weighted"),
                searchable_columns=("^name", "=group.tier", "@name"),
                filterable_columns=frozenset({"state", "group.tier"}),
                sortable_columns=frozenset({"weighted", "group.tier"}),
                quick_tabs=(QuickTab("all", "All"), QuickTab("done", "Done", {"state": "done"})),
                active_tab_key="done",
                search_term="enterprise",
                filter_params=[("group.tier", "enterprise")],
                sort_by="weighted",
                sort_dir="desc",
                default_sort=None,
                page=1,
                page_size=10,
                max_page_size=50,
                display_fields=rv.display_fields,
                show_full_result_count=True,
            )
            assert p_off.total == 2 and p_off.full_total == 4

            # Aggregates (page & all)
            assert compute_page_aggregates([], {"score": "sum"}) == {}
            page_aggs = compute_page_aggregates(
                p_off.items, {"score": "sum", "amount": "avg", "id": "min", "active": "max", "bad": "median"}
            )
            assert page_aggs["score"] == ("SUM", 60.0) and page_aggs["amount"] == ("AVG", 30.0)
            all_aggs = compute_all_aggregates(
                s,
                meta,
                base_stmt=sa.select(QRecord),
                column_aggregates={"score": "sum", "amount": "max", "id": "min", "missing": "sum"},
                searchable_columns=("name",),
                search_term="Node",
                quick_tabs=(QuickTab("all", "All"), QuickTab("new", "New", {"state": "new"})),
                active_tab_key="new",
            )
            assert all_aggs["score"] == ("SUM", 10.0)

            # Kanban, Calendar, and cycle-safe Tree queries
            assert execute_kanban_query(
                s, meta, base_stmt=sa.select(QRecord), kanban_column="name", card_fields=("name",),
                searchable_columns=(), filterable_columns=frozenset(), search_term="", filter_params=()
            ) == []
            kb = execute_kanban_query(
                s, meta, base_stmt=sa.select(QRecord), kanban_column="state", card_fields=("name",),
                searchable_columns=("name",), filterable_columns=frozenset(), search_term="Node", filter_params=()
            )
            assert len(kb) == 2

            cal_bad = execute_calendar_query(s, meta, base_stmt=sa.select(QRecord), date_field="name")
            assert cal_bad["weeks"] == []
            cal_ok = execute_calendar_query(
                s, meta, base_stmt=sa.select(QRecord), date_field="due_on", month_str="2026-05",
                searchable_columns=("name",), search_term="Node",
            )
            assert cal_ok["month_key"] == "2026-05" and cal_ok["weeks"]

            assert execute_tree_query(s, meta, base_stmt=sa.select(QRecord), parent_field="missing") == []
            tree_nodes = execute_tree_query(s, meta, base_stmt=sa.select(QRecord), parent_field="parent_id")
            assert len(tree_nodes) == 4  # includes both Root->Child AND pure cycle 3<->4 safely!


def test_iam_password_policies_mfa_cipher_rotation_i18n_formatters_and_deck_guards() -> None:
    # 1. Password validators & SQLAlchemyAuthProvider strict policy + last-superuser protection
    assert MinimumLengthValidator(10).help_text()
    assert CommonPasswordValidator(extra_common=("customweak",)).validate("customweak") is not None
    assert NumericPasswordValidator().help_text()
    sim = UserAttributeSimilarityValidator()
    assert sim.validate("alice123!", username="alice", email="alice@x.com") is not None
    assert sim.help_text()
    comp = ComplexityValidator()
    assert comp.validate("alllower") is not None
    assert comp.help_text()

    with sqlite_memory_engine() as eng:
        iam = SQLAlchemyAuthProvider(eng, strict_password_policy=True)
        assert len(iam.password_help_texts()) == 5
        with pytest.raises(ValueError, match="empty"):
            iam.create_group(name="  ")
        g1 = iam.create_group(name="ops", label="Ops", permissions=frozenset({"items:view"}))
        with pytest.raises(ValueError, match="already exists"):
            iam.create_group(name="OPS")
        with pytest.raises(KeyError):
            iam.update_group("missing", label="X")
        iam.update_group(
            g1.id,
            label="Ops 2",
            description="desc",
            permissions=frozenset({"items:view", "items:edit"}),
            hidden_fields={"items": frozenset({"a"})},
            readonly_fields={"items": frozenset({"b"})},
            masked_fields={"items": frozenset({"c"})},
        )

        with pytest.raises(ValueError, match="empty"):
            iam.create_user(username=" ", password="Strong#Password123")
        with pytest.raises(ValueError, match="Password is required"):
            iam.create_user(username="nopwd")
        u_super = iam.create_user(
            username="root",
            password="V3ry!Str0ng#Pass99",
            email="root@corp.test",
            is_superuser=True,
            group_ids=[g1.id],
            direct_permissions=["audit:view"],
        )
        u_norm = iam.create_user(
            username="alice",
            password="X9!Valid#Cipher88",
            email="alice@corp.test",
            is_superuser=False,
            group_ids=[g1.id],
        )
        with pytest.raises(ValueError, match="already exists"):
            iam.create_user(username="root", password="V3ry!Str0ng#Pass77")

        # Paginated filtering across status / group_id / overflow page
        items_p, total_p = iam.list_users_paginated(q="ali", status="active", group_id=g1.id, page=99)
        assert total_p == 1 and items_p[0].username == "alice"
        assert iam.list_users_paginated(status="inactive")[1] == 0
        assert iam.list_users_paginated(status="superuser")[1] == 1

        # Last active superuser cannot be demoted, deactivated, bulk-deactivated, or deleted
        with pytest.raises(ValueError, match="last active superuser"):
            iam.update_user(u_super.id, is_superuser=False)
        with pytest.raises(ValueError, match="last active superuser"):
            iam.bulk_set_active([u_super.id], is_active=False)
        with pytest.raises(ValueError, match="last active superuser"):
            iam.delete_user(u_super.id)
        assert iam.bulk_set_active([], is_active=False) == []
        iam.bulk_set_active([u_norm.id], is_active=False)
        assert iam.get_user_by_id(u_norm.id) is None  # inactive
        iam.bulk_set_active([u_norm.id], is_active=True)

        # Password change, admin reset, and reset token reuse / invalid checks
        ok_bad, _ = iam.change_password(u_norm.id, "wrong", "Str0ng!NewPass99")
        assert not ok_bad
        ok_weak, _ = iam.change_password(u_norm.id, "X9!Valid#Cipher88", "weak")
        assert not ok_weak
        ok_good, _ = iam.change_password(u_norm.id, "X9!Valid#Cipher88", "Z7!Fresh#Secret42")
        assert ok_good
        with pytest.raises(KeyError):
            iam.admin_reset_password("missing", "Str0ng!Reset99")
        assert iam.create_password_reset_token("   ") is None
        assert iam.verify_password_reset_token("   ") is None
        res_pair = iam.create_password_reset_token("alice@corp.test")
        assert res_pair is not None
        _, raw_rt = res_pair
        ok_r1, _, _ = iam.consume_password_reset_token(raw_rt, "Str0ng!FinalPass99")
        assert ok_r1 is True
        ok_r2, _, _ = iam.consume_password_reset_token(raw_rt, "Str0ng!FinalPass99")
        assert ok_r2 is False
        iam.delete_user("nonexistent")
        iam.delete_group(g1.id)
        iam.reset_all()

    # 2. MFA SecretCipher encryption, key rotation, and replay/recovery verification
    old_k = "old-encryption-key-material-32b!"
    new_k = "new-encryption-key-material-32b!"
    c_old = SecretCipher(old_k)
    sec_raw = generate_totp_secret()
    enc_old = c_old.encrypt(sec_raw)
    assert enc_old.startswith("enc:v1:")
    assert c_old.encrypt(enc_old) == enc_old  # idempotent
    c_rot = SecretCipher(new_k, fallback_keys=(old_k,))
    plain, needs_rot = c_rot.decrypt_with_status(enc_old)
    assert plain == sec_raw and needs_rot is True
    with pytest.raises(ValueError, match="encryption_key is not set"):
        SecretCipher(None).decrypt(enc_old)
    with pytest.raises(ValueError, match="Unable to decrypt"):
        SecretCipher("wrong-key-material-32-bytes-long!").decrypt(enc_old)
    assert SecretCipher._try_decrypt_with(old_k, "short") is None
    assert SecretCipher._try_decrypt_with(old_k, "%%%not-b64%%%") is None

    codes, hashes = generate_recovery_codes(4)
    with sqlite_memory_engine() as eng:
        # Store legacy plaintext first, then rotate with primary key
        plain_sql_mfa = SQLAlchemyMFAStore(eng)
        plain_sql_mfa.save(MFAEnrollment(user_id="u1", secret=sec_raw, enabled=True, recovery_hashes=hashes))
        assert plain_sql_mfa.rotate_secrets() == 0  # disabled cipher
        rot_sql_mfa = SQLAlchemyMFAStore(eng, encryption_key=new_k)
        assert rot_sql_mfa.rotate_secrets() == 1
        assert rot_sql_mfa.verify_and_record("missing", "123456") is False
        totp_now = compute_totp(sec_raw, timestamp=1_700_000_000.0)
        assert rot_sql_mfa.verify_and_record("u1", totp_now, timestamp=1_700_000_000.0) is True
        assert rot_sql_mfa.verify_and_record("u1", totp_now, timestamp=1_700_000_000.0) is False  # replay blocked!
        assert rot_sql_mfa.verify_and_record("u1", codes[0]) is True
        assert rot_sql_mfa.verify_and_record("u1", codes[0]) is False  # single-use recovery consumed!

        # Same rotation on InMemoryMFAStore
        mem_mfa = InMemoryMFAStore()
        mem_mfa.save(MFAEnrollment(user_id="u1", secret=sec_raw, enabled=True, recovery_hashes=hashes))
        assert mem_mfa.rotate_secrets() == 0
        mem_mfa._cipher = SecretCipher(new_k)
        assert mem_mfa.rotate_secrets() == 1
        assert mem_mfa.verify_and_record("u1", codes[1]) is True

    # 3. i18n helpers & BabelTranslator
    assert normalize_locale(None) == "en"
    assert is_rtl_locale("ar-SA") is True
    assert is_valid_timezone(None) is False
    assert is_valid_timezone("UTC") is True
    naive_dt = datetime(2026, 6, 1, 12, 0)
    assert to_user_timezone(naive_dt, tz_name="Invalid/Zone").tzinfo == timezone.utc
    assert from_user_timezone(naive_dt, tz_name="Europe/Istanbul", store_naive_utc=True).tzinfo is None
    assert format_locale_decimal(Decimal("-1234.56"), locale="tr") == "-1.234,56"
    tr = DictTranslator(default_locale="en", extra_catalogs={"fr": {"Hello {name}": "Bonjour {name}"}})
    assert tr.translate("Hello {name}", name="Ada") == "Hello Ada"
    assert tr.translate("Broken {brace", bad=1) == "Broken {brace"
    fake_babel = SimpleNamespace(get_locale=lambda: "tr_TR", gettext=lambda m, **kw: m)
    btr = BabelTranslator(babel_module=fake_babel)
    assert btr.get_locale() == "tr" and btr.is_rtl() is False
    assert btr.translate("Hello {name}", name="Ada") == "Hello Ada"

    # 4. Formatters edge cases
    cf = CurrencyFormatter(currency="EUR", divisor=100)
    assert "€" in str(cf.format(12345))
    assert "nan" in str(cf.format("nan")).lower()
    assert "bad" in str(cf.format("bad"))
    rtf = RelativeTimeFormatter()
    now = datetime.now(timezone.utc)
    for delta in (
        timedelta(seconds=30),
        timedelta(minutes=5),
        timedelta(hours=2),
        timedelta(days=5),
        timedelta(days=60),
        timedelta(seconds=-30),
        timedelta(minutes=-5),
        timedelta(hours=-2),
        timedelta(days=-5),
        timedelta(days=-60),
    ):
        assert rtf.format(now + delta)
    assert "2026-01-01" in str(rtf.format(date(2026, 1, 1)))
    assert "raw" in str(rtf.format("raw"))
    dtf = DateTimeFormatter()
    assert "—" in str(dtf.format(None))
    assert "2026-01-01" in str(dtf.format(date(2026, 1, 1)))
    assert "raw" in str(dtf.format("raw"))
    pbf = ProgressBarFormatter(warn_below=50, danger_below=20)
    assert "dk-prog-fill-danger" in str(pbf.format(10))
    assert "dk-prog-fill-warn" in str(pbf.format(40))
    assert "dk-prog-fill-ok" in str(pbf.format(90))
    assert "bad" in str(pbf.format("bad"))
    assert "nan" in str(pbf.format(float("nan"))).lower()
    lf = LinkFormatter()
    assert "<a " not in str(lf.format("javascript:alert(1)"))
    assert 'href="https://example.com"' in str(lf.format("https://example.com"))
    assert ImageFormatter().format_with_url("k", "/img.png")
    assert FileFormatter().format_with_url("k", "/f.pdf")

    # 5. Deck startup & registration guards
    with pytest.raises(ValueError, match="not both"):
        Deck(config=DeckConfig(), title="Conflict")
    with pytest.raises(ValueError, match="requires a Flask-SQLAlchemy"):
        Deck(Flask(__name__))

    with sqlite_memory_engine() as eng:
        prod_app = Flask(__name__)
        prod_app.debug = False
        prod_app.testing = False
        with pytest.raises(SecurityConfigurationError, match="AuthProvider"):
            Deck(prod_app, engine=eng)
        with pytest.raises(SecurityConfigurationError, match="secret_key"):
            Deck(prod_app, engine=eng, auth=OpenAuthProvider())

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "deck-guards-secret-32-bytes-long!"
        app.config["TESTING"] = True
        with Deck(
            app,
            engine=eng,
            auth=OpenAuthProvider(),
            read_only=True,
            strict_view_checks=True,
            enable_sql_console=True,
            enable_rest_api=True,
        ) as deck:
            class ReservedSlugView(ModelView):
                model = QGroup
                slug = "_audit"

            class BadSlugView(ModelView):
                model = QGroup
                slug = "bad/slug"

            class StrictBrokenView(ModelView):
                model = QGroup
                slug = "strict-broken"
                columns = ("nonexistent_col",)

            class CustomURLView(ModelView):
                model = QGroup
                slug = "custom-groups"

                def get_urls(self) -> tuple[ModelURL, ...]:
                    return (
                        ModelURL(
                            rule="ping",
                            endpoint="ping",
                            handler=lambda: "pong",
                        ),
                    )

            with pytest.raises(ValueError, match="conflicts with a built-in"):
                deck.register(ReservedSlugView)
            with pytest.raises(ValueError, match="Invalid Deck model slug"):
                deck.register(BadSlugView)
            with pytest.raises(ConfigurationError):
                deck.register(StrictBrokenView)

            deck.register(CustomURLView)
            with pytest.raises(ValueError, match="Duplicate Deck model slug"):
                deck.register(CustomURLView)

            # Custom ModelURL mounted dynamically after init_app works under Deck security boundary
            r_ping = app.test_client().get("/admin/custom-groups/ping")
            assert r_ping.status_code == 200 and r_ping.get_data(as_text=True) == "pong"

            # Site-wide add_action / disable_action
            deck.add_action(lambda recs, form, user: "ok", name="global_ping")
            assert "global_ping" in deck.views["custom-groups"].get_actions(None)
            deck.disable_action("global_ping")
            assert "global_ping" not in deck.views["custom-groups"].get_actions(None)

    # 6. Base MFAStore.verify_and_record contract (TOTP replay protection + single-use recovery codes)
    class MinimalMFAStore(MFAStore):
        def __init__(self) -> None:
            self._data: dict[str, MFAEnrollment] = {}

        def get(self, user_id: str) -> MFAEnrollment | None:
            return self._data.get(user_id)

        def save(self, enrollment: MFAEnrollment) -> None:
            self._data[enrollment.user_id] = enrollment

        def delete(self, user_id: str) -> None:
            self._data.pop(user_id, None)

    min_mfa = MinimalMFAStore()
    assert min_mfa.verify_and_record("missing", "123456") is False
    min_sec = generate_totp_secret()
    min_codes, min_hashes = generate_recovery_codes(4)
    min_mfa.save(MFAEnrollment(user_id="u1", secret=min_sec, enabled=True, recovery_hashes=min_hashes))
    t_code = compute_totp(min_sec, timestamp=1_700_000_000.0)
    assert min_mfa.verify_and_record("u1", t_code, timestamp=1_700_000_000.0) is True
    assert min_mfa.verify_and_record("u1", t_code, timestamp=1_700_000_000.0) is False  # replay blocked
    assert min_mfa.verify_and_record("u1", min_codes[0]) is True
    assert min_mfa.verify_and_record("u1", min_codes[0]) is False  # recovery single-use
    assert min_mfa.verify_and_record("u1", "WRONG-CODE") is False

    # 7. ModelView format_cell array chip overflow (+N) & format_record_repr masked display_column
    class PgView(ModelView):
        model = QPgModel
        slug = "pg-items"
        display_column = "id"
        column_formatters = MappingProxyType({"nums": lambda v, _o: f"count={len(v or [])}"})

    pv = PgView()
    auth_m = RBACAuthProvider(
        roles=[Role("m", permissions=frozenset({"*"}), masked_fields={"pg-items": frozenset({"id"})})]
    )
    u_m = DeckUser(id="m1", username="m", roles=("m",))
    pg_obj = QPgModel(id=7, tags=["a", "b", "c", "d", "e", "f"], nums=[1, 2])
    pg_empty = QPgModel(id=8, tags=[])
    assert "+2" in str(pv.format_cell("tags", pg_obj, auth=auth_m, user=u_m))
    assert "—" in str(pv.format_cell("tags", pg_empty, auth=auth_m, user=u_m))
    assert pv.format_cell("nums", pg_obj, auth=auth_m, user=u_m) == "count=2"
    assert "••••" in pv.format_record_repr(pg_obj, auth=auth_m, user=u_m)
