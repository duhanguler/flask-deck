from __future__ import annotations

import enum
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckUser,
    InlineModelView,
    InMemoryAuditStore,
    ModelView,
    QuickTab,
    RBACAuthProvider,
    Role,
    action,
)

_CSRF_RE = re.compile(r'name="_csrf_token"\s+value="([^"]+)"|name="deck-csrf"\s+content="([^"]+)"')


def extract_csrf(html: str) -> str:
    m = _CSRF_RE.search(html)
    assert m is not None, "CSRF token not found in response HTML"
    return m.group(1) or m.group(2)


def login_as(client: FlaskClient, username: str, password: str, prefix: str = "/admin") -> str:
    resp = client.get(f"{prefix}/login")
    assert resp.status_code == 200
    token = extract_csrf(resp.get_data(as_text=True))
    post = client.post(
        f"{prefix}/login",
        data={"username": username, "password": password, "_csrf_token": token},
        follow_redirects=False,
    )
    assert post.status_code in {302, 303}, post.get_data(as_text=True)
    dash = client.get(f"{prefix}/")
    assert dash.status_code == 200
    return extract_csrf(dash.get_data(as_text=True))


@contextmanager
def count_sql_queries(engine: Engine) -> Iterator[list[str]]:
    statements: list[str] = []

    def _listener(
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", _listener)
    try:
        yield statements
    finally:
        sa.event.remove(engine, "before_cursor_execute", _listener)


# ---- Pure SQLAlchemy 2.0 Test Models ----


class StatusEnum(enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class SampleBase(DeclarativeBase):
    pass


item_tag_table = sa.Table(
    "test_item_tags",
    SampleBase.metadata,
    sa.Column("item_id", sa.ForeignKey("test_items.id"), primary_key=True),
    sa.Column("tag_id", sa.ForeignKey("test_tags.id"), primary_key=True),
)


class Tenant(SampleBase):
    __tablename__ = "test_tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(sa.String(60), unique=True, index=True, nullable=False)

    def __str__(self) -> str:
        return self.name


class Tag(SampleBase):
    __tablename__ = "test_tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(50), unique=True, nullable=False)

    def __str__(self) -> str:
        return self.name


class Item(SampleBase):
    __tablename__ = "test_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(sa.String(120), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(sa.String(140), nullable=True)
    website_url: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    password_hash: Mapped[str] = mapped_column(sa.String(128), default="secret-hash-val")
    api_token: Mapped[str] = mapped_column(sa.String(128), default="tok_live_secret")
    status: Mapped[StatusEnum] = mapped_column(
        sa.Enum(StatusEnum), default=StatusEnum.DRAFT, index=True
    )
    price: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("0.00"))
    quantity: Mapped[int] = mapped_column(sa.Integer, default=1)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    external_uuid: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, nullable=True)
    due_date: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    description: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    tenant_id: Mapped[int] = mapped_column(sa.ForeignKey("test_tenants.id"), index=True)

    tenant: Mapped[Tenant] = relationship()
    tags: Mapped[list[Tag]] = relationship(secondary=item_tag_table)
    notes: Mapped[list[ItemNote]] = relationship(back_populates="item", cascade="all, delete-orphan")

    def __str__(self) -> str:
        return f"{self.code} ({self.title})"


class ItemNote(SampleBase):
    __tablename__ = "test_item_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("test_items.id"), index=True)
    body: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    item: Mapped[Item] = relationship(back_populates="notes")


class CompositeMembership(SampleBase):
    __tablename__ = "test_memberships"
    tenant_id: Mapped[int] = mapped_column(primary_key=True)
    user_code: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    role_name: Mapped[str] = mapped_column(sa.String(32), default="member")


class ItemNoteInline(InlineModelView):
    model = ItemNote
    columns = ("body",)


class ItemView(ModelView):
    model = Item
    columns = ("code", "title", "email", "tenant", "status", "price", "is_active")
    searchable_columns = ("code", "title", "tenant.name")
    filterable_columns = ("status", "is_active", "tenant_id", "price", "created_at")
    inline_editable_columns = ("is_active", "status")
    inlines = (ItemNoteInline,)
    import_key_columns = ("code",)
    quick_tabs = (
        QuickTab("all", "All"),
        QuickTab("active", "Active", filters={"status": "active"}, tone="ok"),
        QuickTab("draft", "Draft", filters={"status": "draft"}, tone="warn"),
        QuickTab("archived", "Archived", filters={"status": "archived"}, tone="neutral"),
    )

    def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
        if user is not None and not user.is_superuser and user.tenant_id is not None:
            return stmt.where(Item.tenant_id == user.tenant_id)
        return stmt

    @action("activate", label="Activate Selected", confirm=True)
    def activate(self, records: list[Item], form_data: Any, user: Any) -> str:
        for r in records:
            r.status = StatusEnum.ACTIVE
        return f"Activated {len(records)} items."


@pytest.fixture()
def sa_bundle() -> Iterator[tuple[Flask, Deck, Engine, sessionmaker[Any], InMemoryAuditStore]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key-with-at-least-thirty-two-bytes!!"
    app.config["TESTING"] = True

    engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SampleBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as sess:
        t1 = Tenant(name="Alpha Corp", slug="alpha")
        t2 = Tenant(name="Beta Corp", slug="beta")
        tag1 = Tag(name="urgent")
        tag2 = Tag(name="billing")
        sess.add_all([t1, t2, tag1, tag2])
        sess.flush()

        it1 = Item(
            code="ITM-001",
            title="Primary Server",
            email="ops@alpha.io",
            website_url="https://alpha.io",
            status=StatusEnum.ACTIVE,
            price=Decimal("199.50"),
            quantity=3,
            is_active=True,
            tenant_id=t1.id,
            tags=[tag1],
            description="Heavy text blob " * 50,
            payload={"tier": "gold"},
        )
        it2 = Item(
            code="ITM-002",
            title="Backup Node",
            email="sec@beta.io",
            status=StatusEnum.DRAFT,
            price=Decimal("49.00"),
            quantity=1,
            is_active=False,
            tenant_id=t2.id,
            description="Beta tenant record",
        )
        sess.add_all([it1, it2])
        sess.flush()
        sess.add_all(
            [
                ItemNote(item_id=it1.id, body="Alpha note 1"),
                ItemNote(item_id=it2.id, body="Beta confidential note"),
                CompositeMembership(tenant_id=1, user_code="u-10", role_name="owner"),
            ]
        )
        sess.commit()

    roles = [
        Role(name="admin", permissions=frozenset({"*"})),
        Role(
            name="tenant_editor",
            permissions=frozenset(
                {
                    "items:view",
                    "items:create",
                    "items:edit",
                    "items:export",
                    "items:import",
                    "tenants:view",
                    "audit:view",
                    "rbac:view",
                }
            ),
            masked_fields={"items": frozenset({"email"})},
            readonly_fields={"items": frozenset({"price"})},
            hidden_fields={"items": frozenset({"quantity"})},
        ),
        Role(
            name="readonly",
            permissions=frozenset({"*:view", "audit:view", "rbac:view"}),
        ),
    ]

    auth = RBACAuthProvider(
        roles=roles,
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-admin",
                    username="admin",
                    display_name="Admin",
                    roles=("admin",),
                    is_superuser=True,
                ),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-alpha",
                    username="alpha_editor",
                    display_name="Alpha Editor",
                    roles=("tenant_editor",),
                    tenant_id=1,
                ),
                password="alpha-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="u-ro",
                    username="viewer",
                    display_name="Viewer",
                    roles=("readonly",),
                    tenant_id=1,
                ),
                password="viewer-password",
            ),
        ],
    )

    audit_store = InMemoryAuditStore(max_entries=200)
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        audit_store=audit_store,
        title="Test Deck",
    )
    deck.register(Tenant, Tag, ItemView, CompositeMembership)
    yield app, deck, engine, SessionLocal, audit_store
    engine.dispose()


@pytest.fixture()
def fsa_app() -> Iterator[tuple[Flask, SQLAlchemy, Deck]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "flask-sqlalchemy-test-secret-key-32bytes"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True

    db = SQLAlchemy(app)

    class WidgetModel(db.Model):  # type: ignore[name-defined,misc]
        __tablename__ = "fsa_widgets"
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(80), nullable=False, index=True)
        enabled = db.Column(db.Boolean, default=True, nullable=False)

    with app.app_context():
        db.create_all()
        db.session.add(WidgetModel(name="FSA Widget 1", enabled=True))
        db.session.commit()

    deck = Deck(app, db, allow_insecure_open=True, title="FSA Deck")
    deck.register(WidgetModel)
    yield app, db, deck
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
