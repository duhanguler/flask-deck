from __future__ import annotations

import contextlib
import enum
import hmac
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone, tzinfo
from types import MappingProxyType
from typing import Any, Literal
from zoneinfo import ZoneInfo

import sqlalchemy as sa
from flask import Flask, jsonify, redirect, request
from flask import session as flask_session
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)
from werkzeug.security import generate_password_hash

from flask_deck.api_keys import build_api_key_record
from flask_deck.approvals import ApprovalRequest
from flask_deck.audit import SQLAlchemyAuditStore, make_audit_entry
from flask_deck.auth import AUTH_USER_KEY
from flask_deck.branding import BrandConfig
from flask_deck.dashboard import (
    ActivityWidget,
    CalloutWidget,
    ChartWidget,
    DashboardContext,
    GaugeWidget,
    HeatmapWidget,
    KPIWidget,
    StatBarWidget,
    TableWidget,
    TimelineWidget,
    Widget,
)
from flask_deck.deck import Deck
from flask_deck.events import WebhookDeliveryRecord
from flask_deck.filters import (
    EmptyFieldListFilter,
    ListFilter,
    RangeListFilter,
    RelatedOnlyFieldListFilter,
)
from flask_deck.formatters import (
    AvatarFormatter,
    BadgeFormatter,
    BooleanIconFormatter,
    CodeFormatter,
    CurrencyFormatter,
    FileFormatter,
    ImageFormatter,
    ProgressBarFormatter,
    RelativeTimeFormatter,
)
from flask_deck.iam import SQLAlchemyAuthProvider
from flask_deck.jobs import JobContext, JobRecord, ThreadPoolJobBackend
from flask_deck.model_view import (
    ActionField,
    Fieldset,
    InlineModelView,
    ModelView,
    action,
    display,
)
from flask_deck.query import QuickTab
from flask_deck.saved_views import RecordNote, SavedViewRecord
from flask_deck.sessions import DECK_SID_SESSION_KEY, SessionRecord, SQLAlchemySessionStore
from flask_deck.sql_console import (
    SavedQueryRecord,
    execute_readonly_sql,
    extract_sql_chart_data,
)
from flask_deck.storage import FileFieldConfig, MemoryFileStorage, make_demo_png
from flask_deck.widgets import CodeWidget, ColorWidget, SliderWidget, TagInputWidget

DEMO_MEDIA_STORAGE = MemoryFileStorage()
_DEMO_PASSWORD_HASH = generate_password_hash("deck-demo-2026", method="pbkdf2:sha256:200000")
_DEMO_STATE_META = sa.MetaData()
_DEMO_STATE_TABLE = sa.Table(
    "_flask_deck_demo_state",
    _DEMO_STATE_META,
    sa.Column("key", sa.String(64), primary_key=True),
    sa.Column("value", sa.String(255), nullable=False),
)


class _EphemeralServerlessSessionStore(SQLAlchemySessionStore):
    """Demo-only SessionStore tolerating stateless serverless instances without shared DB."""

    def is_active(self, session_id: str) -> bool:
        if not session_id:
            return False
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table.c.revoked_at).where(self._table.c.session_id == session_id)
            ).first()
            if row is None:
                # Session was signed on another ephemeral microVM; trust signed cookie + timestamps.
                return True
            return row[0] is None

    def ensure_session(
        self,
        *,
        session_id: str,
        user_id: str,
        username: str,
        ip_address: str,
        user_agent: str,
    ) -> None:
        if not session_id:
            return
        with Session(self._engine) as sess:
            exists = sess.execute(
                sa.select(self._table.c.session_id).where(self._table.c.session_id == session_id)
            ).first()
            if exists is not None:
                return
        now = datetime.now(timezone.utc)
        self.register(
            SessionRecord(
                session_id=session_id,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=now,
                last_seen_at=now,
            )
        )


def _resolve_tz(tz_name: str) -> tzinfo:
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def reset_demo_app(app: Flask, *, force: bool = True) -> dict[str, Any]:
    """Reset the demo database and control-plane stores back to a fresh seeded state."""
    reset_fn = app.extensions.get("flask_deck_demo_reset")
    if not callable(reset_fn):
        raise RuntimeError("This Flask application was not created with create_demo_app().")
    result: dict[str, Any] = reset_fn(force=force)
    return result


class PlanTier(enum.Enum):
    STARTER = "starter"
    GROWTH = "growth"
    ENTERPRISE = "enterprise"


class UserRole(enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ENGINEER = "engineer"
    MEMBER = "member"


class ProductCategory(enum.Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORKING = "networking"
    ADDON = "addon"


class OrderStatus(enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    SHIPPED = "shipped"
    REFUNDED = "refunded"


class TicketPriority(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TicketStatus(enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class DemoBase(DeclarativeBase):
    pass


class Organization(DemoBase):
    __tablename__ = "demo_organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(sa.String(80), unique=True, index=True, nullable=False)
    plan: Mapped[PlanTier] = mapped_column(sa.Enum(PlanTier), default=PlanTier.STARTER, index=True)
    mrr_cents: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    seats_used: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    seats_limit: Mapped[int] = mapped_column(sa.Integer, default=10, nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    users: Mapped[list[User]] = relationship(back_populates="organization")
    orders: Mapped[list[Order]] = relationship(back_populates="organization")

    def __str__(self) -> str:
        return self.name


class User(DemoBase):
    __tablename__ = "demo_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(sa.String(120), nullable=False, index=True)
    email: Mapped[str] = mapped_column(sa.String(160), unique=True, index=True, nullable=False)
    role: Mapped[UserRole] = mapped_column(sa.Enum(UserRole), default=UserRole.MEMBER, index=True)
    password_hash: Mapped[str] = mapped_column(sa.String(255), default="pbkdf2:sha256:redacted")
    api_token: Mapped[str] = mapped_column(sa.String(128), default="sk_live_redacted_demo")
    organization_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_organizations.id"), index=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    organization: Mapped[Organization] = relationship(back_populates="users")

    def __str__(self) -> str:
        return f"{self.full_name} ({self.email})"


class Product(DemoBase):
    __tablename__ = "demo_products"

    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(sa.String(40), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(140), nullable=False, index=True)
    category: Mapped[ProductCategory] = mapped_column(
        sa.Enum(ProductCategory), default=ProductCategory.COMPUTE, index=True
    )
    price_cents: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    stock_pct: Mapped[int] = mapped_column(sa.Integer, default=100, nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    thumbnail_path: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    spec_sheet_path: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __str__(self) -> str:
        return f"{self.sku} · {self.name}"


class Order(DemoBase):
    __tablename__ = "demo_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    order_number: Mapped[str] = mapped_column(sa.String(32), unique=True, index=True, nullable=False)
    organization_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_organizations.id"), index=True)
    customer_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_users.id"), index=True)
    status: Mapped[OrderStatus] = mapped_column(
        sa.Enum(OrderStatus), default=OrderStatus.PENDING, index=True
    )
    total_cents: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    notes: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    organization: Mapped[Organization] = relationship(back_populates="orders")
    customer: Mapped[User] = relationship()
    items: Mapped[list[OrderItem]] = relationship(
        back_populates="order", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return self.order_number


class OrderItem(DemoBase):
    __tablename__ = "demo_order_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_orders.id"), index=True)
    product_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_products.id"), index=True)
    quantity: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    unit_price_cents: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)

    order: Mapped[Order] = relationship(back_populates="items")
    product: Mapped[Product] = relationship()

    def __str__(self) -> str:
        return f"Item #{self.id} (x{self.quantity})"


class SupportTicket(DemoBase):
    __tablename__ = "demo_tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_key: Mapped[str] = mapped_column(sa.String(24), unique=True, index=True, nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(180), nullable=False, index=True)
    organization_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_organizations.id"), index=True)
    requester_id: Mapped[int] = mapped_column(sa.ForeignKey("demo_users.id"), index=True)
    priority: Mapped[TicketPriority] = mapped_column(
        sa.Enum(TicketPriority), default=TicketPriority.MEDIUM, index=True
    )
    status: Mapped[TicketStatus] = mapped_column(
        sa.Enum(TicketStatus), default=TicketStatus.OPEN, index=True
    )
    sla_health: Mapped[int] = mapped_column(sa.Integer, default=95, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    organization: Mapped[Organization] = relationship()
    requester: Mapped[User] = relationship()

    def __str__(self) -> str:
        return f"{self.ticket_key} · {self.subject}"


class InfraNodeType(enum.Enum):
    GLOBAL = "global"
    REGION = "region"
    ZONE = "zone"
    CLUSTER = "cluster"
    GPU_POD = "gpu_pod"


class InfrastructureNode(DemoBase):
    __tablename__ = "demo_infrastructure_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(140), index=True, nullable=False)
    node_type: Mapped[InfraNodeType] = mapped_column(
        sa.Enum(InfraNodeType), default=InfraNodeType.CLUSTER, index=True
    )
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("demo_infrastructure_nodes.id"), nullable=True, index=True
    )
    accent_color: Mapped[str] = mapped_column(sa.String(16), default="#3b82f6", nullable=False)
    health_pct: Mapped[int] = mapped_column(sa.Integer, default=99, nullable=False)
    labels: Mapped[list[str] | None] = mapped_column(sa.JSON, nullable=True)
    topology_yaml: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    parent: Mapped[InfrastructureNode | None] = relationship(remote_side=[id])

    def __str__(self) -> str:
        return f"{self.code} · {self.name}"


# ---- Declarative ModelViews ----


class OrderValueTierFilter(ListFilter):
    """Demo custom ListFilter with 1-query conditional facet predicates."""

    parameter_name = "value_tier"
    title = "Deal Size"

    def lookups(self, session: Session, view: Any, user: Any) -> list[tuple[str, str]]:
        _ = (session, view, user)
        return [
            ("small", "Standard (<$500)"),
            ("mid", "Growth ($500-$2K)"),
            ("whale", "Enterprise ($2K+)"),
        ]

    def facet_predicate(self, value: str, model: Any) -> sa.ColumnElement[bool] | None:
        if model is not Order:
            return None
        col = model.total_cents
        if value == "small":
            return col < 50000
        if value == "mid":
            return sa.and_(col >= 50000, col < 200000)
        if value == "whale":
            return col >= 200000
        return None

    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: Any,
    ) -> sa.Select[Any]:
        _ = (session, user)
        pred = self.facet_predicate(value, view.model)
        return stmt.where(pred) if pred is not None else stmt


class OrganizationView(ModelView):
    model = Organization
    icon = "building"
    category = "Customers"
    columns = ("name", "slug", "plan", "mrr_cents", "seats_used", "seat_health", "is_active", "created_at")
    searchable_columns = ("name", "slug")
    search_help_text = "Search by organization name or URL slug"
    filterable_columns = ("plan", "is_active", "created_at")
    inline_editable_columns = ("is_active", "plan")
    readonly_fields = ("created_at",)
    prepopulated_fields = MappingProxyType({"slug": ("name",)})
    view_on_site = "https://status.acme.dev/orgs/{slug}"
    field_help_texts = MappingProxyType(
        {
            "slug": "Auto-generated URL identifier (kebab-case).",
            "mrr_cents": "Monthly recurring revenue stored in USD cents.",
        }
    )
    column_labels = MappingProxyType({"mrr_cents": "MRR", "seats_used": "Seats"})
    column_aggregates = MappingProxyType({"mrr_cents": "sum", "seats_used": "sum"})
    aggregate_scope = "all"
    form_layout = "tabs"
    field_widgets = MappingProxyType({"plan": "segmented"})
    saved_views = (
        ("Enterprise Only", "?tab=enterprise"),
        ("Paused Orgs", "?f_is_active=false"),
    )
    fieldsets = (
        Fieldset(
            "Organization Identity",
            (("name", "slug"), "plan", "is_active"),
            description="Tenant branding, slug routing, and commercial plan.",
        ),
        Fieldset(
            "Billing & Quotas",
            ("mrr_cents", ("seats_used", "seats_limit"), "created_at"),
            collapsible=True,
        ),
    )
    quick_tabs = (
        QuickTab("all", "All"),
        QuickTab("enterprise", "Enterprise", filters={"plan": "enterprise"}, tone="ok"),
        QuickTab("growth", "Growth", filters={"plan": "growth"}, tone="info"),
        QuickTab("starter", "Starter", filters={"plan": "starter"}, tone="neutral"),
    )
    column_formatters = MappingProxyType(
        {
            "slug": CodeFormatter(copyable=True),
            "plan": BadgeFormatter({"enterprise": "ok", "growth": "info", "starter": "neutral"}),
            "mrr_cents": CurrencyFormatter(currency="USD", divisor=100, decimals=0),
            "is_active": BooleanIconFormatter(true_label="Active", false_label="Paused"),
            "created_at": RelativeTimeFormatter(),
        }
    )

    @display(label="Seat Health", ordering="seats_used")
    def seat_health(self, obj: Organization) -> str:
        pct = int((obj.seats_used / max(1, obj.seats_limit)) * 100)
        return f"{obj.seats_used}/{obj.seats_limit} ({pct}%)"


class UserView(ModelView):
    model = User
    icon = "users"
    category = "Customers"
    columns = ("full_name", "email", "organization", "role", "is_active", "created_at")
    searchable_columns = ("full_name", "email")
    filterable_columns = ("role", "is_active", "organization_id", "created_at")
    inline_editable_columns = ("is_active", "role")
    form_layout = "tabs"
    field_widgets = MappingProxyType({"role": "segmented"})
    column_formatters = MappingProxyType(
        {
            "full_name": AvatarFormatter(),
            "email": CodeFormatter(max_chars=32, copyable=True),
            "role": BadgeFormatter({"owner": "warn", "admin": "info", "engineer": "ok", "member": "neutral"}),
            "is_active": BooleanIconFormatter(),
            "created_at": RelativeTimeFormatter(),
        }
    )
    fieldsets = (
        ("Identity", ("full_name", "email", "organization_id")),
        ("Access Control", ("role", "is_active")),
    )


class ProductView(ModelView):
    model = Product
    icon = "package"
    category = "Commerce"
    columns = ("thumbnail_path", "sku", "name", "category", "price_cents", "stock_pct", "spec_sheet_path", "is_active")
    searchable_columns = ("sku", "name")
    search_help_text = "Search by SKU identifier or catalog product name"
    filterable_columns = ("category", "is_active", "price_cents", "metadata_json")
    custom_filters = (
        RangeListFilter(
            parameter_name="price_band",
            title="Price Band",
            column="price_cents",
            bands=(
                ("under500", "Under $500", None, 50000),
                ("mid", "$500 - $2,000", 50000, 200000),
                ("enterprise", "$2,000+", 200000, None),
            ),
        ),
    )
    show_facets = "auto"
    inline_editable_columns = ("is_active",)
    import_key_columns = ("sku",)
    field_help_texts = MappingProxyType(
        {
            "sku": "Unique catalog SKU code used as upsert key during CSV imports.",
            "price_cents": "Monthly list price billed in USD cents.",
        }
    )
    column_labels = MappingProxyType(
        {
            "thumbnail_path": "Preview",
            "spec_sheet_path": "Spec PDF",
            "price_cents": "Unit Price",
            "stock_pct": "Capacity",
        }
    )
    column_aggregates = MappingProxyType({"price_cents": "avg", "stock_pct": "avg"})
    form_layout = "wizard"
    gallery_image_field = "thumbnail_path"
    gallery_subtitle_field = "sku"
    form_excluded_columns = ("created_at",)
    file_fields = MappingProxyType(
        {
            "thumbnail_path": FileFieldConfig(
                storage=DEMO_MEDIA_STORAGE, kind="image", prefix="products/thumbs"
            ),
            "spec_sheet_path": FileFieldConfig(
                storage=DEMO_MEDIA_STORAGE, kind="file", prefix="products/specs"
            ),
        }
    )
    field_widgets = MappingProxyType(
        {"category": "segmented", "stock_pct": "slider", "metadata_json": "json_kv"}
    )
    fieldsets = (
        ("Catalog Identity", ("sku", "name", "category", "is_active")),
        ("Pricing & Media", ("price_cents", "stock_pct", "thumbnail_path", "spec_sheet_path")),
        ("Structured Metadata", ("metadata_json",)),
    )
    column_formatters = MappingProxyType(
        {
            "thumbnail_path": ImageFormatter(alt_prefix="Product"),
            "spec_sheet_path": FileFormatter(),
            "sku": CodeFormatter(copyable=True),
            "category": BadgeFormatter({"compute": "info", "storage": "ok", "networking": "warn", "addon": "neutral"}),
            "price_cents": CurrencyFormatter(currency="USD", divisor=100),
            "stock_pct": ProgressBarFormatter(max_value=100, warn_below=45, danger_below=20),
            "is_active": BooleanIconFormatter(true_label="Listed", false_label="Archived"),
        }
    )


class OrderItemInline(InlineModelView):
    model = OrderItem
    label = "Line Items"
    columns = ("product_id", "quantity", "unit_price_cents", "line_total")
    order_by = "id"
    extra = 1
    show_change_link = True
    collapsible = True
    field_help_texts = MappingProxyType(
        {
            "quantity": "Provisioned unit quantity.",
            "unit_price_cents": "Unit price locked at invoice time (USD cents).",
        }
    )

    @display(label="Line Total")
    def line_total(self, obj: OrderItem) -> str:
        return f"${(obj.quantity * obj.unit_price_cents) / 100:,.2f}"


class OrderView(ModelView):
    model = Order
    icon = "shopping-bag"
    category = "Commerce"
    columns = ("order_number", "organization", "customer", "status", "total_cents", "est_margin", "created_at")
    searchable_columns = ("^order_number", "organization.name", "=customer.email")
    search_help_text = "Tokenized search: prefix ^order_number, organization name, or exact =customer.email"
    filterable_columns = ("status", "organization_id", "organization.plan", "total_cents", "created_at")
    custom_filters = (
        OrderValueTierFilter,
        EmptyFieldListFilter(column="notes", title="Order Notes"),
        RelatedOnlyFieldListFilter(column="organization_id", title="Ordering Org (Active)"),
    )
    date_hierarchy = "created_at"
    show_facets = "auto"
    show_full_result_count = True
    list_select_related = ("organization", "customer")
    save_as = True
    save_on_top = True
    inline_editable_columns = ("status",)
    inlines = (OrderItemInline,)
    kanban_column = "status"
    kanban_card_fields = ("order_number", "organization", "total_cents")
    calendar_date_field = "created_at"
    calendar_title_field = "order_number"
    column_aggregates = MappingProxyType({"total_cents": "sum"})
    form_layout = "tabs"
    dependent_fields = MappingProxyType({"customer_id": ("organization_id", "organization_id")})
    field_conditions = MappingProxyType({"notes": ("status", "neq", "shipped")})
    field_widgets = MappingProxyType({"status": "segmented", "notes": "markdown"})
    saved_views = (
        ("High Value >$2K", "?f_total_cents__gte=200000"),
        ("Settled (Paid+Shipped)", "?f_status=paid,shipped"),
    )
    column_labels = MappingProxyType({"order_number": "Order #", "total_cents": "Amount"})
    quick_tabs = (
        QuickTab("all", "All"),
        QuickTab("paid", "Paid", filters={"status": "paid"}, tone="ok"),
        QuickTab("shipped", "Shipped", filters={"status": "shipped"}, tone="info"),
        QuickTab("pending", "Pending", filters={"status": "pending"}, tone="warn"),
        QuickTab("refunded", "Refunded", filters={"status": "refunded"}, tone="danger"),
    )
    column_formatters = MappingProxyType(
        {
            "order_number": CodeFormatter(copyable=True),
            "status": BadgeFormatter({"paid": "ok", "shipped": "info", "pending": "warn", "refunded": "danger"}),
            "total_cents": CurrencyFormatter(currency="USD", divisor=100),
            "created_at": RelativeTimeFormatter(),
        }
    )
    fieldsets = (
        ("Order Summary", (("order_number", "status"), ("organization_id", "customer_id"))),
        ("Billing & Markdown Notes", ("total_cents", "notes")),
    )

    @display(label="Est. Margin", ordering="total_cents")
    def est_margin(self, obj: Order) -> str:
        return f"${(obj.total_cents * 0.82) / 100:,.2f}"

    @action("mark_shipped", label="Mark Shipped", icon="truck", confirm=True)
    def mark_shipped(self, records: list[Order], form_data: Any, user: Any) -> str:
        for order in records:
            order.status = OrderStatus.SHIPPED
        return f"Marked {len(records)} order(s) as shipped."

    @action("issue_refund", label="Refund Selected", icon="rotate-ccw", confirm=True, variant="danger")
    def issue_refund(self, records: list[Order], form_data: Any, user: Any) -> str:
        for order in records:
            order.status = OrderStatus.REFUNDED
        return f"Refunded {len(records)} order(s)."

    @action("sync_erp", label="Sync ERP (Async)", icon="cpu", async_job=True)
    def sync_erp(self, records: list[Order], form_data: Any, user: Any, job_ctx: JobContext) -> str:
        total = max(1, len(records))
        for idx, order in enumerate(records, start=1):
            if job_ctx.is_cancelled():
                return "ERP sync cancelled."
            job_ctx.log(f"Reconciling {order.order_number} (${order.total_cents / 100:,.2f})…")
            job_ctx.set_progress(int((idx / total) * 100), f"Synced {idx}/{total} orders")
        return f"Synced {len(records)} order(s) with ERP ledger."


class SupportTicketView(ModelView):
    model = SupportTicket
    slug = "tickets"
    name = "Ticket"
    plural_name = "Support Tickets"
    icon = "life-buoy"
    category = "Operations"
    pagination_mode = "cursor"
    page_size = 4
    soft_delete_column = "deleted_at"
    exclude_columns = ("deleted_at",)
    form_excluded_columns = ("deleted_at",)
    columns = ("ticket_key", "subject", "organization", "priority", "status", "sla_health", "sla_tier", "created_at")
    searchable_columns = ("ticket_key", "subject")
    search_help_text = "Search by ticket key (e.g. OPS-412) or issue summary"
    filterable_columns = ("priority", "status", "organization_id", "organization.plan", "created_at")
    date_hierarchy = "created_at"
    show_facets = "auto"
    inline_editable_columns = ("status", "priority")
    kanban_column = "status"
    kanban_card_fields = ("ticket_key", "organization", "priority", "sla_health")
    column_aggregates = MappingProxyType({"sla_health": "avg"})
    form_layout = "tabs"
    field_widgets = MappingProxyType(
        {"priority": "segmented", "status": "segmented", "sla_health": "slider"}
    )
    saved_views = (
        ("Critical Queue", "?f_priority=critical"),
        ("SLA At Risk (<50%)", "?f_sla_health__lte=50"),
    )
    fieldsets = (
        ("Ticket Triage", ("ticket_key", "subject", "organization_id", "requester_id")),
        ("Priority & SLA Budget", ("priority", "status", "sla_health")),
    )
    column_labels = MappingProxyType({"ticket_key": "Key", "sla_health": "SLA Budget"})
    quick_tabs = (
        QuickTab("all", "All"),
        QuickTab("open", "Open", filters={"status": "open"}, tone="warn"),
        QuickTab("in_progress", "In Progress", filters={"status": "in_progress"}, tone="info"),
        QuickTab("resolved", "Resolved", filters={"status": "resolved"}, tone="ok"),
    )
    column_formatters = MappingProxyType(
        {
            "ticket_key": CodeFormatter(copyable=True),
            "priority": BadgeFormatter({"critical": "danger", "high": "warn", "medium": "info", "low": "neutral"}),
            "status": BadgeFormatter({"open": "warn", "in_progress": "info", "resolved": "ok", "closed": "neutral"}),
            "sla_health": ProgressBarFormatter(max_value=100, warn_below=50, danger_below=25),
            "created_at": RelativeTimeFormatter(),
        }
    )

    @display(label="SLA Tier", ordering="sla_health")
    def sla_tier(self, obj: SupportTicket) -> str:
        if obj.sla_health <= 25:
            return "Breached"
        if obj.sla_health <= 50:
            return "At Risk"
        return "Healthy"

    @action(
        "escalate",
        label="Escalate Priority",
        icon="alert-triangle",
        fields=(
            ActionField(
                "priority",
                "select",
                label="Target Priority",
                choices=(("high", "High"), ("critical", "Critical")),
                default="critical",
                required=True,
            ),
            ActionField(
                "reason",
                "text",
                label="Escalation Reason",
                placeholder="Enterprise SLA threshold breached…",
                required=True,
            ),
        ),
    )
    def escalate(self, records: list[SupportTicket], form_data: Any, user: Any) -> str:
        target = TicketPriority(form_data.get("priority", "critical"))
        reason = str(form_data.get("reason", "")).strip()
        for ticket in records:
            ticket.priority = target
        return f"Escalated {len(records)} ticket(s) to {target.value} ({reason})."


class InfrastructureNodeView(ModelView):
    model = InfrastructureNode
    slug = "infrastructure"
    name = "Infra Node"
    plural_name = "Fleet Topology"
    icon = "cpu"
    category = "Operations"
    tree_parent_field = "parent_id"
    tree_title_field = "name"
    columns = ("code", "name", "node_type", "health_pct", "accent_color", "is_active")
    searchable_columns = ("code", "name")
    filterable_columns = ("node_type", "is_active", "parent_id")
    inline_editable_columns = ("is_active", "health_pct")
    form_excluded_columns = ("created_at",)
    saved_views = (
        ("Tree Hierarchy", "?view=tree"),
        ("Degraded (<80% Health)", "?f_health_pct__lt=80"),
    )
    field_widgets = MappingProxyType(
        {
            "node_type": "segmented",
            "accent_color": ColorWidget(),
            "health_pct": SliderWidget(min_value=0, max_value=100, step=1, unit="%"),
            "labels": TagInputWidget(),
            "topology_yaml": CodeWidget(language="yaml", rows=6),
        }
    )
    fieldsets = (
        ("Node Topology", ("code", "name", "node_type", "parent_id", "is_active")),
        ("Capacity & Telemetry", ("health_pct", "accent_color", "labels", "topology_yaml")),
    )
    column_formatters = MappingProxyType(
        {
            "code": CodeFormatter(copyable=True),
            "node_type": BadgeFormatter(
                {
                    "global": "info",
                    "region": "ok",
                    "zone": "neutral",
                    "cluster": "warn",
                    "gpu_pod": "ok",
                }
            ),
            "health_pct": ProgressBarFormatter(max_value=100, warn_below=75, danger_below=45),
            "accent_color": CodeFormatter(copyable=True),
            "is_active": BooleanIconFormatter(true_label="Online", false_label="Cordoned"),
        }
    )


def _ensure_demo_media(*, count: int) -> list[str]:
    sample_pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    DEMO_MEDIA_STORAGE.save(
        sample_pdf,
        key="products/specs/acme-cloud-datasheet.pdf",
        content_type="application/pdf",
    )
    palette = [
        (96, 165, 250),
        (74, 222, 128),
        (251, 191, 36),
        (244, 244, 245),
        (248, 113, 113),
        (56, 189, 248),
        (167, 139, 250),
        (52, 211, 153),
        (251, 146, 60),
    ]
    thumb_keys: list[str] = []
    for idx in range(count):
        key = f"products/thumbs/sku-{idx + 1}.png"
        acc = palette[idx % len(palette)]
        DEMO_MEDIA_STORAGE.save(make_demo_png(64, 64, accent=acc), key=key, content_type="image/png")
        thumb_keys.append(key)
    return thumb_keys


def _seed_demo_data(
    session_factory: sessionmaker[Any],
    audit_store: SQLAlchemyAuditStore,
    *,
    seed_profile: Literal["standard", "showcase"] = "standard",
) -> None:
    now = datetime.now(timezone.utc)
    is_showcase = seed_profile == "showcase"
    thumb_keys = _ensure_demo_media(count=18 if is_showcase else 7)

    with session_factory() as sess:
        if sess.scalar(sa.select(sa.func.count()).select_from(Organization)) or 0:
            return

        orgs = [
            Organization(name="Northstar Robotics", slug="northstar", plan=PlanTier.ENTERPRISE, mrr_cents=480000, seats_used=42, seats_limit=50, created_at=now - timedelta(days=42)),
            Organization(name="Kestrel FinTech", slug="kestrel-fin", plan=PlanTier.ENTERPRISE, mrr_cents=620000, seats_used=64, seats_limit=80, created_at=now - timedelta(days=35)),
            Organization(name="Helios Grid Labs", slug="helios-grid", plan=PlanTier.GROWTH, mrr_cents=195000, seats_used=18, seats_limit=25, created_at=now - timedelta(days=28)),
            Organization(name="Vektor Mobility", slug="vektor-mob", plan=PlanTier.GROWTH, mrr_cents=149000, seats_used=14, seats_limit=20, created_at=now - timedelta(days=19)),
            Organization(name="Meridian BioAI", slug="meridian-bio", plan=PlanTier.ENTERPRISE, mrr_cents=510000, seats_used=51, seats_limit=60, created_at=now - timedelta(days=12)),
            Organization(name="Cinder Analytics", slug="cinder-data", plan=PlanTier.STARTER, mrr_cents=49000, seats_used=5, seats_limit=10, created_at=now - timedelta(days=7)),
            Organization(name="Solstice Logistics", slug="solstice-log", plan=PlanTier.GROWTH, mrr_cents=180000, seats_used=21, seats_limit=25, created_at=now - timedelta(days=4)),
            Organization(name="Boreal Systems", slug="boreal-sys", plan=PlanTier.STARTER, mrr_cents=39000, seats_used=4, seats_limit=10, is_active=False, created_at=now - timedelta(days=2)),
        ]
        if is_showcase:
            extra_org_specs = [
                ("Aether Compute AI", "aether-ai", PlanTier.ENTERPRISE, 890000, 92, 100, True, 86),
                ("Vanguard Quantum", "vanguard-q", PlanTier.ENTERPRISE, 740000, 71, 80, True, 81),
                ("Lumen Health Cloud", "lumen-health", PlanTier.ENTERPRISE, 560000, 58, 75, True, 75),
                ("Obsidian Payments", "obsidian-pay", PlanTier.ENTERPRISE, 690000, 68, 80, True, 70),
                ("Stratos Aerospace", "stratos-aero", PlanTier.ENTERPRISE, 940000, 114, 120, True, 66),
                ("Cobalt Security", "cobalt-sec", PlanTier.GROWTH, 240000, 22, 30, True, 61),
                ("Atlas Maritime", "atlas-maritime", PlanTier.GROWTH, 215000, 19, 25, True, 57),
                ("Polaris Genomics", "polaris-gene", PlanTier.ENTERPRISE, 530000, 48, 60, True, 53),
                ("Nimbus Telemetry", "nimbus-tel", PlanTier.GROWTH, 175000, 17, 25, True, 49),
                ("Horizon Freight", "horizon-freight", PlanTier.GROWTH, 162000, 15, 25, True, 45),
                ("Veritas Ledger", "veritas-ledger", PlanTier.ENTERPRISE, 645000, 62, 75, True, 39),
                ("Krypton Networks", "krypton-net", PlanTier.GROWTH, 228000, 27, 30, True, 34),
                ("Saffron Retail Ops", "saffron-retail", PlanTier.STARTER, 59000, 7, 10, True, 30),
                ("Pulse Energy Grid", "pulse-energy", PlanTier.ENTERPRISE, 710000, 66, 80, True, 26),
                ("Zeta Robotics", "zeta-robotics", PlanTier.GROWTH, 205000, 23, 25, True, 23),
                ("Argo Autonomous", "argo-auto", PlanTier.ENTERPRISE, 810000, 84, 100, True, 20),
                ("Fable Studio ML", "fable-ml", PlanTier.STARTER, 45000, 6, 10, True, 17),
                ("Sierra Defence AI", "sierra-def", PlanTier.ENTERPRISE, 980000, 96, 100, True, 15),
                ("Halcyon Fintech", "halcyon-fin", PlanTier.GROWTH, 190000, 18, 25, True, 13),
                ("Driftwood Media", "driftwood-med", PlanTier.STARTER, 35000, 3, 10, False, 11),
                ("Vectoris Pharma", "vectoris-ph", PlanTier.ENTERPRISE, 590000, 54, 70, True, 9),
                ("Chronos Data", "chronos-data", PlanTier.GROWTH, 168000, 16, 20, True, 6),
                ("Orion Edge CDN", "orion-edge", PlanTier.GROWTH, 235000, 21, 30, True, 3),
                ("Quarry Labs", "quarry-labs", PlanTier.STARTER, 29000, 2, 10, False, 1),
            ]
            for name, slug, plan, mrr, used, lim, active, days in extra_org_specs:
                orgs.append(
                    Organization(
                        name=name,
                        slug=slug,
                        plan=plan,
                        mrr_cents=mrr,
                        seats_used=used,
                        seats_limit=lim,
                        is_active=active,
                        created_at=now - timedelta(days=days),
                    )
                )
        sess.add_all(orgs)
        sess.flush()

        users = [
            User(full_name="Ada Lindholm", email="ada@northstar.io", role=UserRole.OWNER, organization_id=orgs[0].id, created_at=now - timedelta(days=40)),
            User(full_name="Kerem Kaya", email="kerem@kestrel.finance", role=UserRole.ADMIN, organization_id=orgs[1].id, created_at=now - timedelta(days=32)),
            User(full_name="Elena Rostova", email="elena@heliosgrid.dev", role=UserRole.ENGINEER, organization_id=orgs[2].id, created_at=now - timedelta(days=25)),
            User(full_name="Marcus Vance", email="marcus@vektor.io", role=UserRole.OWNER, organization_id=orgs[3].id, created_at=now - timedelta(days=18)),
            User(full_name="Selin Demir", email="selin@meridian.bio", role=UserRole.ADMIN, organization_id=orgs[4].id, created_at=now - timedelta(days=11)),
            User(full_name="Noah Sato", email="noah@cinder.sh", role=UserRole.ENGINEER, organization_id=orgs[5].id, created_at=now - timedelta(days=6)),
            User(full_name="Clara Weber", email="clara@solstice.eu", role=UserRole.OWNER, organization_id=orgs[6].id, created_at=now - timedelta(days=3)),
            User(full_name="Liam O'Connor", email="liam@boreal.dev", role=UserRole.MEMBER, organization_id=orgs[7].id, is_active=False, created_at=now - timedelta(days=1)),
        ]
        if is_showcase:
            extra_user_names = [
                ("Emre Yilmaz", "emre@aether.ai", UserRole.OWNER, True),
                ("Sophia Patel", "sophia@vanguardq.com", UserRole.ADMIN, True),
                ("Lukas Meyer", "lukas@lumenhealth.org", UserRole.ENGINEER, True),
                ("Nadia Al-Mansoor", "nadia@obsidianpay.io", UserRole.OWNER, True),
                ("Hiroshi Tanaka", "hiroshi@stratosaero.jp", UserRole.ADMIN, True),
                ("Chloe Laurent", "chloe@cobaltsec.dev", UserRole.ENGINEER, True),
                ("Jonas Lindqvist", "jonas@atlasmaritime.se", UserRole.OWNER, True),
                ("Mina Kwak", "mina@polarisgene.kr", UserRole.ADMIN, True),
                ("Rafael Silva", "rafael@nimbustel.br", UserRole.ENGINEER, True),
                ("Hannah Brooks", "hannah@horizonfreight.co", UserRole.MEMBER, True),
                ("Tariq Haddad", "tariq@veritasledger.io", UserRole.OWNER, True),
                ("Klara Novak", "klara@krypton.net", UserRole.ENGINEER, True),
                ("Daniel Cho", "daniel@saffronops.com", UserRole.MEMBER, True),
                ("Eva Rossi", "eva@pulseenergy.it", UserRole.ADMIN, True),
                ("Owen Gallagher", "owen@zetarobotics.ai", UserRole.ENGINEER, True),
                ("Amara Okafor", "amara@argoauto.io", UserRole.OWNER, True),
                ("Viktor Horvath", "viktor@fableml.studio", UserRole.ENGINEER, True),
                ("Zeynep Arslan", "zeynep@sierradef.ai", UserRole.ADMIN, True),
                ("Mateo Morales", "mateo@halcyonfin.es", UserRole.OWNER, True),
                ("Claire Dubois", "claire@driftwood.fm", UserRole.MEMBER, False),
                ("Soren Bakke", "soren@vectorispharma.no", UserRole.ADMIN, True),
                ("Priya Nair", "priya@chronosdata.in", UserRole.ENGINEER, True),
                ("Felix Hoffmann", "felix@orionedge.de", UserRole.OWNER, True),
                ("Tessa Campbell", "tessa@quarrylabs.io", UserRole.MEMBER, False),
                ("Cem Ozkan", "cem@northstar.io", UserRole.ENGINEER, True),
                ("Rachel Greenwald", "rachel@kestrel.finance", UserRole.ENGINEER, True),
                ("Ibrahim Mansour", "ibrahim@aether.ai", UserRole.ADMIN, True),
                ("Yuna Takahashi", "yuna@vanguardq.com", UserRole.ENGINEER, True),
                ("Gavin Mercer", "gavin@lumenhealth.org", UserRole.MEMBER, True),
                ("Daria Sokolova", "daria@obsidianpay.io", UserRole.ADMIN, True),
                ("Samir Haddad", "samir@meridian.bio", UserRole.ENGINEER, True),
                ("Anika Verma", "anika@stratosaero.jp", UserRole.ENGINEER, True),
                ("Lucas Bernard", "lucas@cobaltsec.dev", UserRole.MEMBER, False),
                ("Defne Aydin", "defne@pulseenergy.it", UserRole.ENGINEER, True),
                ("Ethan Park", "ethan@argoauto.io", UserRole.ADMIN, True),
                ("Mila Petrovic", "mila@veritasledger.io", UserRole.ENGINEER, True),
                ("Jules Moreau", "jules@sierradef.ai", UserRole.OWNER, True),
                ("Leila Farah", "leila@vectorispharma.no", UserRole.ENGINEER, True),
                ("Henrik Solberg", "henrik@chronosdata.in", UserRole.MEMBER, True),
                ("Nora Albers", "nora@orionedge.de", UserRole.MEMBER, False),
            ]
            for u_idx, (full_name, email, u_role, active) in enumerate(extra_user_names):
                org = orgs[(u_idx + 8) % len(orgs)]
                users.append(
                    User(
                        full_name=full_name,
                        email=email,
                        role=u_role,
                        organization_id=org.id,
                        is_active=active,
                        created_at=now - timedelta(days=1 + (u_idx * 2) % 85),
                    )
                )
        sess.add_all(users)
        sess.flush()

        products = [
            Product(sku="GPU-H200-8X", name="Dedicated H200 8x Cluster Node", category=ProductCategory.COMPUTE, price_cents=245000, stock_pct=78, thumbnail_path=thumb_keys[0], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "eu-central-1", "vram_gb": 1128}),
            Product(sku="CPU-ARM-64", name="Graviton4 64-vCPU Bare Metal", category=ProductCategory.COMPUTE, price_cents=42000, stock_pct=92, thumbnail_path=thumb_keys[1], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "us-east-1", "arch": "arm64", "ecc": True}),
            Product(sku="NVME-10TB", name="Replicated NVMe Block Pool (10 TB)", category=ProductCategory.STORAGE, price_cents=31000, stock_pct=61, thumbnail_path=thumb_keys[2], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "eu-central-1", "iops": 120000}),
            Product(sku="OBJ-S3-COLD", name="Immutable Audit Object Vault", category=ProductCategory.STORAGE, price_cents=12500, stock_pct=96, thumbnail_path=thumb_keys[3], metadata_json={"region": "eu-west-1", "worm": True}),
            Product(sku="NET-ANYCAST", name="Global Anycast Edge Ingress", category=ProductCategory.NETWORKING, price_cents=18000, stock_pct=38, thumbnail_path=thumb_keys[4], metadata_json={"region": "global", "pops": 44}),
            Product(sku="NET-PRIVLINK", name="Zero-Trust PrivateLink Tunnel", category=ProductCategory.NETWORKING, price_cents=15000, stock_pct=18, thumbnail_path=thumb_keys[5], metadata_json={"region": "eu-central-1", "mtls": True}),
            Product(sku="ADD-SOC2-LOG", name="7-Year Compliance Audit Retention", category=ProductCategory.ADDON, price_cents=29000, stock_pct=100, thumbnail_path=thumb_keys[6], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "global", "packs": ["SOC2", "ISO27001"]}),
        ]
        if is_showcase:
            extra_product_specs = [
                ("GPU-B200-16X", "Blackwell B200 16x Training Pod", ProductCategory.COMPUTE, 480000, 42, True, {"region": "us-east-1", "vram_gb": 2880, "nvlink": "1.8TB/s"}),
                ("GPU-L40S-4X", "Inference L40S 4x Serving Node", ProductCategory.COMPUTE, 118000, 84, True, {"region": "ap-northeast-1", "fp8_tflops": 1466}),
                ("CPU-EPYC-128", "EPYC 9754 High-Memory Compute", ProductCategory.COMPUTE, 68000, 73, True, {"region": "eu-central-1", "ram_gb": 768}),
                ("STO-LUSTRE-50", "Parallel Lustre AI Scratch (50 TB)", ProductCategory.STORAGE, 89000, 55, True, {"region": "us-east-1", "throughput_gbps": 40}),
                ("STO-PG-HA", "Multi-AZ Managed Postgres NVMe", ProductCategory.STORAGE, 54000, 89, True, {"region": "eu-central-1", "pitr_days": 35}),
                ("NET-WAF-ENT", "Enterprise L7 WAF & Bot Shield", ProductCategory.NETWORKING, 34000, 91, True, {"region": "global", "anycast": True}),
                ("NET-MESH-MTLS", "Cross-Region WireGuard Backbone", ProductCategory.NETWORKING, 22000, 31, True, {"region": "global", "mtu": 9000}),
                ("ADD-MCP-GUARD", "AI-Agent HITL Approval Gateway", ProductCategory.ADDON, 45000, 100, True, {"region": "global", "protocols": ["MCP-2025", "REST-v1"]}),
                ("ADD-SSO-SCIM", "OIDC PKCE + Okta SCIM Connector", ProductCategory.ADDON, 19500, 100, True, {"region": "global", "idp": ["Okta", "EntraID"]}),
                ("ADD-DED-KMS", "FIPS 140-3 Hardware KMS Envelope", ProductCategory.ADDON, 39000, 87, True, {"region": "eu-central-1", "hsm": "Luna-7"}),
                ("CPU-INTEL-LEG", "Legacy Skylake Gen2 Spot Pool", ProductCategory.COMPUTE, 21000, 12, False, {"region": "us-west-2", "eol": "2027-Q1"}),
            ]
            for p_idx, (sku, name, cat, price, stock, active, meta) in enumerate(extra_product_specs, start=7):
                products.append(
                    Product(
                        sku=sku,
                        name=name,
                        category=cat,
                        price_cents=price,
                        stock_pct=stock,
                        is_active=active,
                        thumbnail_path=thumb_keys[p_idx],
                        spec_sheet_path="products/specs/acme-cloud-datasheet.pdf" if p_idx % 2 == 0 else None,
                        metadata_json=meta,
                    )
                )
        sess.add_all(products)
        sess.flush()

        status_cycle = [
            OrderStatus.PAID,
            OrderStatus.PAID,
            OrderStatus.SHIPPED,
            OrderStatus.PAID,
            OrderStatus.PENDING,
            OrderStatus.SHIPPED,
            OrderStatus.PAID,
            OrderStatus.REFUNDED,
        ]
        order_count = 120 if is_showcase else 28
        days_span = 89 if is_showcase else 14
        order_notes = [
            "Provisioned via automated enterprise billing cycle.",
            "Approved via four-eyes capacity escalation workflow.",
            "Annual committed reserved-capacity drawdown.",
            "Q4 GPU cluster expansion with multi-AZ NVMe tier.",
        ]
        orders: list[Order] = []
        for idx in range(order_count):
            org = orgs[idx % len(orgs)]
            usr = users[idx % len(users)]
            st = status_cycle[idx % len(status_cycle)]
            p1 = products[idx % len(products)]
            p2 = products[(idx + 2) % len(products)]
            qty1 = 1 + (idx % 3)
            total = p1.price_cents * qty1 + p2.price_cents
            days_ago = (idx * 7) % days_span if is_showcase else (idx % 14)
            ord_obj = Order(
                order_number=f"ORD-2026-{1040 + idx}",
                organization_id=org.id,
                customer_id=usr.id,
                status=st,
                total_cents=total,
                notes=order_notes[idx % len(order_notes)],
                created_at=now - timedelta(days=days_ago, hours=(idx * 3) % 20),
                items=[
                    OrderItem(product_id=p1.id, quantity=qty1, unit_price_cents=p1.price_cents),
                    OrderItem(product_id=p2.id, quantity=1, unit_price_cents=p2.price_cents),
                ],
            )
            orders.append(ord_obj)
        sess.add_all(orders)
        sess.flush()

        tickets = [
            SupportTicket(ticket_key="OPS-412", subject="Dedicated PrivateLink BGP peering failover in eu-central-1", organization_id=orgs[1].id, requester_id=users[1].id, priority=TicketPriority.CRITICAL, status=TicketStatus.IN_PROGRESS, sla_health=22, created_at=now - timedelta(hours=3)),
            SupportTicket(ticket_key="OPS-411", subject="Increase H200 cluster quota from 32 to 64 GPUs", organization_id=orgs[0].id, requester_id=users[0].id, priority=TicketPriority.HIGH, status=TicketStatus.OPEN, sla_health=44, created_at=now - timedelta(hours=7)),
            SupportTicket(ticket_key="OPS-410", subject="Export SOC2 immutable audit trail for Q3 attestation", organization_id=orgs[4].id, requester_id=users[4].id, priority=TicketPriority.MEDIUM, status=TicketStatus.OPEN, sla_health=76, created_at=now - timedelta(days=1)),
            SupportTicket(ticket_key="OPS-409", subject="Configure SAML SCIM group mapping for engineering role", organization_id=orgs[2].id, requester_id=users[2].id, priority=TicketPriority.MEDIUM, status=TicketStatus.IN_PROGRESS, sla_health=68, created_at=now - timedelta(days=2)),
            SupportTicket(ticket_key="OPS-408", subject="Invoice VAT ID update for German subsidiary", organization_id=orgs[6].id, requester_id=users[6].id, priority=TicketPriority.LOW, status=TicketStatus.RESOLVED, sla_health=98, created_at=now - timedelta(days=3)),
            SupportTicket(ticket_key="OPS-407", subject="Read replica lag spike during bulk CSV ingestion", organization_id=orgs[3].id, requester_id=users[3].id, priority=TicketPriority.HIGH, status=TicketStatus.RESOLVED, sla_health=91, created_at=now - timedelta(days=4)),
            SupportTicket(ticket_key="OPS-406", subject="Duplicate staging webhook test alert (archived)", organization_id=orgs[5].id, requester_id=users[5].id, priority=TicketPriority.LOW, status=TicketStatus.CLOSED, sla_health=100, deleted_at=now - timedelta(days=1), created_at=now - timedelta(days=5)),
            SupportTicket(ticket_key="OPS-405", subject="Legacy TLS 1.1 deprecation notice (archived)", organization_id=orgs[7].id, requester_id=users[7].id, priority=TicketPriority.LOW, status=TicketStatus.CLOSED, sla_health=100, deleted_at=now - timedelta(days=2), created_at=now - timedelta(days=6)),
        ]
        if is_showcase:
            extra_ticket_subjects = [
                ("Blackwell B200 NVLink fabric CRC counters elevated in us-east-1", TicketPriority.CRITICAL, TicketStatus.OPEN, 19, False, 2),
                ("Enable hardware KMS key rotation schedule on eu-central-1 vault", TicketPriority.HIGH, TicketStatus.IN_PROGRESS, 52, False, 5),
                ("Audit MCP API key CIDR allowlist for production runner pool", TicketPriority.HIGH, TicketStatus.OPEN, 48, False, 8),
                ("Provision 40 Gbps Lustre scratch volume for genomics pipeline", TicketPriority.MEDIUM, TicketStatus.IN_PROGRESS, 71, False, 11),
                ("Rotate OIDC client secret ahead of annual IdP certificate rollover", TicketPriority.MEDIUM, TicketStatus.OPEN, 82, False, 14),
                ("Packet loss detected on Frankfurt-Amsterdam WireGuard tunnel", TicketPriority.CRITICAL, TicketStatus.IN_PROGRESS, 29, False, 1),
                ("Increase REST API rate limit tier from 120 to 600 req/min", TicketPriority.MEDIUM, TicketStatus.RESOLVED, 95, False, 18),
                ("Cross-border GDPR data residency attestation for Frankfurt cluster", TicketPriority.LOW, TicketStatus.RESOLVED, 99, False, 21),
                ("WebAuthn FIDO2 passkey attestation check on strict CSP origins", TicketPriority.HIGH, TicketStatus.RESOLVED, 88, False, 24),
                ("Dead-letter webhook replay requested after downstream 503 outage", TicketPriority.HIGH, TicketStatus.IN_PROGRESS, 56, False, 4),
                ("Configure custom PO number on annualized Enterprise agreement", TicketPriority.LOW, TicketStatus.OPEN, 86, False, 27),
                ("Investigate occasional cold-start latency on serverless EU worker", TicketPriority.MEDIUM, TicketStatus.IN_PROGRESS, 64, False, 9),
                ("Whitelist customer egress NAT block on PrivateLink endpoint", TicketPriority.MEDIUM, TicketStatus.RESOLVED, 93, False, 30),
                ("Verify hash-chained audit ledger anchor export before board audit", TicketPriority.HIGH, TicketStatus.OPEN, 41, False, 6),
                ("Upgrade Graviton4 fleet kernel for perf_event telemetry patch", TicketPriority.LOW, TicketStatus.RESOLVED, 97, False, 33),
                ("Decommission unused Spot GPU allocation in us-west-2 (archived)", TicketPriority.LOW, TicketStatus.CLOSED, 100, True, 35),
                ("Approve four-eyes production refund batch for billing adjustment", TicketPriority.MEDIUM, TicketStatus.OPEN, 73, False, 3),
                ("Sync Active Directory security groups to Deck RBAC roles", TicketPriority.MEDIUM, TicketStatus.IN_PROGRESS, 69, False, 16),
                ("Resolve 409 OCC edit collision reported by multi-region finance team", TicketPriority.LOW, TicketStatus.RESOLVED, 94, False, 38),
                ("Benchmark keyset cursor pagination over 1.2M ledger events", TicketPriority.LOW, TicketStatus.RESOLVED, 100, False, 41),
                ("Quarantine suspicious credential scan against staging ingress", TicketPriority.CRITICAL, TicketStatus.RESOLVED, 87, False, 44),
                ("Add automated SARIF security audit step to release workflow", TicketPriority.MEDIUM, TicketStatus.RESOLVED, 96, False, 47),
                ("Configure Arabic RTL invoice date/currency formatting preview", TicketPriority.LOW, TicketStatus.CLOSED, 100, False, 50),
                ("Legacy VPN concentrator shutdown notice (archived)", TicketPriority.LOW, TicketStatus.CLOSED, 100, True, 53),
                ("Validate Postgres connection pooler idle timeout under failover", TicketPriority.HIGH, TicketStatus.RESOLVED, 90, False, 56),
                ("Review AI-agent proposed MRR adjustment before checker sign-off", TicketPriority.HIGH, TicketStatus.OPEN, 37, False, 2),
                ("Enable strict immutable WORM lock on compliance S3 bucket", TicketPriority.MEDIUM, TicketStatus.RESOLVED, 97, False, 59),
                ("Test duplicate test-tenant cleanup script (archived)", TicketPriority.LOW, TicketStatus.CLOSED, 100, True, 62),
                ("Inspect slow query plan on multi-bind analytics cluster", TicketPriority.MEDIUM, TicketStatus.OPEN, 79, False, 12),
                ("Configure PagerDuty webhook signature HMAC verification", TicketPriority.MEDIUM, TicketStatus.RESOLVED, 95, False, 65),
                ("Expand anycast PoP health probe interval to 10s", TicketPriority.LOW, TicketStatus.CLOSED, 100, False, 68),
                ("Migrate customer custom role permissions to scoped API keys", TicketPriority.MEDIUM, TicketStatus.IN_PROGRESS, 74, False, 15),
                ("Review quarterly seat utilization overage report", TicketPriority.LOW, TicketStatus.OPEN, 89, False, 19),
                ("Certify Zero-Trust mTLS termination on edge ingress tier", TicketPriority.HIGH, TicketStatus.RESOLVED, 92, False, 72),
            ]
            for t_idx, (subj, prio, t_status, sla, trashed, days_ago) in enumerate(extra_ticket_subjects):
                org = orgs[(t_idx + 2) % len(orgs)]
                usr = users[(t_idx + 2) % len(users)]
                tickets.append(
                    SupportTicket(
                        ticket_key=f"OPS-{413 + t_idx}",
                        subject=subj,
                        organization_id=org.id,
                        requester_id=usr.id,
                        priority=prio,
                        status=t_status,
                        sla_health=sla,
                        deleted_at=(now - timedelta(days=max(1, days_ago // 4))) if trashed else None,
                        created_at=now - timedelta(days=days_ago, hours=(t_idx * 5) % 18),
                    )
                )
        sess.add_all(tickets)

        # Build InfrastructureNode hierarchy (standard: 7 nodes, showcase: 22 nodes)
        root_node = InfrastructureNode(
            code="GLB-CORE-00",
            name="Acme Global Backbone",
            node_type=InfraNodeType.GLOBAL,
            parent_id=None,
            accent_color="#3b82f6",
            health_pct=99,
            labels=["tier:backbone", "control-plane", "soc2"],
            topology_yaml="mesh:\n  bgp_asn: 64512\n  anycast: true\n  mtls_strict: true",
            is_active=True,
        )
        sess.add(root_node)
        sess.flush()

        eu_reg = InfrastructureNode(
            code="REG-EU-C1",
            name="eu-central-1 (Frankfurt)",
            node_type=InfraNodeType.REGION,
            parent_id=root_node.id,
            accent_color="#10b981",
            health_pct=96,
            labels=["region:eu-central-1", "gdpr", "primary"],
            topology_yaml="region: eu-central-1\nquorum: 3\nencryption: fips-140-3",
        )
        us_reg = InfrastructureNode(
            code="REG-US-E1",
            name="us-east-1 (Virginia)",
            node_type=InfraNodeType.REGION,
            parent_id=root_node.id,
            accent_color="#22c55e",
            health_pct=98,
            labels=["region:us-east-1", "ai-training", "primary"],
            topology_yaml="region: us-east-1\nquorum: 3\nnvlink_fabric: enabled",
        )
        ap_reg = InfrastructureNode(
            code="REG-AP-NE1",
            name="ap-northeast-1 (Tokyo)",
            node_type=InfraNodeType.REGION,
            parent_id=root_node.id,
            accent_color="#0ea5e9",
            health_pct=94,
            labels=["region:ap-northeast-1", "inference"],
            topology_yaml="region: ap-northeast-1\nquorum: 2\nlow_latency: true",
        )
        sess.add_all([eu_reg, us_reg, ap_reg])
        sess.flush()

        infra_leaf_specs: list[tuple[str, str, InfraNodeType, int, str, int, list[str], bool]] = [
            ("CL-EU-H200", "Frankfurt H200 Inference Cluster", InfraNodeType.GPU_POD, eu_reg.id, "#22c55e", 91, ["gpu:h200", "vram:1128g"], True),
            ("CL-US-B200", "Virginia B200 Training Pod A", InfraNodeType.GPU_POD, us_reg.id, "#f59e0b", 72, ["gpu:b200", "nvlink"], True),
            ("CL-EU-PLINK", "PrivateLink Edge Concentrator", InfraNodeType.CLUSTER, eu_reg.id, "#ef4444", 39, ["bgp-failover", "net"], True),
        ]
        if is_showcase:
            eu_az1 = InfrastructureNode(
                code="AZ-EU-C1A",
                name="eu-central-1a (Equinix FR5)",
                node_type=InfraNodeType.ZONE,
                parent_id=eu_reg.id,
                accent_color="#3b82f6",
                health_pct=97,
                labels=["az:1a", "equinix"],
                topology_yaml="zone: eu-central-1a\npower_pue: 1.18\nuplink_gbps: 400",
            )
            eu_az2 = InfrastructureNode(
                code="AZ-EU-C1B",
                name="eu-central-1b (Interxion)",
                node_type=InfraNodeType.ZONE,
                parent_id=eu_reg.id,
                accent_color="#6366f1",
                health_pct=88,
                labels=["az:1b", "interxion"],
                topology_yaml="zone: eu-central-1b\npower_pue: 1.21\nuplink_gbps: 400",
            )
            us_az1 = InfrastructureNode(
                code="AZ-US-E1A",
                name="us-east-1a (Ashburn DC4)",
                node_type=InfraNodeType.ZONE,
                parent_id=us_reg.id,
                accent_color="#14b8a6",
                health_pct=95,
                labels=["az:1a", "ashburn"],
                topology_yaml="zone: us-east-1a\ncooling: direct-liquid\nuplink_gbps: 800",
            )
            us_az2 = InfrastructureNode(
                code="AZ-US-E1B",
                name="us-east-1b (Ashburn DC7)",
                node_type=InfraNodeType.ZONE,
                parent_id=us_reg.id,
                accent_color="#22c55e",
                health_pct=99,
                labels=["az:1b", "storage"],
                topology_yaml="zone: us-east-1b\nlustre_pool: active\nuplink_gbps: 400",
            )
            ap_az1 = InfrastructureNode(
                code="AZ-AP-NE1A",
                name="ap-northeast-1a (TY2)",
                node_type=InfraNodeType.ZONE,
                parent_id=ap_reg.id,
                accent_color="#0ea5e9",
                health_pct=94,
                labels=["az:1a", "tokyo"],
                topology_yaml="zone: ap-northeast-1a\nuplink_gbps: 200",
            )
            ap_az2 = InfrastructureNode(
                code="AZ-AP-NE1C",
                name="ap-northeast-1c (TY4)",
                node_type=InfraNodeType.ZONE,
                parent_id=ap_reg.id,
                accent_color="#f59e0b",
                health_pct=68,
                labels=["az:1c", "maintenance"],
                topology_yaml="zone: ap-northeast-1c\nmaintenance_window: sunday-02utc",
            )
            sess.add_all([eu_az1, eu_az2, us_az1, us_az2, ap_az1, ap_az2])
            sess.flush()

            infra_leaf_specs = [
                ("POD-EU-H200-01", "H200-8X Pod Alpha (EU)", InfraNodeType.GPU_POD, eu_az1.id, "#22c55e", 96, ["gpu:h200", "vram:1128g"], True),
                ("POD-EU-H200-02", "H200-8X Pod Beta (EU)", InfraNodeType.GPU_POD, eu_az1.id, "#10b981", 91, ["gpu:h200", "vram:1128g"], True),
                ("CL-EU-PG-HA", "Frankfurt Postgres NVMe Quorum", InfraNodeType.CLUSTER, eu_az1.id, "#3b82f6", 99, ["postgres:17", "ha-quorum"], True),
                ("CL-EU-PLINK", "PrivateLink BGP Peering Cluster", InfraNodeType.CLUSTER, eu_az2.id, "#ef4444", 39, ["bgp-alert", "ticket:OPS-412"], True),
                ("CL-EU-KMS-HSM", "FIPS 140-3 Hardware KMS Vault", InfraNodeType.CLUSTER, eu_az2.id, "#8b5cf6", 100, ["fips-140-3", "hsm"], True),
                ("POD-US-B200-01", "Blackwell B200-16X Training Pod", InfraNodeType.GPU_POD, us_az1.id, "#f59e0b", 72, ["gpu:b200", "nvlink"], True),
                ("POD-US-ARM-01", "Graviton4 Worker Pool US-01", InfraNodeType.CLUSTER, us_az1.id, "#22c55e", 97, ["arch:arm64", "stateless"], True),
                ("CL-US-LUSTRE", "50TB Parallel Lustre Scratch Pool", InfraNodeType.CLUSTER, us_az2.id, "#14b8a6", 95, ["storage:lustre", "40gbps"], True),
                ("CL-US-WORM-01", "Immutable SOC2 Audit Object Vault", InfraNodeType.CLUSTER, us_az2.id, "#6366f1", 100, ["worm", "soc2"], True),
                ("POD-AP-L40S-01", "Tokyo L40S Real-Time Inference Pod", InfraNodeType.GPU_POD, ap_az1.id, "#0ea5e9", 93, ["gpu:l40s", "fp8"], True),
                ("CL-AP-ANYCAST", "Tokyo Anycast PoP Ingress", InfraNodeType.CLUSTER, ap_az1.id, "#3b82f6", 98, ["anycast", "waf-l7"], True),
                ("CL-AP-SPOT-LEG", "Legacy Spot Drained Pool (Cordoned)", InfraNodeType.CLUSTER, ap_az2.id, "#71717a", 44, ["cordoned", "eol"], False),
            ]
        sess.add_all(
            [
                InfrastructureNode(
                    code=code,
                    name=name,
                    node_type=ntype,
                    parent_id=parent_id,
                    accent_color=color,
                    health_pct=health,
                    labels=tags,
                    topology_yaml=f"node: {code.lower()}\nparent_id: {parent_id}\nhealth_sla: {health}%\nactive: {str(active).lower()}",
                    is_active=active,
                    created_at=now - timedelta(days=(idx + 1) * 3),
                )
                for idx, (code, name, ntype, parent_id, color, health, tags, active) in enumerate(infra_leaf_specs)
            ]
        )
        sess.flush()
        sess.commit()

        # Pre-seed chronological Audit Ledger entries (oldest -> newest so hash chain stays valid)
        seed_audits = [
            make_audit_entry(
                actor_id="admin",
                actor_name="Duhan Güler",
                actor_ip="10.24.0.18",
                action="update",
                model_slug="users",
                model_label="User",
                record_pk=str(users[1].id),
                record_repr=users[1].full_name,
                changes={"role": {"old": "engineer", "new": "admin"}, "api_token": {"old": "[REDACTED]", "new": "[REDACTED]"}},
                timestamp=now - timedelta(hours=9),
            ),
            make_audit_entry(
                actor_id="admin",
                actor_name="Duhan Güler",
                actor_ip="10.24.0.18",
                action="import",
                model_slug="products",
                model_label="Product",
                record_pk="batch:7",
                record_repr="Imported catalog_q4.csv (+4 / ~3)",
                metadata={"filename": "catalog_q4.csv", "created": 4, "updated": 3},
                timestamp=now - timedelta(hours=5),
            ),
            make_audit_entry(
                actor_id="admin",
                actor_name="Duhan Güler",
                actor_ip="10.24.0.18",
                action="update",
                model_slug="organizations",
                model_label="Organization",
                record_pk=str(orgs[4].id),
                record_repr=orgs[4].name,
                changes={"plan": {"old": "growth", "new": "enterprise"}, "mrr_cents": {"old": 240000, "new": 510000}},
                timestamp=now - timedelta(hours=2),
            ),
            make_audit_entry(
                actor_id="support",
                actor_name="Maya Chen",
                actor_ip="10.24.0.42",
                action="inline_edit",
                model_slug="tickets",
                model_label="Ticket",
                record_pk=str(tickets[0].id),
                record_repr=tickets[0].ticket_key,
                changes={"status": {"old": "open", "new": "in_progress"}},
                timestamp=now - timedelta(minutes=38),
            ),
            make_audit_entry(
                actor_id="admin",
                actor_name="Duhan Güler",
                actor_ip="10.24.0.18",
                action="update",
                model_slug="orders",
                model_label="Order",
                record_pk=str(orders[0].id),
                record_repr=orders[0].order_number,
                changes={"status": {"old": "pending", "new": "paid"}},
                timestamp=now - timedelta(minutes=14),
            ),
        ]
        if is_showcase:
            extra_audits = [
                make_audit_entry(
                    actor_id="admin",
                    actor_name="Duhan Güler",
                    actor_ip="10.24.0.18",
                    action="create",
                    model_slug="organizations",
                    model_label="Organization",
                    record_pk=str(orgs[i % len(orgs)].id),
                    record_repr=orgs[i % len(orgs)].name,
                    changes={"plan": {"old": None, "new": orgs[i % len(orgs)].plan.value}},
                    timestamp=now - timedelta(days=14 - (i % 12), hours=(i * 2) % 20),
                )
                if i % 4 == 0
                else (
                    make_audit_entry(
                        actor_id="mcp-agent",
                        actor_name="Claude Ops MCP Agent",
                        actor_ip="10.24.8.12",
                        action="approval_approved",
                        model_slug="orders",
                        model_label="Order",
                        record_pk=str(orders[i % len(orders)].id),
                        record_repr=orders[i % len(orders)].order_number,
                        changes={"status": {"old": "pending", "new": "shipped"}},
                        metadata={"actor_type": "ai_agent", "reviewer": "Duhan Güler"},
                        timestamp=now - timedelta(days=12 - (i % 10), hours=(i * 3) % 18),
                    )
                    if i % 4 == 1
                    else (
                        make_audit_entry(
                            actor_id="support",
                            actor_name="Maya Chen",
                            actor_ip="10.24.0.42",
                            action="inline_edit",
                            model_slug="tickets",
                            model_label="Ticket",
                            record_pk=str(tickets[i % len(tickets)].id),
                            record_repr=tickets[i % len(tickets)].ticket_key,
                            changes={"priority": {"old": "medium", "new": "high"}},
                            timestamp=now - timedelta(days=10 - (i % 8), hours=(i * 4) % 16),
                        )
                        if i % 4 == 2
                        else make_audit_entry(
                            actor_id="admin",
                            actor_name="Duhan Güler",
                            actor_ip="10.24.0.18",
                            action="api_key_create",
                            model_slug="infrastructure",
                            model_label="Infra Node",
                            record_pk=str(root_node.id),
                            record_repr=f"Key rotation & node health sync #{i}",
                            changes={"health_pct": {"old": 94, "new": 98}},
                            timestamp=now - timedelta(days=8 - (i % 6), hours=(i * 5) % 14),
                        )
                    )
                )
                for i in range(31)
            ]
            seed_audits = [*extra_audits, *seed_audits]
        for entry in seed_audits:
            audit_store.record(entry)


def _seed_showcase_control_plane(
    deck: Deck,
    session_factory: sessionmaker[Any],
    now: datetime,
) -> None:
    """Populate v0.4.0 governance, BI SQL, API key, webhook DLQ, and job showcase stores."""
    with session_factory() as sess:
        orgs = list(sess.scalars(sa.select(Organization).order_by(Organization.id.asc()).limit(10)).all())
        orders = list(sess.scalars(sa.select(Order).order_by(Order.id.asc()).limit(8)).all())
        tickets = list(sess.scalars(sa.select(SupportTicket).order_by(SupportTicket.id.asc()).limit(6)).all())
        infra_nodes = list(
            sess.scalars(sa.select(InfrastructureNode).order_by(InfrastructureNode.id.asc()).limit(12)).all()
        )
    if not orgs or not orders or not tickets:
        return

    # 1. Four-Eyes Maker-Checker Approvals (4 pending incl. 2 AI agent proposals + 3 historical)
    if deck.approval_store is not None and not deck.approval_store.list_requests(limit=1):
        pending_specs: list[dict[str, Any]] = [
            {
                "id": "appr-ai-001",
                "model_slug": "organizations",
                "model_label": "Organization",
                "operation": "edit",
                "record_pk": str(orgs[2].id),
                "record_repr": orgs[2].name,
                "payload": {
                    "values": {"plan": "enterprise", "seats_limit": 60, "mrr_cents": 495000},
                    "_actor_roles": ["superadmin"],
                    "_actor_superuser": True,
                },
                "diff": {
                    "plan": {"old": "growth", "new": "enterprise"},
                    "seats_limit": {"old": 25, "new": 60},
                    "mrr_cents": {"old": 195000, "new": 495000},
                },
                "reason": "MCP agent verified signed enterprise PO #ENT-2026-884 and seat pressure (72% -> 95% forecast).",
                "requester_id": "mcp-agent",
                "requester_name": "Claude Ops MCP Agent",
                "actor_type": "ai_agent",
                "mins": 9,
            },
            {
                "id": "appr-ai-002",
                "model_slug": "tickets",
                "model_label": "Ticket",
                "operation": "edit",
                "record_pk": str(tickets[1].id),
                "record_repr": f"{tickets[1].ticket_key} · {tickets[1].subject[:48]}",
                "payload": {
                    "values": {"priority": "critical", "status": "in_progress", "sla_health": 32},
                    "_actor_roles": ["superadmin"],
                    "_actor_superuser": True,
                },
                "diff": {
                    "priority": {"old": "high", "new": "critical"},
                    "status": {"old": "open", "new": "in_progress"},
                },
                "reason": "AI telemetry triage detected GPU queue backlog exceeding 4h Enterprise SLA budget.",
                "requester_id": "mcp-agent",
                "requester_name": "Claude Ops MCP Agent",
                "actor_type": "ai_agent",
                "mins": 24,
            },
            {
                "id": "appr-hm-003",
                "model_slug": "orders",
                "model_label": "Order",
                "operation": "action",
                "record_pk": str(orders[3].id),
                "record_repr": orders[3].order_number,
                "payload": {"action_name": "issue_refund", "pks": [str(orders[3].id)], "params": {}},
                "diff": {"status": {"old": orders[3].status.value, "new": "refunded"}},
                "reason": "Customer duplicate billing adjustment requested by Maya Chen (requires checker sign-off).",
                "requester_id": "support",
                "requester_name": "Maya Chen",
                "actor_type": "human",
                "mins": 55,
            },
            {
                "id": "appr-hm-004",
                "model_slug": "organizations",
                "model_label": "Organization",
                "operation": "edit",
                "record_pk": str(orgs[5].id),
                "record_repr": orgs[5].name,
                "payload": {"values": {"plan": "growth", "seats_limit": 25, "mrr_cents": 149000}},
                "diff": {
                    "plan": {"old": "starter", "new": "growth"},
                    "seats_limit": {"old": 10, "new": 25},
                },
                "reason": "Mid-cycle plan expansion signed via Stripe Enterprise Billing webhook.",
                "requester_id": "support",
                "requester_name": "Maya Chen",
                "actor_type": "human",
                "mins": 110,
            },
        ]
        for sp in pending_specs:
            deck.approval_store.create(
                ApprovalRequest(
                    id=sp["id"],
                    model_slug=sp["model_slug"],
                    model_label=sp["model_label"],
                    operation=sp["operation"],
                    record_pk=sp["record_pk"],
                    record_repr=sp["record_repr"],
                    payload=sp["payload"],
                    diff=sp["diff"],
                    reason=sp["reason"],
                    requester_id=sp["requester_id"],
                    requester_name=sp["requester_name"],
                    actor_type=sp["actor_type"],
                    created_at=now - timedelta(minutes=sp["mins"]),
                )
            )

        historical_specs: list[tuple[str, str, str, str, str, str, str, str, str]] = [
            ("appr-hist-101", "orders", "Order", "edit", str(orders[0].id), orders[0].order_number, "mcp-agent", "approved", "Checker confirmed Stripe settlement TX #ch_3QP91."),
            ("appr-hist-102", "tickets", "Ticket", "edit", str(tickets[0].id), tickets[0].ticket_key, "support", "approved", "Escalated BGP failover to eu-central-1 network on-call."),
            ("appr-hist-103", "organizations", "Organization", "delete", str(orgs[7].id), orgs[7].name, "mcp-agent", "rejected", "Retain paused organization ledger records for 7-year SOC2 retention."),
        ]
        for aid, slug, label, op, pk, repr_s, req_id, final_st, note in historical_specs:
            deck.approval_store.create(
                ApprovalRequest(
                    id=aid,
                    model_slug=slug,
                    model_label=label,
                    operation=op,  # type: ignore[arg-type]
                    record_pk=pk,
                    record_repr=repr_s,
                    payload={"note": note},
                    diff={"reviewed": {"old": "pending", "new": final_st}},
                    reason="Historical governance audit record.",
                    requester_id=req_id,
                    requester_name="Claude Ops MCP Agent" if req_id == "mcp-agent" else "Maya Chen",
                    actor_type="ai_agent" if req_id == "mcp-agent" else "human",
                    created_at=now - timedelta(hours=6),
                )
            )
            deck.approval_store.resolve(
                aid,
                status=final_st,  # type: ignore[arg-type]
                reviewer_id="admin",
                reviewer_name="Duhan Güler",
                review_note=note,
            )

    # 2. Saved BI SQL Queries & Pinned Dashboard Tiles
    if deck.saved_query_store is not None and not deck.saved_query_store.list_queries(limit=1):
        saved_queries = [
            SavedQueryRecord(
                id="sq-bi-plan-mrr",
                name="Active MRR by Plan Tier (USD)",
                sql="SELECT plan, SUM(mrr_cents) / 100 AS mrr_usd FROM demo_organizations WHERE is_active = TRUE GROUP BY plan ORDER BY mrr_usd DESC",
                owner_id="admin",
                owner_name="Duhan Güler",
                is_pinned_to_dashboard=True,
                chart_type="bar",
                created_at=now - timedelta(hours=1),
            ),
            SavedQueryRecord(
                id="sq-bi-cat-rev",
                name="Order Line-Item Revenue by Category (USD)",
                sql="SELECT p.category, SUM(oi.quantity * oi.unit_price_cents) / 100 AS revenue_usd FROM demo_order_items oi JOIN demo_products p ON p.id = oi.product_id GROUP BY p.category ORDER BY revenue_usd DESC",
                owner_id="admin",
                owner_name="Duhan Güler",
                is_pinned_to_dashboard=True,
                chart_type="bar",
                created_at=now - timedelta(hours=2),
            ),
            SavedQueryRecord(
                id="sq-bi-order-st",
                name="Orders by Fulfillment State",
                sql="SELECT status, COUNT(*) AS orders, SUM(total_cents) / 100 AS volume_usd FROM demo_orders GROUP BY status ORDER BY orders DESC",
                owner_id="admin",
                owner_name="Duhan Güler",
                is_pinned_to_dashboard=False,
                chart_type="line",
                created_at=now - timedelta(hours=5),
            ),
            SavedQueryRecord(
                id="sq-bi-seat-pressure",
                name="High Seat Utilization Accounts (>80%)",
                sql="SELECT name, plan, seats_used, seats_limit, ROUND(100.0 * seats_used / seats_limit, 1) AS pct_used FROM demo_organizations WHERE is_active = TRUE AND (100.0 * seats_used / seats_limit) >= 80 ORDER BY pct_used DESC LIMIT 12",
                owner_id="admin",
                owner_name="Duhan Güler",
                is_pinned_to_dashboard=False,
                chart_type="table",
                created_at=now - timedelta(hours=8),
            ),
            SavedQueryRecord(
                id="sq-bi-sla-risk",
                name="Open Critical & High SLA Tickets",
                sql="SELECT ticket_key, priority, status, sla_health, subject FROM demo_tickets WHERE deleted_at IS NULL AND UPPER(CAST(status AS TEXT)) IN ('OPEN', 'IN_PROGRESS') ORDER BY sla_health ASC LIMIT 10",
                owner_id="support",
                owner_name="Maya Chen",
                is_pinned_to_dashboard=False,
                chart_type="table",
                created_at=now - timedelta(hours=12),
            ),
            SavedQueryRecord(
                id="sq-bi-fleet-health",
                name="Fleet Health by Node Tier",
                sql="SELECT node_type, COUNT(*) AS nodes, ROUND(AVG(health_pct), 1) AS avg_health_pct FROM demo_infrastructure_nodes GROUP BY node_type ORDER BY avg_health_pct ASC",
                owner_id="admin",
                owner_name="Duhan Güler",
                is_pinned_to_dashboard=False,
                chart_type="bar",
                created_at=now - timedelta(days=1),
            ),
        ]
        for sq in saved_queries:
            deck.saved_query_store.create(sq)

    # 3. Shared Team Saved Views
    if deck.saved_view_store is not None and not deck.saved_view_store.list_for_model(
        "organizations", user_id="admin", roles=("superadmin",)
    ):
        team_views = [
            SavedViewRecord(id="sv-org-ent", model_slug="organizations", name="Enterprise $4K+ MRR", query_string="f_plan=enterprise&f_mrr_cents__gte=400000", scope="team", owner_id="admin", owner_name="Duhan Güler"),
            SavedViewRecord(id="sv-ord-ent", model_slug="orders", name="Enterprise Plan Orders", query_string="f_organization.plan=enterprise", scope="team", owner_id="admin", owner_name="Duhan Güler"),
            SavedViewRecord(id="sv-ord-big", model_slug="orders", name="Large Deals ($5K+)", query_string="f_total_cents__gte=500000", scope="team", owner_id="admin", owner_name="Duhan Güler"),
            SavedViewRecord(id="sv-tkt-sla", model_slug="tickets", name="SLA At-Risk (<50%)", query_string="f_sla_health__lte=50", scope="team", owner_id="support", owner_name="Maya Chen"),
            SavedViewRecord(id="sv-prd-gpu", model_slug="products", name="Compute Gallery", query_string="view=gallery&f_category=compute", scope="team", owner_id="admin", owner_name="Duhan Güler"),
            SavedViewRecord(id="sv-inf-tree", model_slug="infrastructure", name="Live Fleet Tree", query_string="view=tree", scope="team", owner_id="admin", owner_name="Duhan Güler"),
        ]
        for sv in team_views:
            deck.saved_view_store.create(sv)

    # 4. Operational Record Notes (strict-CSP safe Markdown subset)
    if deck.note_store is not None and not deck.note_store.list_notes("tickets", str(tickets[0].id), limit=1):
        notes_specs: list[tuple[str, str, str, str, str, bool, int]] = [
            ("tickets", str(tickets[0].id), "admin", "Duhan Güler", "**Incident Commander Note:** BGP session bounced on `DE-CIX-02`. Failover active via Interxion backup fiber; zero customer packet drop after `03:14 UTC`.", True, 25),
            ("tickets", str(tickets[0].id), "support", "Maya Chen", "Shared live packet capture summary with Kerem Kaya (`kestrel-fin`). Monitoring stability window for next 4h.", False, 15),
            ("tickets", str(tickets[1].id), "admin", "Duhan Güler", "**Capacity Check:** Verify `AZ-US-E1A` H200 thermal envelope before expanding quota from 32 to 64 GPUs.", True, 45),
            ("tickets", str(tickets[2].id), "support", "Maya Chen", "SOC2 Type II attestation package generated as CSV artifact in `/admin/_jobs`.", False, 90),
            ("organizations", str(orgs[0].id), "admin", "Duhan Güler", "**Strategic Account:** Executive sponsor `Ada Lindholm`. Dedicated 64x H200 renewal scheduled for Q1 2027.", True, 120),
            ("organizations", str(orgs[1].id), "admin", "Duhan Güler", "- Strict PrivateLink mTLS required on all endpoints\n- Audit exports retained in EU-Central vault (`eu-central-1`)", True, 180),
            ("organizations", str(orgs[2].id), "support", "Maya Chen", "Pending AI-agent **Enterprise upgrade proposal** in `/admin/_approvals` awaiting Finance checker sign-off.", False, 14),
            ("organizations", str(orgs[4].id), "admin", "Duhan Güler", "Upgraded Growth → Enterprise (`$2,400` → `$5,100` MRR); HIPAA BAA countersigned.", False, 240),
            ("orders", str(orders[0].id), "admin", "Duhan Güler", "Stripe invoice settled (`EUR/USD FX locked`); provisioning completed across 2 line items.", True, 60),
            ("orders", str(orders[1].id), "support", "Maya Chen", "Customer requested consolidated PO reference on next monthly billing run.", False, 140),
            ("orders", str(orders[2].id), "admin", "Duhan Güler", "Verified EU-Central shipping fulfillment & NVMe snapshot replication.", False, 200),
            ("infrastructure", str(infra_nodes[0].id), "admin", "Duhan Güler", "**Global Mesh Policy:** All inter-region east-west traffic enforces WireGuard + FIPS-140-3 KMS rotation every 24h.", True, 300),
            ("infrastructure", str(infra_nodes[1].id), "admin", "Duhan Güler", "Primary GDPR-pinned cluster zone; all KMS keys reside in `eu-central-1` HSM.", True, 360),
            ("infrastructure", str(infra_nodes[-1].id), "support", "Maya Chen", "Health degraded under BGP maintenance; auto-drain rule verified.", False, 40),
        ]
        for slug, pk, aid, aname, body, pinned, mins in notes_specs:
            deck.note_store.add(
                RecordNote(
                    id="",
                    model_slug=slug,
                    record_pk=pk,
                    author_id=aid,
                    author_name=aname,
                    body=body,
                    pinned=pinned,
                    created_at=now - timedelta(minutes=mins),
                )
            )

    # 5. Scoped API Keys (SHA-256 hashed at rest, plaintext never stored)
    if deck.api_key_store is not None and not deck.api_key_store.list_keys(limit=1):
        key_specs: list[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], bool, int | None, bool]] = [
            ("Claude Ops MCP Agent (HITL)", ("*:view", "organizations:edit", "tickets:edit"), ("support",), (), False, 90, False),
            ("Billing ERP Read-Only Sync", ("orders:view", "orders:export", "organizations:view"), ("auditor",), ("10.24.0.0/16", "198.51.100.0/24"), False, 180, False),
            ("SOC2 Compliance Auditor Bot", ("*:view", "audit:view", "*:export"), ("auditor",), (), False, 365, False),
            ("Legacy Staging CI Key", ("*:view",), ("auditor",), (), False, 30, True),
        ]
        for k_name, scopes, k_roles, cidrs, is_su, ttl, should_revoke in key_specs:
            _plaintext, k_rec = build_api_key_record(
                name=k_name,
                owner_id="admin",
                owner_name="Duhan Güler",
                scopes=scopes,
                roles=k_roles,
                allowed_ips=cidrs,
                is_superuser=is_su,
                ttl_days=ttl,
            )
            deck.api_key_store.create(k_rec)
            if should_revoke:
                deck.api_key_store.revoke(k_rec.id)

    # 6. Webhook Delivery Ledger & Dead-Letter Queue (DLQ)
    if deck.webhook_delivery_store is not None and not deck.webhook_delivery_store.list_deliveries(limit=1):
        wh_specs: list[tuple[str, str, str, int, int, int | None, str | None, int]] = [
            ("https://hooks.acme-ops.internal/audit-siem", "audit.recorded", "delivered", 1, 3, 200, None, 4),
            ("https://hooks.acme-ops.internal/erp-billing", "record.updated", "delivered", 1, 3, 200, None, 16),
            ("https://hooks.acme-ops.internal/pagerduty-bridge", "approval.requested", "dead_letter", 3, 3, 503, "Webhook transport returned HTTP 503 (upstream maintenance window)", 28),
            ("https://hooks.acme-ops.internal/slack-secops", "api_key.created", "delivered", 1, 3, 200, None, 44),
            ("https://hooks.acme-ops.internal/warehouse-cdc", "import.committed", "retrying", 2, 4, 504, "Upstream timeout after 5000ms waiting for TLS handshake", 62),
            ("https://hooks.acme-ops.internal/pagerduty-bridge", "record.updated", "delivered", 1, 3, 200, None, 95),
            ("https://hooks.acme-ops.internal/audit-siem", "approval.resolved", "delivered", 1, 3, 200, None, 130),
            ("https://hooks.acme-ops.internal/erp-billing", "record.created", "dead_letter", 3, 3, 502, "Bad Gateway from legacy SAP billing receiver", 190),
            ("https://hooks.acme-ops.internal/slack-secops", "record.restored", "delivered", 1, 3, 200, None, 250),
            ("https://hooks.acme-ops.internal/audit-siem", "job.succeeded", "delivered", 1, 3, 200, None, 310),
        ]
        for idx, (url, ev, st, att, max_att, code, err, mins) in enumerate(wh_specs):
            ts = now - timedelta(minutes=mins)
            deck.webhook_delivery_store.record(
                WebhookDeliveryRecord(
                    id=f"wh-demo-{idx + 1:03d}",
                    webhook_url=url,
                    event_name=ev,
                    payload_json=f'{{"event":"{ev}","seq":{idx + 1},"env":"staging"}}',
                    status=st,  # type: ignore[arg-type]
                    attempts=att,
                    max_attempts=max_att,
                    last_status_code=code,
                    last_error=err,
                    created_at=ts,
                    updated_at=ts + timedelta(seconds=att * 2),
                    delivered_at=(ts + timedelta(seconds=1)) if st == "delivered" else None,
                )
            )

    # 7. Background Jobs & Downloadable Compliance Artifact
    if isinstance(deck.job_backend, ThreadPoolJobBackend) and not deck.job_backend.list_jobs(limit=1):
        report_csv = (
            b"timestamp_utc,actor,action,model,record_pk,chain_status\n"
            b"2026-11-23T12:00:00Z,admin,update,organizations,5,VALID\n"
            b"2026-11-23T14:15:00Z,mcp-agent,approval_approved,orders,1,VALID\n"
            b"2026-11-23T16:45:00Z,support,inline_edit,tickets,1,VALID\n"
        )
        deck.job_storage.save(
            report_csv,
            key="jobs/soc2-q4-attestation.csv",
            content_type="text/csv",
        )
        seeded_jobs = [
            JobRecord(
                id="job-demo-005",
                name="audit_chain_snapshot",
                label="Audit Chain Merkle Anchor Snapshot",
                actor_id="admin",
                actor_name="Duhan Güler",
                model_slug="",
                status="succeeded",
                progress=100,
                message="Verified 36 hash-chained audit ledger entries (0 breaks).",
                logs=[
                    "[09:00:01] Starting cryptographic chain scan across flask_deck_audit_logs",
                    "[09:00:02] Verified GENESIS -> seq=36 SHA-256 integrity",
                ],
                created_at=now - timedelta(hours=7),
                started_at=now - timedelta(hours=7),
                finished_at=now - timedelta(hours=7) + timedelta(seconds=2),
            ),
            JobRecord(
                id="job-demo-004",
                name="webhook_dlq_replay",
                label="Replay ERP Webhook Dead-Letter Batch",
                actor_id="support",
                actor_name="Maya Chen",
                model_slug="orders",
                status="failed",
                progress=65,
                message="Failed",
                error="Legacy SAP billing receiver returned HTTP 502 Bad Gateway after 3 retries.",
                logs=[
                    "[11:20:00] Dequeued 2 dead_letter deliveries for replay",
                    "[11:20:04] ERROR: HTTP 502 Bad Gateway from hooks.acme-ops.internal/erp-billing",
                ],
                created_at=now - timedelta(hours=5),
                started_at=now - timedelta(hours=5),
                finished_at=now - timedelta(hours=5) + timedelta(seconds=5),
            ),
            JobRecord(
                id="job-demo-003",
                name="bulk_import_commit",
                label="Async Catalog CSV Import (Q4 SKUs)",
                actor_id="admin",
                actor_name="Duhan Güler",
                model_slug="products",
                status="succeeded",
                progress=100,
                message="Committed +11 created, ~3 updated across 14 SKU rows.",
                logs=[
                    "[13:10:00] Validated SAVEPOINT dry-run preview token",
                    "[13:10:01] Committed 14 product catalog mutations atomically",
                ],
                created_at=now - timedelta(hours=3),
                started_at=now - timedelta(hours=3),
                finished_at=now - timedelta(hours=3) + timedelta(seconds=1),
            ),
            JobRecord(
                id="job-demo-002",
                name="orders_sync_erp",
                label="Sync ERP Ledger (12 Selected Orders)",
                actor_id="admin",
                actor_name="Duhan Güler",
                model_slug="orders",
                status="succeeded",
                progress=100,
                message="Synced 12 order(s) with ERP ledger.",
                logs=[
                    "[15:40:00] Reconciling ORD-2026-1040..ORD-2026-1051",
                    "[15:40:03] Ledger balanced ($148,920.00 settled)",
                ],
                created_at=now - timedelta(hours=2),
                started_at=now - timedelta(hours=2),
                finished_at=now - timedelta(hours=2) + timedelta(seconds=3),
            ),
            JobRecord(
                id="job-demo-001",
                name="soc2_attestation_export",
                label="Generate SOC2 Q4 Attestation Bundle (CSV)",
                actor_id="admin",
                actor_name="Duhan Güler",
                model_slug="",
                status="succeeded",
                progress=100,
                message="Generated signed SOC2 attestation CSV artifact.",
                logs=[
                    "[17:15:00] Exporting tamper-evident audit digest",
                    "[17:15:01] Saved artifact soc2-q4-attestation.csv",
                ],
                created_at=now - timedelta(minutes=42),
                started_at=now - timedelta(minutes=42),
                finished_at=now - timedelta(minutes=42) + timedelta(seconds=1),
                artifact_key="jobs/soc2-q4-attestation.csv",
                artifact_filename="soc2-q4-attestation.csv",
                artifact_mime="text/csv",
            ),
        ]
        with deck.job_backend._lock:
            for job in seeded_jobs:
                deck.job_backend._jobs[job.id] = job


def _seed_demo_iam(auth: SQLAlchemyAuthProvider) -> None:
    """Ensure the three curated DB-backed demo groups and accounts exist idempotently."""
    def _ensure_group(
        *,
        name: str,
        label: str,
        description: str,
        permissions: frozenset[str],
        readonly_fields: dict[str, frozenset[str]] | None = None,
        masked_fields: dict[str, frozenset[str]] | None = None,
    ) -> str:
        existing = auth.get_group_by_name(name)
        if existing is not None:
            return existing.id
        try:
            return auth.create_group(
                name=name,
                label=label,
                description=description,
                permissions=permissions,
                readonly_fields=readonly_fields,
                masked_fields=masked_fields,
            ).id
        except ValueError:
            found = auth.get_group_by_name(name)
            assert found is not None
            return found.id

    g_super_id = _ensure_group(
        name="superadmin",
        label="Superadmin",
        description="Unrestricted platform operations, dry-run imports, and audit revert.",
        permissions=frozenset({"*"}),
    )
    g_sup_id = _ensure_group(
        name="support",
        label="Support Engineer",
        description="Customer operations with PII email masking and read-only financials.",
        permissions=frozenset(
            {
                "*:view",
                "tickets:create",
                "tickets:edit",
                "orders:edit",
                "orders:action:mark_shipped",
                "orders:export",
                "audit:view",
                "rbac:view",
            }
        ),
        masked_fields={"users": frozenset({"email"})},
        readonly_fields={
            "orders": frozenset({"total_cents", "organization_id"}),
            "organizations": frozenset({"mrr_cents", "plan"}),
        },
    )
    g_aud_id = _ensure_group(
        name="auditor",
        label="Compliance Auditor",
        description="Strict read-only inspection across models, exports, and audit ledger.",
        permissions=frozenset({"*:view", "*:export", "audit:view", "rbac:view"}),
        masked_fields={"users": frozenset({"email"})},
    )

    accounts = (
        ("admin", "admin@acme.dev", "Duhan Güler", "admin@acme.dev", True, [g_super_id]),
        ("support", "support@acme.dev", "Maya Chen", "support@acme.dev", False, [g_sup_id]),
        ("viewer", "viewer@acme.dev", "Alex Rivera", "viewer@acme.dev", False, [g_aud_id]),
    )
    for uid, uname, disp, email, is_super, gids in accounts:
        if auth.get_user_record(uid) is None:
            with contextlib.suppress(ValueError):
                auth.create_user(
                    user_id=uid,
                    username=uname,
                    display_name=disp,
                    email=email,
                    is_active=True,
                    is_superuser=is_super,
                    group_ids=gids,
                    password_hash=_DEMO_PASSWORD_HASH,
                )


def create_demo_app(
    db_uri: str = "sqlite:///:memory:",
    *,
    secret_key: str | None = None,
    seed_profile: Literal["standard", "showcase"] = "standard",
    auto_daily_reset: bool = False,
    reset_timezone: str = "Europe/Istanbul",
    stateless_ephemeral_sessions: bool = False,
    demo_safe_mode: bool = False,
) -> Flask:
    """Create the complete Acme Cloud Ops SaaS demo Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secret_key or os.environ.get("FLASK_DECK_SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    connect_args = {"check_same_thread": False} if db_uri.startswith("sqlite") else {}
    pool_kwargs: dict[str, Any] = {}
    if db_uri == "sqlite:///:memory:":
        from sqlalchemy.pool import StaticPool

        pool_kwargs["poolclass"] = StaticPool

    engine = sa.create_engine(db_uri, connect_args=connect_args, **pool_kwargs)
    if db_uri.startswith("sqlite:///") and db_uri != "sqlite:///:memory:":
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA busy_timeout=5000")
    DemoBase.metadata.create_all(engine)
    _DEMO_STATE_META.create_all(engine, checkfirst=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    audit_store = SQLAlchemyAuditStore(engine, hash_chain=True)
    _seed_demo_data(session_factory, audit_store, seed_profile=seed_profile)

    demo_pwd = "deck-demo-2026"
    auth = SQLAlchemyAuthProvider(
        engine,
        password_min_length=8,
        demo_account_ids=("admin", "support", "viewer"),
    )
    _seed_demo_iam(auth)

    ephemeral_session_store = (
        _EphemeralServerlessSessionStore(engine)
        if stateless_ephemeral_sessions and db_uri == "sqlite:///:memory:"
        else None
    )

    deck = Deck(
        app,
        session_factory=session_factory,
        engine=engine,
        auth=auth,
        audit_store=audit_store,
        session_store=ephemeral_session_store,
        title="Acme Ops",
        subtitle="Cloud Infrastructure & Billing Control Plane",
        environment="staging",
        enable_sql_console=True,
        enable_rest_api=True,
        enable_mcp=True,
        demo_role_switcher=True,
        demo_safe_mode=demo_safe_mode,
        site_url="https://github.com/duhanguler/flask-deck",
        sidebar_order=("Customers", "Commerce", "Operations"),
        brand=BrandConfig(
            accent="monochrome",
            footer_note="Acme Cloud Ops",
            login_notice=(
                (
                    f"Demo Safe Mode (IAM & Destructive Ops Locked) · Auto-Resets Daily at 00:00 ({reset_timezone})"
                    if demo_safe_mode
                    else f"SOC2 Type II Audited · Auto-Resets Daily at 00:00 ({reset_timezone})"
                )
                if auto_daily_reset
                else (
                    "Demo Safe Mode (IAM & Destructive Ops Locked) · Select a Demo RBAC Profile Below"
                    if demo_safe_mode
                    else "SOC2 Type II Audited · Select a Demo RBAC Profile Below"
                )
            ),
        ),
        demo_credentials=[
            ("admin@acme.dev", demo_pwd, "Superadmin · Full Access"),
            ("support@acme.dev", demo_pwd, "Support · Masked PII + RO Billing"),
            ("viewer@acme.dev", demo_pwd, "Auditor · Strict Read-Only"),
        ],
        sql_presets=[
            (
                "Top Orgs by MRR",
                "SELECT name, plan, mrr_cents / 100 AS mrr_usd, seats_used, seats_limit FROM demo_organizations ORDER BY mrr_cents DESC LIMIT 10",
            ),
            (
                "PII Auto-Redaction Demo",
                "SELECT id, full_name, email, role, password_hash, api_token FROM demo_users ORDER BY id LIMIT 8",
            ),
            (
                "Order Status Summary",
                "SELECT status, COUNT(*) AS orders, SUM(total_cents) / 100 AS volume_usd FROM demo_orders GROUP BY status ORDER BY orders DESC",
            ),
            (
                "Category Revenue Split",
                "SELECT p.category, COUNT(*) AS line_items, SUM(oi.quantity * oi.unit_price_cents) / 100 AS revenue_usd FROM demo_order_items oi JOIN demo_products p ON p.id = oi.product_id GROUP BY p.category ORDER BY revenue_usd DESC",
            ),
            (
                "Enterprise Seat Pressure (>80%)",
                "SELECT name, plan, seats_used, seats_limit, ROUND(100.0 * seats_used / seats_limit, 1) AS util_pct FROM demo_organizations WHERE is_active = TRUE AND (100.0 * seats_used / seats_limit) >= 80 ORDER BY util_pct DESC",
            ),
            (
                "Fleet Topology Health",
                "SELECT code, name, node_type, health_pct, is_active FROM demo_infrastructure_nodes ORDER BY health_pct ASC LIMIT 12",
            ),
        ],
    )
    deck.register(
        OrganizationView,
        UserView,
        ProductView,
        OrderView,
        SupportTicketView,
        InfrastructureNodeView,
    )
    if seed_profile == "showcase":
        _seed_showcase_control_plane(deck, session_factory, datetime.now(timezone.utc))

    @deck.scheduled_job(
        "nightly_billing_reconcile",
        schedule="0 2 * * *",
        label="Reconcile Enterprise Billing",
        description="Verify active MRR commitments against settled payment ledger.",
    )
    def _nightly_billing_reconcile(job_ctx: JobContext) -> str:
        job_ctx.set_progress(40, "Scanning active enterprise subscriptions…")
        job_ctx.log("Reconciled active MRR & settled order totals against ledger.")
        job_ctx.set_progress(100, "Billing reconciliation complete")
        return "Reconciled enterprise MRR and order totals cleanly."

    @deck.scheduled_job(
        "sla_breach_digest",
        schedule="*/15 * * * *",
        label="Check Critical SLA Budgets",
        description="Scan open Critical & High tickets below 45% SLA remaining.",
    )
    def _sla_breach_digest(job_ctx: JobContext) -> str:
        job_ctx.set_progress(50, "Evaluating open ticket SLA thresholds…")
        job_ctx.log("Checked Critical/High queue SLA budgets across active tenants.")
        job_ctx.set_progress(100, "SLA digest emitted")
        return "Evaluated open SLA budgets and dispatched alert digest."

    @deck.scheduled_job(
        "audit_chain_snapshot",
        schedule="0 * * * *",
        label="Verify & Snapshot Audit Chain",
        description="Validate cryptographic SHA-256 hash chain across flask_deck_audit_logs.",
    )
    def _audit_chain_snapshot(job_ctx: JobContext) -> str:
        ok, err = audit_store.verify_chain()
        job_ctx.log(f"Hash chain verification result: ok={ok}")
        job_ctx.set_progress(100, "Verified" if ok else f"Broken: {err}")
        return "Audit hash chain integrity verified (0 tamper breaks)." if ok else f"Chain check failed: {err}"

    @deck.dashboard
    def acme_dashboard(ctx: DashboardContext) -> list[Widget]:
        sess = ctx.session
        total_mrr = int(sess.scalar(sa.select(sa.func.coalesce(sa.func.sum(Organization.mrr_cents), 0)).where(Organization.is_active.is_(True))) or 0)
        orgs_all = list(sess.scalars(sa.select(Organization).order_by(Organization.mrr_cents.desc())).all())
        active_orgs = sum(1 for o in orgs_all if o.is_active)
        order_total = int(sess.scalar(sa.select(sa.func.coalesce(sa.func.sum(Order.total_cents), 0)).where(Order.status.in_([OrderStatus.PAID, OrderStatus.SHIPPED]))) or 0)
        tickets_all = list(
            sess.scalars(
                sa.select(SupportTicket)
                .where(SupportTicket.deleted_at.is_(None))
                .order_by(SupportTicket.sla_health.asc())
            ).all()
        )
        open_tickets = sum(1 for t in tickets_all if t.status in {TicketStatus.OPEN, TicketStatus.IN_PROGRESS})
        critical_open = sum(
            1
            for t in tickets_all
            if t.priority == TicketPriority.CRITICAL and t.status in {TicketStatus.OPEN, TicketStatus.IN_PROGRESS}
        )
        critical_t = next(
            (
                t
                for t in tickets_all
                if t.priority == TicketPriority.CRITICAL
                and t.status in {TicketStatus.OPEN, TicketStatus.IN_PROGRESS}
            ),
            None,
        )
        total_seats_used = sum(o.seats_used for o in orgs_all if o.is_active)
        total_seats_lim = sum(o.seats_limit for o in orgs_all if o.is_active)
        seat_util_pct = int(total_seats_used / max(1, total_seats_lim) * 100)

        span_days = ctx.range_days
        labels = ctx.last_n_days(span_days)
        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=span_days - 1)
        rev_buckets = [0.0] * span_days
        all_orders = list(sess.scalars(sa.select(Order)).all())
        status_counts: dict[str, int] = {"paid": 0, "shipped": 0, "pending": 0, "refunded": 0}
        for o in all_orders:
            status_counts[o.status.value] = status_counts.get(o.status.value, 0) + 1
            if isinstance(o.created_at, datetime):
                delta_d = (o.created_at.date() - start_day).days
                if 0 <= delta_d < span_days and o.status in {OrderStatus.PAID, OrderStatus.SHIPPED}:
                    rev_buckets[delta_d] += o.total_cents / 100.0

        # Deterministic 91-day activity heatmap series
        heatmap_cells: list[tuple[str, int]] = []
        for offset in range(90, -1, -1):
            d = today - timedelta(days=offset)
            val = ((d.toordinal() * 7 + d.weekday() * 3) % 11)
            if d.weekday() >= 5:
                val = val // 3
            heatmap_cells.append((d.strftime("%Y-%m-%d"), val))

        seat_bars = [
            {
                "label": o.name,
                "value": o.seats_used,
                "max": o.seats_limit,
                "meta": f"{o.seats_used}/{o.seats_limit} ({int(o.seats_used / max(1, o.seats_limit) * 100)}%)",
                "tone": "warn" if (o.seats_used / max(1, o.seats_limit)) >= 0.84 else "ok",
            }
            for o in orgs_all[:5]
        ]

        recent_orders = list(
            sess.scalars(
                sa.select(Order)
                .options(sa.orm.joinedload(Order.organization))
                .order_by(Order.created_at.desc())
                .limit(5)
            ).all()
        )
        status_fmt = BadgeFormatter({"paid": "ok", "shipped": "info", "pending": "warn", "refunded": "danger"})
        money_fmt = CurrencyFormatter(currency="USD", divisor=100)
        code_fmt = CodeFormatter(copyable=True)

        widgets: list[Widget] = []
        if critical_t is not None:
            widgets.append(
                CalloutWidget(
                    title=f"Critical SLA Alert · {critical_t.ticket_key}",
                    message=f"{critical_t.subject} ({critical_t.sla_health}% SLA budget remaining)",
                    tone="danger",
                    action_label="Open Kanban Board",
                    action_href=f"{ctx.url_for_model(SupportTicket)}?view=board",
                    col_span=12,
                )
            )

        widgets.extend(
            [
                KPIWidget(
                    title="Active MRR",
                    value=f"${total_mrr / 100:,.0f}",
                    delta="+14.2% MoM",
                    trend="up",
                    icon="dollar-sign",
                    href=ctx.url_for_model(Organization),
                    sparkline=[178, 184, 192, 198, 206, 214, total_mrr / 10000.0],
                    col_span=3,
                ),
                KPIWidget(
                    title=f"Settled Volume ({span_days}d)",
                    value=f"${order_total / 100:,.0f}",
                    delta=f"{len(all_orders)} orders",
                    trend="up",
                    icon="shopping-bag",
                    href=ctx.url_for_model(Order),
                    sparkline=rev_buckets[-7:],
                    col_span=3,
                ),
                KPIWidget(
                    title="Active Organizations",
                    value=str(active_orgs),
                    delta=f"{seat_util_pct}% seat utilization",
                    trend="up",
                    icon="building",
                    href=ctx.url_for_model(Organization),
                    sparkline=[4, 5, 5, 6, 6, 7, float(active_orgs)],
                    col_span=3,
                ),
                KPIWidget(
                    title="Open SLA Tickets",
                    value=str(open_tickets),
                    delta=f"{critical_open} critical (<4h SLA)",
                    trend="down" if open_tickets >= 4 else "flat",
                    icon="life-buoy",
                    href=f"{ctx.url_for_model(SupportTicket)}?view=board",
                    sparkline=[2, 3, 2, 4, 3, 5, float(open_tickets)],
                    col_span=3,
                ),
                ChartWidget(
                    title=f"Settled Revenue Trend ({span_days}d)",
                    subtitle="Daily paid + shipped order volume in USD (pure SSR SVG)",
                    chart_type="area",
                    labels=labels,
                    series=[{"name": "Revenue ($)", "data": rev_buckets, "tone": "primary"}],
                    col_span=8,
                ),
                ChartWidget(
                    title="Order Fulfillment Split",
                    subtitle="Live distribution across lifecycle states",
                    chart_type="donut",
                    labels=["Paid", "Shipped", "Pending", "Refunded"],
                    series=[
                        {
                            "data": [
                                status_counts["paid"],
                                status_counts["shipped"],
                                status_counts["pending"],
                                status_counts["refunded"],
                            ],
                            "tones": ["ok", "info", "warn", "danger"],
                        }
                    ],
                    center_label="Orders",
                    col_span=4,
                ),
                HeatmapWidget(
                    title="91-Day Operational Event Density",
                    subtitle="Daily billing, provisioning & mutation volume (zero JS chart library)",
                    cells=heatmap_cells,
                    unit="events",
                    col_span=8,
                ),
                StatBarWidget(
                    title="Enterprise Seat Utilization",
                    subtitle="Active seat allocation vs contracted quota",
                    items=seat_bars,
                    col_span=4,
                ),
                TableWidget(
                    title="Latest Orders",
                    subtitle="Most recent enterprise billing events",
                    headers=["Order #", "Organization", "Status", "Total"],
                    rows=[
                        [
                            code_fmt.format(o.order_number),
                            o.organization.name if o.organization else "—",
                            status_fmt.format(o.status),
                            money_fmt.format(o.total_cents),
                        ]
                        for o in recent_orders
                    ],
                    href=ctx.url_for_model(Order),
                    href_label="All Orders",
                    col_span=6,
                ),
                ActivityWidget(
                    title="Recent Audit Ledger",
                    subtitle="Immutable field-level diffs captured across operators",
                    limit=5,
                    col_span=6,
                ),
            ]
        )
        if (
            deck.saved_query_store is not None
            and deck.config.enable_sql_console
            and deck.auth.has_permission(ctx.user, "sql:query")
            and deck.adapter is not None
        ):
            pinned_queries = deck.saved_query_store.list_queries(pinned_only=True, limit=4)
            engines = deck.adapter.get_engines()
            for sq in pinned_queries:
                target_eng = engines.get(sq.bind_key) if sq.bind_key else deck.adapter.get_engine()
                if target_eng is None:
                    continue
                q_res = execute_readonly_sql(
                    target_eng,
                    sq.sql,
                    max_rows=min(25, deck.config.sql_console_max_rows),
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                if q_res.error:
                    continue
                chart_pair = extract_sql_chart_data(q_res) if sq.chart_type in {"bar", "line"} else None
                if chart_pair is not None:
                    c_labels, c_series = chart_pair
                    widgets.append(
                        ChartWidget(
                            title=sq.name,
                            subtitle=f"Pinned BI ({sq.bind_key or 'default'})",
                            chart_type="area" if sq.chart_type == "line" else "bar",
                            labels=c_labels,
                            series=c_series,
                            col_span=6,
                        )
                    )
                else:
                    widgets.append(
                        TableWidget(
                            title=sq.name,
                            subtitle=f"Pinned SQL ({sq.bind_key or 'default'})",
                            headers=list(q_res.columns),
                            rows=[list(r) for r in q_res.rows[:10]],
                            col_span=6,
                        )
                    )
        return widgets

    @deck.page(
        "sla-monitor",
        title="SLA & Capacity",
        icon="cpu",
        category="Operations",
        subtitle="Custom @deck.page operational view with pure SVG gauges, grouped bars & incident timeline",
    )
    def sla_monitor_page(ctx: DashboardContext) -> list[Widget]:
        sess = ctx.session
        products = list(sess.scalars(sa.select(Product).order_by(Product.stock_pct.asc())).all())
        avg_cap = sum(p.stock_pct for p in products) / max(1, len(products))
        return [
            GaugeWidget(
                title="Fleet Capacity Headroom",
                subtitle="Weighted across compute, storage & edge networking",
                value=round(avg_cap, 1),
                gauge_label="Available",
                tone="ok" if avg_cap >= 60 else "warn",
                details=[
                    ("Compute Nodes", "85% avg"),
                    ("Storage Pools", "78% avg"),
                    ("Networking", "28% low"),
                ],
                col_span=4,
            ),
            ChartWidget(
                title="Capacity vs Demand by Tier",
                subtitle="Grouped SVG bar comparison across infrastructure categories",
                chart_type="grouped_bar",
                labels=["Compute", "Storage", "Networking", "Add-ons"],
                series=[
                    {"name": "Provisioned %", "data": [85, 79, 28, 100], "tone": "primary"},
                    {"name": "Reserved %", "data": [62, 54, 72, 41], "tone": "ok"},
                ],
                col_span=8,
            ),
            StatBarWidget(
                title="Per-SKU Capacity Utilization",
                subtitle="Live inventory headroom across infrastructure SKUs",
                items=[
                    {
                        "label": f"{p.sku} · {p.name}",
                        "value": p.stock_pct,
                        "max": 100,
                        "meta": f"{p.stock_pct}%",
                        "tone": "danger" if p.stock_pct <= 25 else ("warn" if p.stock_pct <= 45 else "ok"),
                    }
                    for p in products
                ],
                col_span=6,
            ),
            TimelineWidget(
                title="Infrastructure Incident & Provisioning Timeline",
                subtitle="Latest cluster operations and SLA events",
                events=[
                    {"title": "OPS-412 · BGP peering failover opened", "detail": "Kestrel FinTech · eu-central-1 PrivateLink", "time": "3h ago", "tone": "danger", "href": f"{ctx.url_for_model(SupportTicket)}?view=board"},
                    {"title": "OPS-411 · H200 cluster quota expansion requested", "detail": "Northstar Robotics · 32 → 64 GPUs", "time": "7h ago", "tone": "warn"},
                    {"title": "Meridian BioAI upgraded Growth → Enterprise", "detail": "MRR updated $2,400 → $5,100 · audited", "time": "2h ago", "tone": "ok"},
                    {"title": "Q4 catalog batch CSV committed", "detail": "4 created, 3 updated via SAVEPOINT dry-run", "time": "5h ago", "tone": "info"},
                ],
                col_span=6,
            ),
        ]

    tz = _resolve_tz(reset_timezone)
    reset_lock = threading.RLock()
    state: dict[str, str] = {"last_reset_day": datetime.now(tz).date().isoformat()}

    def _read_db_reset_day() -> str | None:
        with engine.connect() as conn:
            row = conn.execute(
                sa.select(_DEMO_STATE_TABLE.c.value).where(_DEMO_STATE_TABLE.c.key == "last_reset_day")
            ).scalar_one_or_none()
        return str(row) if isinstance(row, str) else None

    def _write_db_reset_day(day_str: str) -> None:
        with engine.begin() as conn:
            conn.execute(
                _DEMO_STATE_TABLE.delete().where(_DEMO_STATE_TABLE.c.key == "last_reset_day")
            )
            conn.execute(
                _DEMO_STATE_TABLE.insert().values(key="last_reset_day", value=day_str)
            )

    def _reset_demo_state(*, force: bool = True, current_day: str | None = None) -> dict[str, Any]:
        target_day = current_day or datetime.now(tz).date().isoformat()
        with reset_lock:
            if not force:
                existing_day = _read_db_reset_day()
                if existing_day == target_day:
                    state["last_reset_day"] = target_day
                    return {
                        "reset": False,
                        "reset_day": target_day,
                        "timezone": reset_timezone,
                        "seed_profile": seed_profile,
                    }

            if engine.dialect.name == "postgresql":
                with engine.begin() as conn:
                    conn.execute(
                        sa.text(
                            "TRUNCATE TABLE demo_order_items, demo_orders, demo_tickets, "
                            "demo_users, demo_products, demo_organizations, "
                            "demo_infrastructure_nodes RESTART IDENTITY CASCADE"
                        )
                    )
            else:
                DemoBase.metadata.drop_all(engine)
                DemoBase.metadata.create_all(engine)

            stores: tuple[Any, ...] = (
                deck.audit_store,
                deck.approval_store,
                deck.saved_query_store,
                deck.saved_view_store,
                deck.note_store,
                deck.api_key_store,
                deck.webhook_delivery_store,
                deck.mfa_store,
                deck.passkey_store,
                deck.session_store,
                deck._preview_store,
                deck._rate_limiter,
                deck.job_backend,
            )
            with engine.begin() as conn:
                for store in stores:
                    tbl = getattr(store, "_table", None)
                    if isinstance(tbl, sa.Table):
                        conn.execute(tbl.delete())

            if deck.approval_store is not None and hasattr(deck.approval_store, "_pending_cache"):
                deck.approval_store._pending_cache = None
            if deck.saved_view_store is not None and hasattr(deck.saved_view_store, "_model_cache"):
                model_cache = deck.saved_view_store._model_cache
                if isinstance(model_cache, dict):
                    model_cache.clear()
            deck._staged_imports.clear()

            with DEMO_MEDIA_STORAGE._lock:
                DEMO_MEDIA_STORAGE._entries.clear()
            if isinstance(deck.job_storage, MemoryFileStorage):
                with deck.job_storage._lock:
                    deck.job_storage._entries.clear()
            if isinstance(deck.job_backend, ThreadPoolJobBackend):
                with deck.job_backend._lock:
                    deck.job_backend._jobs.clear()
                    deck.job_backend._cancel_events.clear()
                    deck.job_backend._callables.clear()

            auth.reset_all()
            _seed_demo_iam(auth)
            _seed_demo_data(session_factory, audit_store, seed_profile=seed_profile)
            if seed_profile == "showcase":
                _seed_showcase_control_plane(deck, session_factory, datetime.now(timezone.utc))

            _write_db_reset_day(target_day)
            state["last_reset_day"] = target_day
            return {
                "reset": True,
                "reset_day": target_day,
                "timezone": reset_timezone,
                "seed_profile": seed_profile,
                "reset_at": datetime.now(timezone.utc).isoformat(),
            }

    app.extensions["flask_deck_demo_reset"] = _reset_demo_state

    startup_day = datetime.now(tz).date().isoformat()
    existing_day = _read_db_reset_day()
    if existing_day is None:
        _write_db_reset_day(startup_day)
        state["last_reset_day"] = startup_day
    elif auto_daily_reset and existing_day != startup_day:
        _reset_demo_state(force=True, current_day=startup_day)
    else:
        state["last_reset_day"] = existing_day

    if auto_daily_reset:
        def _check_daily_demo_reset() -> None:
            path = request.path
            if path.startswith("/admin/static/") or path == "/api/cron/reset-demo":
                return None
            today_str = datetime.now(tz).date().isoformat()
            if today_str != state["last_reset_day"]:
                _reset_demo_state(force=False, current_day=today_str)
            return None

        app.before_request_funcs.setdefault(None, []).insert(0, _check_daily_demo_reset)

    if ephemeral_session_store is not None:
        @app.before_request
        def _hydrate_ephemeral_session() -> None:
            if not request.path.rstrip("/").endswith("/_security/sessions"):
                return None
            uid = flask_session.get(AUTH_USER_KEY)
            sid = flask_session.get(DECK_SID_SESSION_KEY)
            if isinstance(uid, str) and uid and isinstance(sid, str) and sid:
                u = auth.get_user_by_id(uid)
                ephemeral_session_store.ensure_session(
                    session_id=sid,
                    user_id=uid,
                    username=u.username if u is not None else uid,
                    ip_address=str(request.remote_addr or "127.0.0.1"),
                    user_agent=str(request.headers.get("User-Agent", "")),
                )
            return None

    @app.route("/api/cron/reset-demo", methods=["GET", "POST"])
    def cron_reset_demo() -> Any:
        cron_secret = os.environ.get("CRON_SECRET", "").strip()
        auth_header = request.headers.get("Authorization", "")
        if not cron_secret or not hmac.compare_digest(auth_header, f"Bearer {cron_secret}"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        result = _reset_demo_state(force=True)
        return jsonify({"ok": True, **result}), 200

    @app.route("/")
    def root_redirect() -> Any:
        return redirect("/admin/")

    return app
