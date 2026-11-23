from __future__ import annotations

import enum
import os
import secrets
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any

import sqlalchemy as sa
from flask import Flask, redirect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck.audit import SQLAlchemyAuditStore, make_audit_entry
from flask_deck.auth import DeckUser, RBACAuthProvider, Role
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
from flask_deck.jobs import JobContext
from flask_deck.model_view import ActionField, InlineModelView, ModelView, action
from flask_deck.query import QuickTab
from flask_deck.storage import FileFieldConfig, MemoryFileStorage, make_demo_png

DEMO_MEDIA_STORAGE = MemoryFileStorage()


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


# ---- Declarative ModelViews ----


class OrganizationView(ModelView):
    model = Organization
    icon = "building"
    category = "Customers"
    columns = ("name", "slug", "plan", "mrr_cents", "seats_used", "is_active", "created_at")
    searchable_columns = ("name", "slug")
    filterable_columns = ("plan", "is_active", "created_at")
    inline_editable_columns = ("is_active", "plan")
    column_labels = MappingProxyType({"mrr_cents": "MRR", "seats_used": "Seats"})
    column_aggregates = MappingProxyType({"mrr_cents": "sum", "seats_used": "sum"})
    form_layout = "tabs"
    field_widgets = MappingProxyType({"plan": "segmented"})
    saved_views = (
        ("Enterprise Only", "?tab=enterprise"),
        ("Paused Orgs", "?f_is_active=false"),
    )
    fieldsets = (
        ("Organization Identity", ("name", "slug", "plan", "is_active")),
        ("Billing & Quotas", ("mrr_cents", "seats_used", "seats_limit")),
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
    filterable_columns = ("category", "is_active", "price_cents", "metadata_json")
    inline_editable_columns = ("is_active",)
    import_key_columns = ("sku",)
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
    columns = ("product_id", "quantity", "unit_price_cents")
    order_by = "id"


class OrderView(ModelView):
    model = Order
    icon = "shopping-bag"
    category = "Commerce"
    columns = ("order_number", "organization", "customer", "status", "total_cents", "created_at")
    searchable_columns = ("order_number", "organization.name", "customer.email")
    filterable_columns = ("status", "organization_id", "total_cents", "created_at")
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
        ("Order Summary", ("order_number", "organization_id", "customer_id", "status")),
        ("Billing & Markdown Notes", ("total_cents", "notes")),
    )

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
    columns = ("ticket_key", "subject", "organization", "priority", "status", "sla_health", "created_at")
    searchable_columns = ("ticket_key", "subject")
    filterable_columns = ("priority", "status", "organization_id", "created_at")
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


def _seed_demo_data(session_factory: sessionmaker[Any], audit_store: SQLAlchemyAuditStore) -> None:
    now = datetime.now(timezone.utc)
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
        sess.add_all(users)
        sess.flush()

        sample_pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
        DEMO_MEDIA_STORAGE.save(sample_pdf, key="products/specs/acme-cloud-datasheet.pdf", content_type="application/pdf")
        palette = [
            (96, 165, 250),
            (74, 222, 128),
            (251, 191, 36),
            (244, 244, 245),
            (248, 113, 113),
            (96, 165, 250),
            (74, 222, 128),
        ]
        thumb_keys: list[str] = []
        for idx, acc in enumerate(palette):
            key = f"products/thumbs/sku-{idx + 1}.png"
            DEMO_MEDIA_STORAGE.save(make_demo_png(64, 64, accent=acc), key=key, content_type="image/png")
            thumb_keys.append(key)

        products = [
            Product(sku="GPU-H200-8X", name="Dedicated H200 8x Cluster Node", category=ProductCategory.COMPUTE, price_cents=245000, stock_pct=78, thumbnail_path=thumb_keys[0], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "eu-central-1", "vram_gb": 1128}),
            Product(sku="CPU-ARM-64", name="Graviton4 64-vCPU Bare Metal", category=ProductCategory.COMPUTE, price_cents=42000, stock_pct=92, thumbnail_path=thumb_keys[1], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "us-east-1", "arch": "arm64", "ecc": True}),
            Product(sku="NVME-10TB", name="Replicated NVMe Block Pool (10 TB)", category=ProductCategory.STORAGE, price_cents=31000, stock_pct=61, thumbnail_path=thumb_keys[2], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "eu-central-1", "iops": 120000}),
            Product(sku="OBJ-S3-COLD", name="Immutable Audit Object Vault", category=ProductCategory.STORAGE, price_cents=12500, stock_pct=96, thumbnail_path=thumb_keys[3], metadata_json={"region": "eu-west-1", "worm": True}),
            Product(sku="NET-ANYCAST", name="Global Anycast Edge Ingress", category=ProductCategory.NETWORKING, price_cents=18000, stock_pct=38, thumbnail_path=thumb_keys[4], metadata_json={"region": "global", "pops": 44}),
            Product(sku="NET-PRIVLINK", name="Zero-Trust PrivateLink Tunnel", category=ProductCategory.NETWORKING, price_cents=15000, stock_pct=18, thumbnail_path=thumb_keys[5], metadata_json={"region": "eu-central-1", "mtls": True}),
            Product(sku="ADD-SOC2-LOG", name="7-Year Compliance Audit Retention", category=ProductCategory.ADDON, price_cents=29000, stock_pct=100, thumbnail_path=thumb_keys[6], spec_sheet_path="products/specs/acme-cloud-datasheet.pdf", metadata_json={"region": "global", "packs": ["SOC2", "ISO27001"]}),
        ]
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
        orders: list[Order] = []
        for idx in range(28):
            org = orgs[idx % len(orgs)]
            usr = users[idx % len(users)]
            st = status_cycle[idx % len(status_cycle)]
            p1 = products[idx % len(products)]
            p2 = products[(idx + 2) % len(products)]
            qty1 = 1 + (idx % 3)
            total = p1.price_cents * qty1 + p2.price_cents
            days_ago = idx % 14
            ord_obj = Order(
                order_number=f"ORD-2026-{1040 + idx}",
                organization_id=org.id,
                customer_id=usr.id,
                status=st,
                total_cents=total,
                notes="Provisioned via automated enterprise billing cycle.",
                created_at=now - timedelta(days=days_ago, hours=(idx * 3) % 20),
            )
            sess.add(ord_obj)
            sess.flush()
            sess.add_all(
                [
                    OrderItem(order_id=ord_obj.id, product_id=p1.id, quantity=qty1, unit_price_cents=p1.price_cents),
                    OrderItem(order_id=ord_obj.id, product_id=p2.id, quantity=1, unit_price_cents=p2.price_cents),
                ]
            )
            orders.append(ord_obj)

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
        sess.add_all(tickets)
        sess.commit()

        # Pre-seed crisp realistic Audit Ledger entries
        seed_audits = [
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
                model_slug="organizations",
                model_label="Organization",
                record_pk=str(orgs[4].id),
                record_repr=orgs[4].name,
                changes={"plan": {"old": "growth", "new": "enterprise"}, "mrr_cents": {"old": 240000, "new": 510000}},
                timestamp=now - timedelta(hours=2),
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
                model_slug="users",
                model_label="User",
                record_pk=str(users[1].id),
                record_repr=users[1].full_name,
                changes={"role": {"old": "engineer", "new": "admin"}, "api_token": {"old": "[REDACTED]", "new": "[REDACTED]"}},
                timestamp=now - timedelta(hours=9),
            ),
        ]
        for entry in seed_audits:
            audit_store.record(entry)


def create_demo_app(
    db_uri: str = "sqlite:///:memory:",
    *,
    secret_key: str | None = None,
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
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    audit_store = SQLAlchemyAuditStore(engine, hash_chain=True)
    _seed_demo_data(session_factory, audit_store)

    roles = [
        Role(
            name="superadmin",
            label="Superadmin",
            description="Unrestricted platform operations, dry-run imports, and audit revert.",
            permissions=frozenset({"*"}),
        ),
        Role(
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
        ),
        Role(
            name="auditor",
            label="Compliance Auditor",
            description="Strict read-only inspection across models, exports, and audit ledger.",
            permissions=frozenset({"*:view", "*:export", "audit:view", "rbac:view"}),
            masked_fields={"users": frozenset({"email"})},
        ),
    ]

    demo_pwd = "deck-demo-2026"
    auth = RBACAuthProvider(
        roles=roles,
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="admin",
                    username="admin@acme.dev",
                    display_name="Duhan Güler",
                    email="admin@acme.dev",
                    roles=("superadmin",),
                    is_superuser=True,
                ),
                password=demo_pwd,
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="support",
                    username="support@acme.dev",
                    display_name="Maya Chen",
                    email="support@acme.dev",
                    roles=("support",),
                ),
                password=demo_pwd,
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="viewer",
                    username="viewer@acme.dev",
                    display_name="Alex Rivera",
                    email="viewer@acme.dev",
                    roles=("auditor",),
                ),
                password=demo_pwd,
            ),
        ],
    )

    deck = Deck(
        app,
        session_factory=session_factory,
        engine=engine,
        auth=auth,
        audit_store=audit_store,
        title="Acme Ops",
        subtitle="Cloud Infrastructure & Billing Control Plane",
        environment="staging",
        enable_sql_console=True,
        enable_rest_api=True,
        enable_mcp=True,
        demo_role_switcher=True,
        brand=BrandConfig(
            accent="monochrome",
            footer_note="Acme Cloud Ops",
            login_notice="SOC2 Type II Audited · Select a Demo RBAC Profile Below",
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
        ],
    )
    deck.register(OrganizationView, UserView, ProductView, OrderView, SupportTicketView)

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
        critical_t = next((t for t in tickets_all if t.priority == TicketPriority.CRITICAL and t.status != TicketStatus.RESOLVED), None)

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
                    delta="87% enterprise seats",
                    trend="up",
                    icon="building",
                    href=ctx.url_for_model(Organization),
                    sparkline=[4, 5, 5, 6, 6, 7, float(active_orgs)],
                    col_span=3,
                ),
                KPIWidget(
                    title="Open SLA Tickets",
                    value=str(open_tickets),
                    delta="1 critical (<4h SLA)",
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

    @app.route("/")
    def root_redirect() -> Any:
        return redirect("/admin/")

    return app
