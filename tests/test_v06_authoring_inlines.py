from __future__ import annotations

import io
from collections.abc import Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask, Response
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    ColorWidget,
    Deck,
    DeckUser,
    Fieldset,
    FileFieldConfig,
    InlineModelView,
    InMemoryAuditStore,
    MemoryFileStorage,
    ModelView,
    RBACAuthProvider,
    Role,
    VirtualField,
    action,
    display,
)
from flask_deck.storage import make_demo_png
from tests.conftest import login_as


class ABase(DeclarativeBase):
    pass


class ADivision(ABase):
    __tablename__ = "v06_a_divisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    def __str__(self) -> str:
        return self.name


class AOrder(ABase):
    __tablename__ = "v06_a_orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(20), default="draft", nullable=False)
    amount: Mapped[int] = mapped_column(sa.Integer, default=100, nullable=False)
    division_id: Mapped[int | None] = mapped_column(sa.ForeignKey("v06_a_divisions.id"), nullable=True)
    accent: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    locked_by_owner: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    division: Mapped[ADivision | None] = relationship()
    lines: Mapped[list[ALine]] = relationship(back_populates="order", cascade="all, delete-orphan")
    comp_items: Mapped[list[ACompositeItem]] = relationship(
        back_populates="order", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return self.code


class ALine(ABase):
    __tablename__ = "v06_a_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(sa.ForeignKey("v06_a_orders.id"), nullable=False)
    sku: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    unit_price: Mapped[int] = mapped_column(sa.Integer, default=10, nullable=False)
    attachment_path: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    color: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    hidden_scope: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    order: Mapped[AOrder] = relationship(back_populates="lines")


class ACompositeItem(ABase):
    __tablename__ = "v06_a_comp_items"
    order_id: Mapped[int] = mapped_column(sa.ForeignKey("v06_a_orders.id"), primary_key=True)
    slot_no: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    note: Mapped[str] = mapped_column(sa.String(80), nullable=False)

    order: Mapped[AOrder] = relationship(back_populates="comp_items")


@pytest.fixture()
def authoring_bundle() -> Iterator[tuple[Flask, Deck, MemoryFileStorage, InMemoryAuditStore, list[dict[str, Any]]]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "v06-authoring-secret-key-at-least-32-bytes"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    ABase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    storage = MemoryFileStorage()
    audit_store = InMemoryAuditStore()
    hook_log: list[dict[str, Any]] = []

    with SessionLocal() as sess:
        d_act = ADivision(name="Active Div", is_active=True)
        d_inact = ADivision(name="Archived Div", is_active=False)
        d_del = ADivision(name="Deletable Div", is_active=True)
        # Extra divisions for paginated FK test
        extra_divs = [ADivision(name=f"Div-{i:02d}", is_active=True) for i in range(1, 30)]
        sess.add_all([d_act, d_inact, d_del, *extra_divs])
        sess.flush()

        o1 = AOrder(code="ORD-DRAFT", status="draft", amount=100, division_id=d_act.id)
        o2 = AOrder(code="ORD-LOCKED", status="paid", amount=250, division_id=d_act.id, locked_by_owner=True)
        o3 = AOrder(code="ORD-BATCH", status="draft", amount=300, division_id=d_act.id)
        sess.add_all([o1, o2, o3])
        sess.flush()

        sess.add_all(
            [
                ALine(order_id=o1.id, sku="SKU-A", qty=2, unit_price=50),
                ALine(order_id=o1.id, sku="SKU-OUT-OF-SCOPE", qty=1, unit_price=99, hidden_scope=True),
                ALine(order_id=o2.id, sku="SKU-OTHER-PARENT", qty=1, unit_price=10),
                ACompositeItem(order_id=o1.id, slot_no=1, note="Slot One"),
            ]
        )
        sess.commit()

    class DivisionView(ModelView):
        model = ADivision
        slug = "divisions"
        searchable_columns = ("name",)

    class LineInline(InlineModelView):
        model = ALine
        label = "Order Lines"
        columns = ("sku", "qty", "unit_price", "line_total", "attachment_path", "color")
        readonly_fields = ("unit_price",)
        collapsible = True
        collapsed = False
        extra = 0
        extra_on_edit = 0
        file_fields = MappingProxyType(
            {"attachment_path": FileFieldConfig(storage=storage, kind="image", prefix="inline-img")}
        )
        field_widgets = MappingProxyType({"color": ColorWidget()})

        @display(label="Line Total")
        def line_total(self, obj: ALine) -> str:
            return f"${obj.qty * obj.unit_price}"

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None, parent_obj: Any = None) -> sa.Select[Any]:
            _ = (user, parent_obj)
            return stmt.where(ALine.hidden_scope.is_(False))

        def validate_rows(
            self,
            rows: Sequence[Mapping[str, Any]],
            parent_obj: Any,
            user: DeckUser | None,
        ) -> dict[str, list[str]]:
            _ = (parent_obj, user)
            total_qty = sum(int(r.get("qty") or 0) for r in rows)
            if total_qty > 50:
                return {"lines": ["Total inline quantity cannot exceed 50."]}
            return {}

    class CompositeInline(InlineModelView):
        model = ACompositeItem
        label = "Composite Slots"
        columns = ("slot_no", "note")
        extra = 0
        extra_on_edit = 0

    class OrderView(ModelView):
        model = AOrder
        slug = "orders"
        is_primary_view = True
        columns = ("code", "status", "amount", "division")
        list_display_links = ("status",)
        inline_editable_columns = ("amount",)
        inline_edit_mode = "batch"
        save_as = True
        save_as_continue = False
        save_on_top = True
        raw_id_fields = ("division_id",)
        formfield_overrides = MappingProxyType({"text": "markdown"})
        field_widgets = MappingProxyType({"accent": ColorWidget()})
        extra_form_fields = (
            VirtualField(
                name="audit_reason",
                label="Change Reason",
                field_type="string",
                required=False,
                help_text="Stored in audit hook only.",
            ),
        )
        inlines = (LineInline, CompositeInline)

        def get_readonly_fields(self, user: DeckUser | None, obj: Any | None = None) -> tuple[str, ...]:
            _ = user
            if obj is not None and obj.status == "paid":
                return ("amount", "code")
            return ()

        def get_fieldsets(self, user: DeckUser | None, obj: Any | None = None) -> Sequence[Fieldset]:
            _ = user
            title = "Paid Order (Locked)" if (obj is not None and obj.status == "paid") else "Draft Order"
            return (
                Fieldset(title, ("code", "status", "amount", "division_id", "accent", "audit_reason")),
            )

        def get_list_display(self, user: DeckUser | None) -> tuple[str, ...]:
            if user is not None and not user.is_superuser:
                return ("code", "status")
            return self.columns

        def can_edit_record(self, obj: Any, user: DeckUser | None) -> bool:
            return not (user is not None and not user.is_superuser and obj.locked_by_owner)

        def can_delete_record(self, obj: Any, user: DeckUser | None) -> bool:
            return not (obj.locked_by_owner and (user is None or not user.is_superuser))

        def formfield_for_foreignkey(
            self, field_name: str, stmt: sa.Select[Any], user: DeckUser | None, obj: Any | None = None
        ) -> sa.Select[Any]:
            _ = (user, obj)
            if field_name == "division_id":
                return stmt.where(ADivision.is_active.is_(True))
            return stmt

        def on_model_change(
            self,
            obj: Any,
            *,
            is_created: bool,
            user: DeckUser | None = None,
            virtual_data: Mapping[str, Any] | None = None,
        ) -> None:
            hook_log.append(
                {
                    "event": "change",
                    "code": obj.code,
                    "is_created": is_created,
                    "virtual": dict(virtual_data or {}),
                }
            )

        def save_related(
            self,
            obj: Any,
            *,
            is_created: bool,
            user: DeckUser | None = None,
            inline_diffs: Sequence[tuple[str, str, str, dict[str, dict[str, Any]]]] = (),
        ) -> None:
            _ = (is_created, user)
            hook_log.append({"event": "save_related", "code": obj.code, "inline_count": len(inline_diffs)})

        def validate_batch(
            self,
            changes: Sequence[tuple[Any, Mapping[str, Any]]],
            user: DeckUser | None,
        ) -> dict[str, list[str]]:
            _ = user
            for obj, vals in changes:
                if int(vals.get("amount", obj.amount)) > 10000:
                    return {str(obj.id): ["Batch amount cannot exceed 10000."]}
            return {}

        @action("export_codes", label="Download Codes CSV")
        def export_codes(self, records: list[AOrder], form_data: Any, user: DeckUser | None) -> Response:
            _ = (form_data, user)
            body = "code,amount\n" + "\n".join(f"{r.code},{r.amount}" for r in records)
            return Response(
                body,
                mimetype="text/csv",
                headers={"Content-Disposition": 'attachment; filename="codes.csv"'},
            )

    class ProxyDraftOrdersView(ModelView):
        model = AOrder
        slug = "draft-orders"
        plural_name = "Draft Orders"
        is_primary_view = False
        disabled_actions = ("delete",)
        columns = ("code", "amount")

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
            _ = user
            return stmt.where(AOrder.status == "draft")

    auth = RBACAuthProvider(
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="admin", username="admin", roles=("admin",), is_superuser=True),
                password="pass",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="staff", username="staff", roles=("staff",)),
                password="pass",
            ),
        ],
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="staff",
                permissions=frozenset(
                    {
                        "orders:view",
                        "orders:create",
                        "orders:edit",
                        "orders:delete",
                        "divisions:view",
                        "divisions:delete",
                        "v06-a-lines:view",
                        "v06-a-lines:create",
                        "v06-a-lines:edit",
                        "v06-a-lines:delete",
                        "draft-orders:view",
                    }
                ),
            ),
        ],
    )
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, audit_store=audit_store)

    def global_ping(view: ModelView, records: Sequence[Any], form_data: Any, user: DeckUser | None) -> str:
        _ = (form_data, user)
        return f"Pinged {len(records)} {view.meta.slug}"

    deck.add_action(global_ping, name="ping_all", label="Ping Global")
    deck.register(DivisionView, OrderView, ProxyDraftOrdersView)
    yield app, deck, storage, audit_store, hook_log
    deck.close()
    engine.dispose()


def test_dynamic_hooks_virtual_field_batch_edit_response_action_and_proxy(
    authoring_bundle: tuple[Flask, Deck, MemoryFileStorage, InMemoryAuditStore, list[dict[str, Any]]],
) -> None:
    app, deck, _storage, audit_store, hook_log = authoring_bundle
    c_admin = app.test_client()
    csrf = login_as(c_admin, "admin", "pass")

    # Canonical primary view resolution for multi-view same model
    assert deck._views_by_model[AOrder].meta.slug == "orders"
    proxy_html = c_admin.get("/admin/draft-orders/").get_data(as_text=True)
    assert "ORD-DRAFT" in proxy_html
    assert "ORD-LOCKED" not in proxy_html
    # disabled_actions = ("delete",) hides bulk delete button on proxy view
    assert "/action/delete" not in proxy_html

    # Dynamic get_list_display + list_display_links + site-level global action
    list_html = c_admin.get("/admin/orders/").get_data(as_text=True)
    assert "Ping Global" in list_html
    assert "dk-batch-save-bar" in list_html

    # Dynamic get_readonly_fields enforced against mass assignment on paid order (id=2)
    edit_paid_html = c_admin.get("/admin/orders/2/edit").get_data(as_text=True)
    assert "Paid Order (Locked)" in edit_paid_html
    assert "dk-form-top-bar" in edit_paid_html  # save_on_top
    r_tamper = c_admin.post(
        "/admin/orders/2/edit",
        data={
            "_csrf_token": csrf,
            "code": "HACKED-CODE",
            "status": "paid",
            "amount": "999999",
            "division_id": "1",
            "locked_by_owner": "true",
            "audit_reason": "Trying tamper",
        },
        follow_redirects=False,
    )
    assert r_tamper.status_code == 302
    # Amount and code stayed untouched despite POST tampering!
    detail_paid = c_admin.get("/admin/orders/2").get_data(as_text=True)
    assert "ORD-LOCKED" in detail_paid
    assert "250" in detail_paid
    assert "HACKED-CODE" not in detail_paid

    # VirtualField passed to on_model_change (never setattr'd on ORM model) + URL prefill
    prefill_html = c_admin.get("/admin/orders/new?code=PRE-01&amount=420").get_data(as_text=True)
    assert 'value="PRE-01"' in prefill_html
    assert 'value="420"' in prefill_html
    r_create = c_admin.post(
        "/admin/orders/new",
        data={
            "_csrf_token": csrf,
            "code": "ORD-VIRTUAL",
            "status": "draft",
            "amount": "555",
            "division_id": "1",
            "audit_reason": "Board approved Q4",
        },
        follow_redirects=False,
    )
    assert r_create.status_code == 302
    assert any(
        e.get("event") == "change" and e.get("virtual", {}).get("audit_reason") == "Board approved Q4"
        for e in hook_log
    )
    assert any(e.get("event") == "save_related" and e.get("code") == "ORD-VIRTUAL" for e in hook_log)
    assert not hasattr(AOrder, "audit_reason")

    # formfield_for_foreignkey blocks assigning inactive division_id=2!
    r_bad_fk = c_admin.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ORD-DRAFT",
            "status": "draft",
            "amount": "100",
            "division_id": "2",
        },
    )
    assert r_bad_fk.status_code == 200
    assert "outside your allowed scope" in r_bad_fk.get_data(as_text=True)

    # save_as_continue=False redirects back to list after Save as New
    r_save_as = c_admin.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "_save_action": "save_as",
            "code": "ORD-CLONED",
            "status": "draft",
            "amount": "111",
            "division_id": "1",
        },
        follow_redirects=False,
    )
    assert r_save_as.status_code == 302
    assert r_save_as.headers["Location"].endswith("/admin/orders/")

    # Hybrid Batch Edit: validate_batch failure rolls back ALL rows atomically
    r_batch_fail = c_admin.post(
        "/admin/orders/batch-edit",
        data={
            "_csrf_token": csrf,
            "batch__0___pk": "1",
            "batch__0__amount": "777",
            "batch__1___pk": "3",
            "batch__1__amount": "50000",  # > 10000 triggers validate_batch rollback!
        },
        follow_redirects=False,
    )
    assert r_batch_fail.status_code == 302
    # Row 1 must NOT be 777 because whole transaction rolled back!
    assert "777" not in c_admin.get("/admin/orders/1").get_data(as_text=True)

    # Valid Batch Edit commits atomically and records per-row audit diffs
    r_batch_ok = c_admin.post(
        "/admin/orders/batch-edit",
        data={
            "_csrf_token": csrf,
            "batch__0___pk": "1",
            "batch__0__amount": "450",
            "batch__1___pk": "3",
            "batch__1__amount": "650",
        },
        follow_redirects=False,
    )
    assert r_batch_ok.status_code == 302
    assert "450" in c_admin.get("/admin/orders/1").get_data(as_text=True)
    assert "650" in c_admin.get("/admin/orders/3").get_data(as_text=True)
    entries, _ = audit_store.list_entries(limit=50)
    assert any(
        e.action == "inline_edit" and e.metadata.get("batch_edit") is True and e.record_pk == "1"
        for e in entries
    )

    # Response-returning @action returns CSV with nosniff + no-store + audit record
    r_csv = c_admin.post(
        "/admin/orders/action/export_codes",
        data={"_csrf_token": csrf, "selected_pks": ["1", "3"]},
    )
    assert r_csv.status_code == 200
    assert r_csv.mimetype == "text/csv"
    assert r_csv.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in (r_csv.headers.get("Cache-Control") or "")
    assert "ORD-DRAFT,450" in r_csv.get_data(as_text=True)

    # Site-level global action executes cleanly
    r_ping = c_admin.post(
        "/admin/orders/action/ping_all",
        data={"_csrf_token": csrf, "selected_pks": ["1"]},
        follow_redirects=True,
    )
    assert "Pinged 1 orders" in r_ping.get_data(as_text=True)

    # Per-record can_edit_record / can_delete_record blocks staff on locked order #2
    c_staff = app.test_client()
    staff_csrf = login_as(c_staff, "staff", "pass")
    assert c_staff.get("/admin/orders/2/edit").status_code == 403
    assert c_staff.post("/admin/orders/2/delete", data={"_csrf_token": staff_csrf}).status_code == 403
    assert (
        c_staff.post(
            "/admin/orders/batch-edit",
            data={"_csrf_token": staff_csrf, "batch__0___pk": "2", "batch__0__amount": "1"},
        ).status_code
        == 403
    )


def test_rich_inlines_2_0_files_composite_idor_and_lookup_controls(
    authoring_bundle: tuple[Flask, Deck, MemoryFileStorage, InMemoryAuditStore, list[dict[str, Any]]],
) -> None:
    app, _deck, storage, _audit, _hooks = authoring_bundle
    c = app.test_client()
    csrf = login_as(c, "admin", "pass")

    # Edit form renders Rich Inline 2.0 (@display line_total, ColorWidget, collapsible <details>)
    # and excludes hidden_scope=True child row (id=2)
    form_html = c.get("/admin/orders/1/edit").get_data(as_text=True)
    assert "SKU-A" in form_html
    assert "SKU-OUT-OF-SCOPE" not in form_html
    assert "$100" in form_html  # @display line_total (2 * 50)
    assert "dk-fieldset-details" in form_html
    assert "dk-color-widget" in form_html
    assert "data-deck-rel-lookup" in form_html
    assert "data-deck-rel-del" in form_html

    # Inline file upload (valid PNG) + readonly unit_price tamper ignored + composite PK inline edit
    from flask_deck.adapters.sqlalchemy import encode_pk

    comp_pk = encode_pk((1, 1))
    png_bytes = make_demo_png(16, 16)
    r_ok = c.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ORD-DRAFT",
            "status": "draft",
            "amount": "100",
            "division_id": "1",
            "inline__a-lines__0___pk": "1",
            "inline__a-lines__0__sku": "SKU-A-UPD",
            "inline__a-lines__0__qty": "3",
            "inline__a-lines__0__unit_price": "9999",  # readonly -> must be ignored!
            "inline__a-lines__0__attachment_path": (io.BytesIO(png_bytes), "photo.png"),
            "inline__a-composite-items__0___pk": comp_pk,
            "inline__a-composite-items__0__slot_no": "1",
            "inline__a-composite-items__0__note": "Slot One Updated",
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert r_ok.status_code == 302
    after_html = c.get("/admin/orders/1/edit").get_data(as_text=True)
    assert "SKU-A-UPD" in after_html
    assert "$150" in after_html  # 3 * 50 (unit_price stayed 50, NOT 9999!)
    assert "Slot One Updated" in after_html

    # Inline media proxy serves uploaded image with nosniff + rejects out-of-scope child (id=2 -> 404)
    r_media = c.get("/admin/_media/orders/_inline/a-lines/attachment_path/1")
    assert r_media.status_code == 200
    assert r_media.headers.get("X-Content-Type-Options") == "nosniff"
    assert c.get("/admin/_media/orders/_inline/a-lines/attachment_path/2").status_code == 404

    # Inline validate_rows failure rolls back DB AND deletes newly uploaded orphan file!
    keys_before = set(storage._entries.keys())
    r_val_fail = c.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ORD-DRAFT",
            "status": "draft",
            "amount": "100",
            "division_id": "1",
            "inline__a-lines__0___pk": "1",
            "inline__a-lines__0__sku": "SKU-OVER",
            "inline__a-lines__0__qty": "99",  # exceeds 50!
            "inline__a-lines__0__attachment_path": (io.BytesIO(png_bytes), "orphan.png"),
        },
        content_type="multipart/form-data",
    )
    assert r_val_fail.status_code == 200
    assert "cannot exceed 50" in r_val_fail.get_data(as_text=True)
    assert set(storage._entries.keys()) == keys_before  # zero orphan files left behind!

    # Inline IDOR barrier: tampering with another parent's child (id=3) OR hidden_scope child (id=2) -> 403!
    r_idor_parent = c.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ORD-DRAFT",
            "status": "draft",
            "amount": "100",
            "division_id": "1",
            "inline__a-lines__0___pk": "3",
            "inline__a-lines__0__sku": "STOLEN",
            "inline__a-lines__0__qty": "1",
        },
    )
    assert r_idor_parent.status_code == 403

    r_idor_scope = c.post(
        "/admin/orders/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ORD-DRAFT",
            "status": "draft",
            "amount": "100",
            "division_id": "1",
            "inline__a-lines__0___pk": "2",
            "inline__a-lines__0__sku": "STOLEN-SCOPE",
            "inline__a-lines__0__qty": "1",
        },
    )
    assert r_idor_scope.status_code == 403

    # Paginated /_api/fk/divisions (page=1 has_more=True, page=2 returns next slice, honors formfield_for_foreignkey)
    p1 = c.get("/admin/_api/fk/divisions?page=1&owner_slug=orders&field_name=division_id").get_json()
    assert p1["page"] == 1
    assert p1["has_more"] is True
    assert all(it["label"] != "Archived Div" for it in p1["items"])
    p2 = c.get("/admin/_api/fk/divisions?page=2&owner_slug=orders&field_name=division_id").get_json()
    assert p2["page"] == 2
    assert len(p2["items"]) >= 1

    # Searchable /_api/divisions/lookup drawer HTML
    r_lkp = c.get("/admin/_api/divisions/lookup?q=Active&target_field=fld_division_id")
    assert r_lkp.status_code == 200
    lkp_html = r_lkp.get_data(as_text=True)
    assert "Active Div" in lkp_html
    assert "data-deck-lookup-pick" in lkp_html

    # FK Related Delete endpoint (POST /_api/divisions/3/quick-delete)
    r_qdel_nocsrf = c.post("/admin/_api/divisions/3/quick-delete")
    assert r_qdel_nocsrf.status_code == 403
    r_qdel = c.post(
        "/admin/_api/divisions/3/quick-delete",
        headers={"X-Deck-CSRFToken": csrf},
    )
    assert r_qdel.status_code == 200
    assert r_qdel.get_json()["ok"] is True
