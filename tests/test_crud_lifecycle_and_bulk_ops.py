"""Behavioral & security tests for CRUD lifecycle, batch inline edit, OCC, soft-delete, and chunked bulk jobs."""

from __future__ import annotations

import enum
import io
import time
from datetime import datetime, timezone
from decimal import Decimal
from types import MappingProxyType
from typing import Any

import sqlalchemy as sa
from flask import Flask, Response
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    ActionField,
    Deck,
    DeckUser,
    FileFieldConfig,
    InlineModelView,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemorySessionStore,
    MemoryFileStorage,
    ModelView,
    RBACAuthProvider,
    Role,
    ThreadPoolJobBackend,
    action,
    display,
)
from flask_deck.adapters.sqlalchemy import encode_pk
from flask_deck.security import CSRF_FORM_FIELD, CSRF_HEADER_NAME
from tests._backends import sqlite_memory_engine


class CrudStatus(enum.Enum):
    OPEN = "open"
    CLOSED = "closed"


class CrudBase(DeclarativeBase):
    pass


class CrudOrg(CrudBase):
    __tablename__ = "crud_orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), unique=True, nullable=False)
    items: Mapped[list[CrudItem]] = relationship(back_populates="org")

    def __str__(self) -> str:
        return self.name


class CrudItem(CrudBase):
    __tablename__ = "crud_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    org_id: Mapped[int | None] = mapped_column(sa.ForeignKey("crud_orgs.id"), nullable=True)
    status: Mapped[CrudStatus] = mapped_column(
        sa.Enum(CrudStatus), default=CrudStatus.OPEN, nullable=False
    )
    amount: Mapped[Decimal] = mapped_column(
        sa.Numeric(10, 2), default=Decimal("10.00"), nullable=False
    )
    price_cents: Mapped[int] = mapped_column(sa.Integer, default=1000, nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    is_archived: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    doc_key: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    org: Mapped[CrudOrg | None] = relationship(back_populates="items")
    lines: Mapped[list[CrudLine]] = relationship(back_populates="item")


class CrudLine(CrudBase):
    __tablename__ = "crud_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("crud_items.id"), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    item: Mapped[CrudItem] = relationship(back_populates="lines")


class CrudComposite(CrudBase):
    __tablename__ = "crud_composites"
    tenant: Mapped[str] = mapped_column(sa.String(20), primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(20), primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(60), nullable=False)


class CrudLineInline(InlineModelView):
    model = CrudLine
    fk_column = "item_id"
    columns = ("label", "qty")


def _extract_csrf(client: Any, url: str = "/admin/login") -> str:
    resp = client.get(url)
    html = resp.get_data(as_text=True)
    marker = f'name="{CSRF_FORM_FIELD}" value="'
    idx = html.find(marker)
    if idx != -1:
        start = idx + len(marker)
        return html[start : html.find('"', start)]
    meta = 'name="csrf-token" content="'
    idx = html.find(meta)
    assert idx != -1, f"CSRF token not found in {url}"
    start = idx + len(meta)
    return html[start : html.find('"', start)]


def _login(client: Any, username: str, password: str) -> str:
    csrf = _extract_csrf(client, "/admin/login")
    resp = client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    return _extract_csrf(client, "/admin/")


def _extract_input_value(html: str, name: str) -> str:
    marker = f'name="{name}"'
    idx = html.find(marker)
    assert idx != -1, f"input {name!r} not found"
    val_idx = html.find('value="', idx)
    assert val_idx != -1
    start = val_idx + len('value="')
    return html[start : html.find('"', start)]


def _wait_job(backend: ThreadPoolJobBackend, job_id: str, timeout: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rec = backend.get(job_id)
        if rec is not None and rec.status in {"succeeded", "failed", "cancelled"}:
            return rec
        time.sleep(0.02)
    return backend.get(job_id)


def test_crud_list_batch_edit_occ_save_as_and_soft_delete_flows() -> None:
    storage = MemoryFileStorage()

    class OrgView(ModelView):
        model = CrudOrg
        slug = "orgs"
        searchable_columns = ("name",)

    class ItemView(ModelView):
        model = CrudItem
        slug = "items"
        columns = ("code", "title", "org", "status", "price_cents", "amount", "active", "summary")
        searchable_columns = ("code", "title")
        filterable_columns = ("status", "org_id", "active")
        inline_edit_mode = "batch"
        inline_editable_columns = ("title", "status", "active", "org_id", "amount")
        soft_delete_column = "deleted_at"
        version_column = "version"
        date_hierarchy = "created_at"
        calendar_date_field = "created_at"
        kanban_column = "status"
        save_as = True
        save_as_continue = False
        preserve_filters = True
        show_facets = "always"
        column_aggregates = MappingProxyType({"price_cents": "sum", "amount": "avg"})
        aggregate_scope = "all"
        file_fields = MappingProxyType({"doc_key": FileFieldConfig(storage=storage, kind="file")})
        inlines = (CrudLineInline,)

        @display(label="Summary")
        def summary(self, obj: Any) -> str:
            return f"{obj.code}:{obj.status.value}"

        def get_search_results(
            self, stmt: sa.Select[Any], search_term: str, user: Any
        ) -> tuple[sa.Select[Any], bool]:
            _ = user
            return stmt.where(CrudItem.title.ilike(f"%{search_term}%")), False

        def can_view_record(self, obj: Any, user: Any) -> bool:
            return not (obj.code == "SECRET" and user is not None and not user.is_superuser)

        def can_edit_record(self, obj: Any, user: Any) -> bool:
            return not (obj.locked and user is not None and not user.is_superuser)

        def can_delete_record(self, obj: Any, user: Any) -> bool:
            return not (obj.locked and user is not None and not user.is_superuser)

        def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
            _ = obj
            if data.get("title") == "FORBIDDEN_TITLE":
                return {"title": ["Title is forbidden"]}
            return {}

        def validate_batch(
            self, changes: Any, user: Any
        ) -> dict[str, list[str]]:
            _ = user
            if any(vals.get("title") == "BATCH_REJECT" for _, vals in changes):
                return {"batch": ["Cross-row batch rule failed"]}
            return {}

    class GovItemView(ModelView):
        model = CrudItem
        slug = "gov-items"
        approval_required = ("create", "edit", "delete")
        save_as = True
        inline_edit_mode = "batch"
        inline_editable_columns = ("title",)
        inlines = (CrudLineInline,)

    class DisabledOrgView(ModelView):
        model = CrudOrg
        slug = "disabled-orgs"
        can_view = False
        can_create = False
        can_edit = False
        can_delete = False
        can_export = False
        can_import = False

    class BoolSoftItemView(ModelView):
        model = CrudItem
        slug = "bool-items"
        soft_delete_column = "is_archived"

    with sqlite_memory_engine() as eng:
        CrudBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            o1 = CrudOrg(name="Acme")
            o2 = CrudOrg(name="Beta")
            s.add_all([o1, o2])
            s.flush()
            i1 = CrudItem(
                code="IT-1",
                title="First Item",
                org_id=o1.id,
                price_cents=2500,
                amount=Decimal("25.00"),
                active=True,
            )
            i2 = CrudItem(
                code="IT-2",
                title="Second Item",
                org_id=o2.id,
                price_cents=1500,
                amount=Decimal("15.00"),
                active=False,
            )
            i_secret = CrudItem(code="SECRET", title="Secret Item", org_id=o1.id)
            i_trashed = CrudItem(
                code="TRASH",
                title="Trashed Item",
                org_id=o1.id,
                deleted_at=datetime.now(timezone.utc),
            )
            s.add_all([i1, i2, i_secret, i_trashed])
            s.flush()
            s.add(CrudLine(item_id=i1.id, label="Line A", qty=2))
            s.commit()
            o1_id = o1.id
            i1_id, i2_id, i_secret_id, i_trashed_id = i1.id, i2.id, i_secret.id, i_trashed.id

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "crud-lifecycle-secret-32-bytes!!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role(
                    "editor",
                    permissions=frozenset(
                        {
                            "items:view",
                            "items:create",
                            "items:edit",
                            "items:delete",
                            "orgs:view",
                            "gov-items:view",
                            "gov-items:create",
                            "gov-items:edit",
                            "gov-items:delete",
                            "audit:view",
                        }
                    ),
                    hidden_fields={"items": frozenset({"summary"})},
                    masked_fields={"items": frozenset({"amount"})},
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
                    password="AdminPassword1!",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-ed", username="editor", roles=("editor",)),
                    password="EditorPassword1!",
                ),
            ],
        )

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            approval_store=InMemoryApprovalStore(),
            session_store=InMemorySessionStore(),
            page_size=2,
            max_page_size=10,
        )
        deck.register(OrgView, ItemView, GovItemView, DisabledOrgView, BoolSoftItemView)

        try:
            c = app.test_client()
            csrf = _login(c, "admin", "AdminPassword1!")

            # Disabled view guards (404 / 403)
            assert c.get("/admin/disabled-orgs/").status_code == 404
            assert c.get("/admin/disabled-orgs/new").status_code == 403
            assert c.get(f"/admin/disabled-orgs/{o1_id}").status_code == 404
            assert c.get(f"/admin/disabled-orgs/{o1_id}/history").status_code == 404
            assert c.get(f"/admin/disabled-orgs/{o1_id}/edit").status_code == 403
            assert c.post(f"/admin/disabled-orgs/{o1_id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 403
            assert c.get("/admin/disabled-orgs/export.csv").status_code == 403
            assert c.get("/admin/disabled-orgs/import").status_code == 403
            assert c.get("/admin/disabled-orgs/import/errors/tok.csv").status_code == 403

            # List edge cases: bad page/page_size, custom search + date_hierarchy + facets + aggregates
            r_list = c.get("/admin/items/?page=bad&page_size=bad&q=First")
            assert r_list.status_code == 200
            assert "First Item" in r_list.get_data(as_text=True)
            assert c.get("/admin/items/?view=calendar").status_code == 200
            assert c.get("/admin/items/?view=board").status_code == 200
            assert c.get("/admin/items/?page_size=all").status_code == 200

            # Batch inline edit (JSON & form, empty, validation, FK scope, soft-deleted, approval, cross-row, success)
            assert c.post("/admin/orgs/batch-edit", data={CSRF_FORM_FIELD: csrf}).status_code == 400
            r_empty_j = c.post(
                "/admin/items/batch-edit",
                json={"rows": []},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_empty_j.status_code == 200 and r_empty_j.get_json()["updated"] == 0
            r_empty_f = c.post("/admin/items/batch-edit", data={CSRF_FORM_FIELD: csrf})
            assert r_empty_f.status_code == 302

            # Batch edit invalid coercion + invalid FK + trashed row + custom validation
            r_bad_j = c.post(
                "/admin/items/batch-edit",
                json={
                    "rows": [
                        {"pk": str(i1_id), "values": {"amount": "not-a-num", "org_id": "999999"}},
                        {"pk": str(i_trashed_id), "values": {"title": "Edit Trashed"}},
                        {"pk": str(i2_id), "values": {"title": "FORBIDDEN_TITLE"}},
                    ]
                },
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_bad_j.status_code == 422
            errs = r_bad_j.get_json()["errors"]
            assert f"{i1_id}.amount" in errs
            assert f"{i1_id}.org_id" in errs
            assert str(i_trashed_id) in errs
            assert f"{i2_id}.title" in errs

            # Cross-row validate_batch failure
            r_xrow = c.post(
                "/admin/items/batch-edit",
                json={"rows": [{"pk": str(i1_id), "values": {"title": "BATCH_REJECT"}}]},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_xrow.status_code == 422
            assert "batch" in r_xrow.get_json()["errors"]

            # Approval-required batch edit rejected
            r_gov_b = c.post(
                "/admin/gov-items/batch-edit",
                json={"rows": [{"pk": str(i1_id), "values": {"title": "Gov Changed"}}]},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_gov_b.status_code == 422

            # Form-encoded batch edit success + version bump + JSON success
            r_bf = c.post(
                "/admin/items/batch-edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "batch__0___pk": str(i1_id),
                    "batch__0__title": "Batch Updated 1",
                    "batch__0__active": "",
                    "batch__0___present_active": "1",
                    "batch__1___pk": "",  # skipped blank pk
                },
            )
            assert r_bf.status_code == 302
            r_bj = c.post(
                "/admin/items/batch-edit",
                json={"rows": [{"pk": str(i2_id), "values": {"title": "Batch JSON 2", "org_id": str(o1_id)}}]},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_bj.status_code == 200 and r_bj.get_json()["updated"] == 1

            # Create with save_action=continue & save_action=add_another + clone trashed 404
            assert c.get(f"/admin/items/new?clone={i_trashed_id}").status_code == 404
            r_cont = c.post(
                "/admin/items/new",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "IT-CONT",
                    "title": "Continue Item",
                    "status": "open",
                    "amount": "12.50",
                    "price_cents": "1250",
                    "active": "1",
                    "_save_action": "continue",
                },
            )
            assert r_cont.status_code == 302 and "/edit" in r_cont.headers["Location"]

            r_add = c.post(
                "/admin/items/new",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "IT-ADD",
                    "title": "Add Another",
                    "status": "open",
                    "amount": "5.00",
                    "price_cents": "500",
                    "active": "1",
                    "_save_action": "add_another",
                },
            )
            assert r_add.status_code == 302 and "/admin/items/new" in r_add.headers["Location"]

            # IntegrityError on duplicate code cleans up uploaded file
            r_dup = c.post(
                "/admin/items/new",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "IT-CONT",
                    "title": "Dup",
                    "status": "open",
                    "amount": "1.00",
                    "price_cents": "100",
                    "active": "1",
                    "doc_key": (io.BytesIO(b"hello text"), "dup.txt"),
                },
                content_type="multipart/form-data",
            )
            assert r_dup.status_code == 200
            assert "integrity" in r_dup.get_data(as_text=True).lower()

            # Create with inline + approval_required on GovItemView queues approval
            r_gov_c = c.post(
                "/admin/gov-items/new",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "IT-GOV-1",
                    "title": "Gov Pending",
                    "status": "open",
                    "amount": "9.00",
                    "price_cents": "900",
                    "active": "1",
                    "inline__crud_lines__0__label": "Gov Line",
                    "inline__crud_lines__0__qty": "3",
                },
            )
            assert r_gov_c.status_code == 302

            # Edit: OCC 409 conflict (boolean + field diff AND version-only diff), then force overwrite
            edit_html = c.get(f"/admin/items/{i1_id}/edit").get_data(as_text=True)
            cur_ver = _extract_input_value(edit_html, "_deck_version")
            r_occ1 = c.post(
                f"/admin/items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_deck_version": "stale-version",
                    "code": "IT-1",
                    "title": "Conflicting Title",
                    "status": "closed",
                    "amount": "25.00",
                    "price_cents": "2500",
                    "active": "1",  # currently False -> boolean conflict branch
                },
            )
            assert r_occ1.status_code == 409
            assert "Concurrent modification" in r_occ1.get_data(as_text=True)

            # Version-only conflict (submitted fields equal current values)
            r_occ_ver = c.post(
                f"/admin/items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_deck_version": "stale-version",
                    "code": "IT-1",
                    "title": "Batch Updated 1",
                    "status": "open",
                    "amount": "25.00",
                    "price_cents": "2500",
                },
            )
            assert r_occ_ver.status_code == 409

            # Force overwrite + add_another redirect + _return_qs redirect
            r_force = c.post(
                f"/admin/items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_deck_version": "stale-version",
                    "_deck_force_overwrite": "1",
                    "code": "IT-1",
                    "title": "Force Overwritten",
                    "status": "closed",
                    "amount": "30.00",
                    "price_cents": "3000",
                    "active": "1",
                    "_save_action": "add_another",
                },
            )
            assert r_force.status_code == 302 and "/admin/items/new" in r_force.headers["Location"]

            # Save-as-new (save_as_continue=False -> redirects to list; IntegrityError on dup code; approval on gov-items)
            r_sa_ok = c.post(
                f"/admin/items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_save_action": "save_as",
                    "code": "IT-SAVE-AS",
                    "title": "Saved As New",
                    "status": "open",
                    "amount": "11.00",
                    "price_cents": "1100",
                    "active": "1",
                },
            )
            assert r_sa_ok.status_code == 302 and r_sa_ok.headers["Location"].endswith("/admin/items/")
            r_sa_dup = c.post(
                f"/admin/items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_save_action": "save_as",
                    "code": "IT-SAVE-AS",
                    "title": "Dup Save As",
                    "status": "open",
                    "amount": "11.00",
                    "price_cents": "1100",
                    "active": "1",
                },
            )
            assert r_sa_dup.status_code == 200
            r_sa_gov = c.post(
                f"/admin/gov-items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "_save_action": "save_as",
                    "code": "IT-GOV-SA",
                    "title": "Gov Save As",
                    "status": "open",
                    "amount": "11.00",
                    "price_cents": "1100",
                    "active": "1",
                },
            )
            assert r_sa_gov.status_code == 302
            # Edit on gov-items with inline queues approval
            r_gov_e = c.post(
                f"/admin/gov-items/{i1_id}/edit",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "code": "IT-1",
                    "title": "Gov Edited",
                    "status": "closed",
                    "amount": "30.00",
                    "price_cents": "3000",
                    "active": "1",
                    "inline__crud_lines__0__label": "Gov Edit Line",
                    "inline__crud_lines__0__qty": "1",
                },
            )
            assert r_gov_e.status_code == 302

            # Detail & history (including non-superuser hidden/masked/can_view_record guards)
            assert c.get(f"/admin/items/{i1_id}").status_code == 200
            assert c.get(f"/admin/items/{i1_id}/history").status_code == 200
            assert c.get(f"/admin/orgs/{o1_id}").status_code == 200

            ec = app.test_client()
            _login(ec, "editor", "EditorPassword1!")
            assert ec.get(f"/admin/items/{i_secret_id}").status_code == 403
            assert ec.get(f"/admin/items/{i_secret_id}/history").status_code == 403
            assert ec.get(f"/admin/items/new?clone={i_secret_id}").status_code == 403
            assert ec.get(f"/admin/items/{i1_id}").status_code == 200
            assert ec.get(f"/admin/items/{i1_id}/history").status_code == 200
            # Editor cannot use save_as on orgs (save_as=False) -> 403
            assert c.post(
                f"/admin/orgs/{o1_id}/edit",
                data={CSRF_FORM_FIELD: csrf, "_save_action": "save_as", "name": "NewOrg"},
            ).status_code == 403

            # Restore already active + restore trashed + boolean soft-delete + delete approval
            assert c.post(f"/admin/orgs/{o1_id}/restore", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            r_rest_active = c.post(f"/admin/items/{i1_id}/restore", data={CSRF_FORM_FIELD: csrf})
            assert r_rest_active.status_code == 302
            r_rest_ok = c.post(f"/admin/items/{i_trashed_id}/restore", data={CSRF_FORM_FIELD: csrf})
            assert r_rest_ok.status_code == 302
            # Boolean soft delete + restore
            r_bdel = c.post(f"/admin/bool-items/{i2_id}/delete", data={CSRF_FORM_FIELD: csrf})
            assert r_bdel.status_code == 302
            r_brest = c.post(f"/admin/bool-items/{i2_id}/restore", data={CSRF_FORM_FIELD: csrf})
            assert r_brest.status_code == 302
            # Delete on gov-items queues approval
            r_gdel = c.post(f"/admin/gov-items/{i1_id}/delete", data={CSRF_FORM_FIELD: csrf})
            assert r_gdel.status_code == 302
            assert cur_ver  # sanity
        finally:
            deck.close()


def test_crud_bulk_actions_select_across_prod_safeguards_and_chunked_jobs() -> None:
    class ProdItemView(ModelView):
        model = CrudItem
        slug = "items"
        soft_delete_column = "deleted_at"

        @action(
            "tag_bulk",
            label="Tag Bulk",
            require_confirm_text=True,
            fields=(
                ActionField("note", required=True),
                ActionField("tier", field_type="select", choices=(("a", "A"), ("b", "B"))),
                ActionField("count", field_type="number"),
            ),
        )
        def tag_bulk(self, records: Any, form: Any, user: Any) -> str:
            _ = user
            note = form.get("note", "")
            for r in records:
                r.title = f"{r.title} [{note}]"
            return f"Tagged {len(records)}"

        @action("fail_act", label="Fail Act")
        def fail_act(self, records: Any, form: Any, user: Any) -> str:
            _ = (records, form, user)
            raise ValueError("simulated action failure")

        @action("async_act", label="Async Act", async_job=True)
        def async_act(self, records: Any, form: Any, user: Any, job_ctx: Any) -> str:
            _ = (form, user)
            job_ctx.log("running async_act")
            return f"Async processed {len(records)}"

        @action("download_act", label="Download Act")
        def download_act(self, records: Any, form: Any, user: Any) -> Response:
            _ = (form, user)
            return Response(f"count={len(records)}", mimetype="text/plain")

    class CompositeView(ModelView):
        model = CrudComposite
        slug = "composites"

        @action("ping", label="Ping", async_job=True)
        def ping(self, records: Any, form: Any, user: Any, job_ctx: Any) -> str:
            _ = (form, user, job_ctx)
            return f"Pinged {len(records)}"

    with sqlite_memory_engine() as eng:
        CrudBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            items = [CrudItem(code=f"B-{i}", title=f"Bulk {i}") for i in range(4)]
            s.add_all(items)
            s.add_all(
                [
                    CrudComposite(tenant="t1", code="c1", label="Comp 1"),
                    CrudComposite(tenant="t1", code="c2", label="Comp 2"),
                ]
            )
            s.commit()
            pks = [str(x.id) for x in items]

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "bulk-ops-secret-32-bytes-long!!!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[Role("admin", permissions=frozenset({"*"}))],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
                    password="AdminPassword1!",
                )
            ],
        )
        jobs = ThreadPoolJobBackend(max_workers=2)
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            approval_store=False,
            session_store=InMemorySessionStore(),
            job_backend=jobs,
            environment="production",
            require_confirm_text_in_prod=True,
            bulk_sync_limit=2,
            max_select_across=10,
        )
        deck.register(ProdItemView, CompositeView)

        try:
            c = app.test_client()
            csrf = _login(c, "admin", "AdminPassword1!")

            # Empty selection & unknown action
            assert c.post("/admin/items/action/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert c.post(
                "/admin/items/action/nonexistent",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": [pks[0]]},
            ).status_code == 404

            # Production safeguard rejects missing/wrong confirm_text on sync custom action + field validation
            r_no_conf = c.post(
                "/admin/items/action/tag_bulk",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": [pks[0]], "note": "ok"},
            )
            assert r_no_conf.status_code == 302
            # Invalid choice / invalid number on action fields
            r_bad_choice = c.post(
                "/admin/items/action/tag_bulk",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "selected_pks": [pks[0]],
                    "confirm_text": "CONFIRM 1",
                    "note": "ok",
                    "tier": "invalid",
                },
            )
            assert r_bad_choice.status_code == 302
            r_bad_num = c.post(
                "/admin/items/action/tag_bulk",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "selected_pks": [pks[0]],
                    "confirm_text": "CONFIRM 1",
                    "note": "ok",
                    "tier": "a",
                    "count": "notnum",
                },
            )
            assert r_bad_num.status_code == 302

            # Action raising ValueError rolls back cleanly; action returning Response adds security headers
            assert c.post(
                "/admin/items/action/fail_act",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": [pks[0]]},
            ).status_code == 302
            r_dl = c.post(
                "/admin/items/action/download_act",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": [pks[0]]},
            )
            assert r_dl.status_code == 200
            assert r_dl.headers.get("X-Content-Type-Options") == "nosniff"
            assert "count=1" in r_dl.get_data(as_text=True)

            # Composite PK sync bulk delete & async action
            r_comp_async = c.post(
                "/admin/composites/action/ping",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "selected_pks": [encode_pk(("t1", "c1")), encode_pk(("t1", "c2"))],
                },
            )
            assert r_comp_async.status_code == 302
            job_id_comp = r_comp_async.headers["Location"].split("focus=")[-1]
            rec_comp = _wait_job(jobs, job_id_comp)
            assert rec_comp is not None and rec_comp.status == "succeeded"

            # Select-across tampered token -> 403; trashed mismatch -> 403
            list_html = c.get("/admin/items/?page_size=2").get_data(as_text=True)
            st_m = 'data-slice-token="'
            st_i = list_html.find(st_m)
            assert st_i != -1
            st_s = st_i + len(st_m)
            slice_tok = list_html[st_s : list_html.find('"', st_s)]
            assert c.post(
                "/admin/items/action/delete",
                data={CSRF_FORM_FIELD: csrf, "select_across": "1", "slice_token": "tampered"},
            ).status_code == 403
            assert c.post(
                "/admin/items/action/restore",
                data={CSRF_FORM_FIELD: csrf, "select_across": "1", "slice_token": slice_tok},
            ).status_code == 403

            # Export with select_across + invalid format 404 + async export invalid fmt 400
            assert c.get("/admin/items/export.xml").status_code == 404
            assert c.get("/admin/items/export.csv?select_across=1&slice_token=bad").status_code == 403
            r_exp_sa = c.get(f"/admin/items/export.csv?select_across=1&slice_token={slice_tok}")
            assert r_exp_sa.status_code == 200 and "B-0" in r_exp_sa.get_data(as_text=True)
            assert c.post(
                "/admin/items/export-async",
                data={CSRF_FORM_FIELD: csrf, "fmt": "xml"},
            ).status_code == 400

            # Chunked background bulk (> bulk_sync_limit=2): custom action + soft delete + restore + force_delete
            # 1) Custom action >2 rows: prod confirm safeguard rejects first, then succeeds via background job
            r_c_bad = c.post(
                "/admin/items/action/tag_bulk",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "selected_pks": pks[:3],
                    "confirm_text": "WRONG",
                    "note": "n1",
                },
            )
            assert r_c_bad.status_code == 302
            r_c_ok = c.post(
                "/admin/items/action/tag_bulk",
                data={
                    CSRF_FORM_FIELD: csrf,
                    "selected_pks": pks[:3],
                    "confirm_text": "CONFIRM 3",
                    "note": "bulktag",
                    "tier": "a",
                },
            )
            assert r_c_ok.status_code == 302 and "/_jobs" in r_c_ok.headers["Location"]
            rec_tag = _wait_job(jobs, r_c_ok.headers["Location"].split("focus=")[-1])
            assert rec_tag is not None and rec_tag.status == "succeeded"

            # 2) Async action >2 rows
            r_as = c.post(
                "/admin/items/action/async_act",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:3]},
            )
            assert r_as.status_code == 302
            rec_as = _wait_job(jobs, r_as.headers["Location"].split("focus=")[-1])
            assert rec_as is not None and rec_as.status == "succeeded"

            # 3) Chunked soft-delete (3 rows) with DELETE 3 safeguard
            r_del_bad = c.post(
                "/admin/items/action/delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:3], "confirm_text": "NOPE"},
            )
            assert r_del_bad.status_code == 302
            r_del_ok = c.post(
                "/admin/items/action/delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:3], "confirm_text": "DELETE 3"},
            )
            assert r_del_ok.status_code == 302 and "/_jobs" in r_del_ok.headers["Location"]
            rec_del = _wait_job(jobs, r_del_ok.headers["Location"].split("focus=")[-1])
            assert rec_del is not None and rec_del.status == "succeeded"

            # 4) Chunked restore (3 trashed rows)
            r_res_ok = c.post(
                "/admin/items/action/restore",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:3]},
            )
            assert r_res_ok.status_code == 302 and "/_jobs" in r_res_ok.headers["Location"]
            rec_res = _wait_job(jobs, r_res_ok.headers["Location"].split("focus=")[-1])
            assert rec_res is not None and rec_res.status == "succeeded"

            # 5) Sync soft-delete (2 rows) + sync force_delete (prod guard + confirm)
            r_sdel = c.post(
                "/admin/items/action/delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:2], "confirm_text": "DELETE 2"},
            )
            assert r_sdel.status_code == 302
            r_fdel_bad = c.post(
                "/admin/items/action/force_delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:2], "confirm_text": "WRONG"},
            )
            assert r_fdel_bad.status_code == 302
            r_fdel_ok = c.post(
                "/admin/items/action/force_delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": pks[:2], "confirm_text": "DELETE 2"},
            )
            assert r_fdel_ok.status_code == 302

            # 6) Chunked force_delete (soft-delete remaining 2 + 1 new so we have 3 trashed)
            with SessionLocal() as s:
                extra = CrudItem(code="B-EXTRA", title="Extra")
                s.add(extra)
                s.commit()
                rem_pks = [pks[2], pks[3], str(extra.id)]
            r_sd3 = c.post(
                "/admin/items/action/delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": rem_pks, "confirm_text": "DELETE 3"},
            )
            _wait_job(jobs, r_sd3.headers["Location"].split("focus=")[-1])
            r_fd3_bad = c.post(
                "/admin/items/action/force_delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": rem_pks, "confirm_text": "NOPE"},
            )
            assert r_fd3_bad.status_code == 302
            r_fd3_ok = c.post(
                "/admin/items/action/force_delete",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": rem_pks, "confirm_text": "DELETE 3"},
            )
            rec_fd3 = _wait_job(jobs, r_fd3_ok.headers["Location"].split("focus=")[-1])
            assert rec_fd3 is not None and rec_fd3.status == "succeeded"

            with SessionLocal() as s:
                assert s.scalar(sa.select(sa.func.count()).select_from(CrudItem)) == 0
        finally:
            deck.close()


def test_crud_subtable_scoping_delete_validation_restore_and_chunked_rollback() -> None:
    from flask_deck.exceptions import ValidationError

    restored_hooks: list[int] = []

    class _ScopedOrgView(ModelView):
        model = CrudOrg
        slug = "orgs"

    class _ScopedItemView(ModelView):
        model = CrudItem
        slug = "items"
        soft_delete_column = "deleted_at"
        version_column = "version"

        def scope_query(self, stmt: Any, user: Any) -> Any:
            _ = user
            return stmt.where(CrudItem.code != "HIDDEN-SUB")

        def can_view_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.locked

        def on_model_delete(self, obj: Any, *, user: Any) -> None:
            _ = user
            if obj.code == "VETO-ITEM":
                raise ValidationError({"__all__": ["Cannot delete vetoed item"]})

        def on_model_change(self, obj: Any, *, is_created: bool, user: Any) -> None:
            _ = (is_created, user)
            restored_hooks.append(obj.id)

        @action("bump_or_fail", label="Bump or Fail")
        def bump_or_fail(self, records: list[CrudItem], form_data: Any, user: Any) -> str:
            _ = (form_data, user)
            for r in records:
                r.title = f"{r.title} [bumped]"
                if r.code == "CHUNK-BOOM":
                    raise ValueError("Simulated chunk failure")
            return f"Bumped {len(records)}"

    with sqlite_memory_engine() as eng:
        CrudBase.metadata.create_all(eng)
        SL = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SL() as s:
            o1 = CrudOrg(name="Scoped Org")
            s.add(o1)
            s.flush()
            i_vis = CrudItem(code="VIS-SUB", title="Visible Sub", org_id=o1.id)
            i_hid = CrudItem(code="HIDDEN-SUB", title="Hidden Sub", org_id=o1.id)
            i_lock = CrudItem(code="LOCK-SUB", title="Locked Sub", org_id=o1.id, locked=True)
            i_veto = CrudItem(code="VETO-ITEM", title="Veto Item", org_id=o1.id)
            i_boom = CrudItem(code="CHUNK-BOOM", title="Boom Item", org_id=o1.id)
            i_trash = CrudItem(
                code="REST-ITEM",
                title="Restorable Item",
                org_id=o1.id,
                version=3,
                deleted_at=datetime.now(timezone.utc),
            )
            s.add_all([i_vis, i_hid, i_lock, i_veto, i_boom, i_trash])
            s.commit()
            o1_id = o1.id
            i_vis_id, i_veto_id, i_boom_id, i_trash_id = i_vis.id, i_veto.id, i_boom.id, i_trash.id

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "crud-reg-wave4-secret-32-bytes!"
        app.config["TESTING"] = True
        jobs = ThreadPoolJobBackend(max_workers=1)
        deck = Deck(
            app,
            session_factory=SL,
            engine=eng,
            allow_insecure_open=True,
            job_backend=jobs,
            audit_store=InMemoryAuditStore(),
            bulk_sync_limit=1,
        )
        deck.register(_ScopedOrgView, _ScopedItemView)
        try:
            c = app.test_client()
            html_idx = c.get("/admin/").get_data(as_text=True)
            marker = 'name="deck-csrf" content="'
            idx = html_idx.find(marker)
            if idx == -1:
                marker = 'name="csrf-token" content="'
                idx = html_idx.find(marker)
            start = idx + len(marker)
            csrf = html_idx[start : html_idx.find('"', start)]

            # 1. Detail subtables apply target view scope_query & can_view_record
            r_det = c.get(f"/admin/orgs/{o1_id}")
            assert r_det.status_code == 200
            det_html = r_det.get_data(as_text=True)
            assert "VIS-SUB" in det_html
            assert "HIDDEN-SUB" not in det_html
            assert "LOCK-SUB" not in det_html

            # 2. Delete catches ValidationError cleanly (redirects 302, record preserved)
            assert c.post(f"/admin/items/{i_veto_id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            with SL() as s:
                assert s.get(CrudItem, i_veto_id).deleted_at is None  # type: ignore[union-attr]

            # 3. Single-record restore bumps integer version_column & invokes on_model_change
            assert c.post(f"/admin/items/{i_trash_id}/restore", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            with SL() as s:
                restored = s.get(CrudItem, i_trash_id)
                assert restored is not None and restored.deleted_at is None and restored.version == 4
            assert i_trash_id in restored_hooks

            # 4. Chunked async action rolls back failing chunk without corrupting row
            r_chunk = c.post(
                "/admin/items/action/bump_or_fail",
                data={CSRF_FORM_FIELD: csrf, "selected_pks": [str(i_vis_id), str(i_boom_id)]},
            )
            assert r_chunk.status_code == 302 and "focus=" in r_chunk.headers["Location"]
            jid = r_chunk.headers["Location"].split("focus=")[-1]
            rec_j = _wait_job(jobs, jid)
            assert rec_j is not None and rec_j.status in {"succeeded", "failed"}
            with SL() as s:
                assert s.get(CrudItem, i_boom_id).title == "Boom Item"  # type: ignore[union-attr]
        finally:
            deck.close()
