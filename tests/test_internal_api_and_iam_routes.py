"""Behavioral & security tests for internal UI API routes (/admin/_api/*) and IAM routes (/admin/_security/*)."""

from __future__ import annotations

import enum
from datetime import datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Any

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    Deck,
    DeckUser,
    FileFieldConfig,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemoryRecordNoteStore,
    InMemorySavedViewStore,
    InMemorySessionStore,
    MemoryFileStorage,
    ModelView,
    RBACAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
)
from flask_deck.mfa import MFA_VERIFIED_KEY
from flask_deck.security import CSRF_FORM_FIELD, CSRF_HEADER_NAME
from tests._backends import sqlite_memory_engine


class ApiState(enum.Enum):
    NEW = "new"
    DONE = "done"


class ApiBase(DeclarativeBase):
    pass


class ApiParent(ApiBase):
    __tablename__ = "api_parents"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), unique=True, nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    children: Mapped[list[ApiChild]] = relationship(back_populates="parent")

    def __str__(self) -> str:
        return self.name


class ApiChild(ApiBase):
    __tablename__ = "api_children"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(sa.ForeignKey("api_parents.id"), nullable=True)
    state: Mapped[ApiState] = mapped_column(sa.Enum(ApiState), default=ApiState.NEW, nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("10.00"), nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    doc_path: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    parent: Mapped[ApiParent | None] = relationship(back_populates="children")


class ApiParentView(ModelView):
    model = ApiParent
    slug = "parents"
    searchable_columns = ("name",)
    filterable_columns = ("active",)


class ApiChildView(ModelView):
    model = ApiChild
    slug = "children"
    searchable_columns = ("code",)
    filterable_columns = ("state", "parent_id")
    inline_editable_columns = ("state", "amount", "parent_id")
    soft_delete_column = "deleted_at"
    version_column = "version"

    def can_view_record(self, obj: Any, user: Any) -> bool:
        return not (obj.code == "HIDDEN" and user is not None and not user.is_superuser)

    def can_edit_record(self, obj: Any, user: Any) -> bool:
        return not obj.locked

    def can_delete_record(self, obj: Any, user: Any) -> bool:
        return not obj.locked

    def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
        _ = obj
        if str(data.get("amount", "")) == "999.00":
            return {"amount": ["999 is reserved"]}
        return {}


class ApiFileChildView(ModelView):
    model = ApiChild
    slug = "file-children"
    file_fields = MappingProxyType({"doc_path": FileFieldConfig(storage=MemoryFileStorage(), kind="file")})


class ApiGovernedChildView(ModelView):
    model = ApiChild
    slug = "gov-children"
    inline_editable_columns = ("state",)
    approval_required = ("create", "edit", "delete")


class ApiDisabledView(ModelView):
    model = ApiParent
    slug = "disabled-parents"
    can_view = False
    can_create = False
    can_edit = False
    can_delete = False


def _login_csrf(client: Any, username: str, password: str) -> str:
    html = client.get("/admin/login").get_data(as_text=True)
    tok = html.split('name="_csrf_token" value="', 1)[1].split('"', 1)[0]
    r = client.post("/admin/login", data={"username": username, "password": password, CSRF_FORM_FIELD: tok}, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    return body.split('name="deck-csrf" content="', 1)[1].split('"', 1)[0]


def test_internal_api_fk_lookup_quick_ops_delete_impact_saved_views_and_notes() -> None:
    with sqlite_memory_engine() as eng:
        ApiBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "internal-api-secret-32-bytes!!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[
                Role("superadmin", permissions=frozenset({"*"})),
                Role("viewer", permissions=frozenset({"children:view", "parents:view"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="secret-pass",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="viewer", username="viewer", roles=("viewer",)),
                    password="secret-pass",
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
            saved_view_store=InMemorySavedViewStore(),
            note_store=InMemoryRecordNoteStore(),
        )
        deck.register(ApiParentView, ApiChildView, ApiFileChildView, ApiGovernedChildView, ApiDisabledView)

        try:
            with SessionLocal() as sess:
                p1 = ApiParent(name="Org-A", active=True)
                p2 = ApiParent(name="Org-B", active=False)
                sess.add_all([p1, p2])
                sess.flush()
                c1 = ApiChild(code="CH-1", parent_id=p1.id)
                c_locked = ApiChild(code="LOCKED", parent_id=p1.id, locked=True)
                c_hidden = ApiChild(code="HIDDEN", parent_id=p1.id)
                sess.add_all([c1, c_locked, c_hidden])
                sess.commit()
                p1_id, p2_id = p1.id, p2.id
                c1_id, c_locked_id, c_hidden_id = c1.id, c_locked.id, c_hidden.id

            ac = app.test_client()
            csrf_a = _login_csrf(ac, "admin", "secret-pass")
            vc = app.test_client()
            csrf_v = _login_csrf(vc, "viewer", "secret-pass")
            hdr_a = {"X-Deck-CSRFToken": csrf_a, "Accept": "application/json"}
            hdr_v = {"X-Deck-CSRFToken": csrf_v, "Accept": "application/json"}

            # 1. Search, FK, Lookup, Drawer, Facets, Notifications
            assert ac.get("/admin/_api/search?q=CH-1").status_code == 200
            assert ac.get("/admin/_api/fk/disabled-parents").status_code == 404
            fk_r = ac.get("/admin/_api/fk/parents?q=Org&dep_col=active&dep_val=true&page=bad&page_size=bad&owner_slug=children&field_name=parent_id")
            assert fk_r.status_code == 200 and len(fk_r.get_json()["items"]) == 1
            assert ac.get("/admin/_api/fk/parents?is_m2m=1&owner_slug=children&field_name=parent_id").status_code == 200

            assert ac.get("/admin/_api/disabled-parents/lookup").status_code == 404
            assert ac.get("/admin/_api/parents/lookup?q=Org&dep_col=active&dep_val=true&page=bad&owner_slug=children&field_name=parent_id").status_code == 200

            assert ac.get(f"/admin/_api/disabled-parents/{p1_id}/drawer").status_code == 404
            assert vc.get(f"/admin/_api/children/{c_hidden_id}/drawer").status_code == 403
            assert ac.get(f"/admin/_api/children/{c1_id}/drawer").status_code == 200
            assert ac.get("/admin/_api/children/facets?q=CH").status_code == 200
            assert ac.get("/admin/_api/disabled-parents/facets").status_code == 404

            # 2. Quick-Edit PATCH boundaries
            assert ac.patch(f"/admin/_api/disabled-parents/{p1_id}/quick-edit", json={}, headers=hdr_a).status_code == 403
            assert ac.patch(f"/admin/_api/children/{c_locked_id}/quick-edit", json={"field": "state", "value": "done"}, headers=hdr_a).status_code == 403
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", data="bad", headers=hdr_a).status_code == 400
            assert ac.patch(f"/admin/_api/gov-children/{c1_id}/quick-edit", json={"field": "state", "value": "done"}, headers=hdr_a).status_code == 403
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "code", "value": "X"}, headers=hdr_a).status_code == 403
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "amount", "value": "not-a-num"}, headers=hdr_a).status_code == 422
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "parent_id", "value": "999999"}, headers=hdr_a).status_code == 422
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "amount", "value": "999.00"}, headers=hdr_a).status_code == 422
            r_qe = ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "amount", "value": "42.50"}, headers=hdr_a)
            assert r_qe.status_code == 200 and r_qe.get_json()["value"] == "42.50"

            # 3. Quick-Create & Quick-Edit-Form slide-over endpoints
            assert ac.get("/admin/_api/disabled-parents/quick-create").status_code == 403
            assert ac.get("/admin/_api/file-children/quick-create").status_code == 400
            assert ac.get("/admin/_api/gov-children/quick-create").status_code == 409
            assert ac.get("/admin/_api/parents/quick-create").status_code == 200
            r_qc = ac.post("/admin/_api/parents/quick-create", data={CSRF_FORM_FIELD: csrf_a, "name": "Org-New", "active": "true"})
            assert r_qc.status_code == 201
            new_p_id = r_qc.get_json()["id"]
            # Duplicate name triggers IntegrityError -> 422 re-rendered form
            assert ac.post("/admin/_api/parents/quick-create", data={CSRF_FORM_FIELD: csrf_a, "name": "Org-New", "active": "true"}).status_code == 422

            assert ac.get(f"/admin/_api/disabled-parents/{p1_id}/quick-edit-form").status_code == 403
            assert ac.get(f"/admin/_api/children/{c_locked_id}/quick-edit-form").status_code == 403
            assert ac.get(f"/admin/_api/file-children/{c1_id}/quick-edit-form").status_code == 400
            assert ac.get(f"/admin/_api/gov-children/{c1_id}/quick-edit-form").status_code == 409
            assert ac.get(f"/admin/_api/parents/{new_p_id}/quick-edit-form").status_code == 200
            assert ac.post(f"/admin/_api/parents/{new_p_id}/quick-edit-form", data={CSRF_FORM_FIELD: csrf_a, "name": "Org-Updated", "active": "true"}).status_code == 200
            assert ac.post(f"/admin/_api/parents/{new_p_id}/quick-edit-form", data={CSRF_FORM_FIELD: csrf_a, "name": "Org-A", "active": "true"}).status_code == 422

            # 4. Delete-Impact API
            assert ac.post("/admin/_api/disabled-parents/delete-impact", json={"pks": [str(p1_id)]}, headers=hdr_a).status_code == 403
            assert ac.post("/admin/_api/children/delete-impact", data="bad", headers=hdr_a).status_code == 400
            assert ac.post("/admin/_api/parents/delete-impact", json={"pks": [str(p1_id)], "force": True}, headers=hdr_a).status_code == 400
            assert ac.post("/admin/_api/children/delete-impact", json={"pks": "bad"}, headers=hdr_a).status_code == 400
            assert ac.post("/admin/_api/children/delete-impact", json={"pks": []}, headers=hdr_a).status_code == 200
            assert ac.post("/admin/_api/children/delete-impact", json={"pks": ["not-an-int"]}, headers=hdr_a).status_code == 400
            assert ac.post("/admin/_api/children/delete-impact", json={"select_across": True, "slice_token": "bogus"}, headers=hdr_a).status_code == 403
            assert ac.post("/admin/_api/children/delete-impact", json={"pks": [str(c1_id)]}, headers=hdr_a).status_code == 200

            # 5. Saved Views API (JSON + HTML validation, RBAC, delete)
            assert ac.get("/admin/_api/children/saved-views").status_code == 200
            assert ac.post("/admin/_api/children/saved-views", data="bad", content_type="application/json", headers=hdr_a).status_code == 400
            assert ac.post("/admin/_api/children/saved-views", json={"name": ""}, headers=hdr_a).status_code == 422
            assert ac.post("/admin/_api/children/saved-views", json={"name": "X", "scope": "invalid"}, headers=hdr_a).status_code == 422
            assert vc.post("/admin/_api/children/saved-views", json={"name": "T", "scope": "team"}, headers=hdr_v).status_code == 403
            assert ac.post("/admin/_api/children/saved-views", json={"name": "R", "scope": "role"}, headers=hdr_a).status_code == 422
            assert ac.post("/admin/_api/children/saved-views", json={"name": "S", "query_string": "javascript:alert(1)"}, headers=hdr_a).status_code == 422
            assert ac.post("/admin/_api/children/saved-views", json={"name": "S2", "query_string": "a=\x01"}, headers=hdr_a).status_code == 422

            r_sv = ac.post("/admin/_api/children/saved-views", json={"name": "My Slice", "scope": "personal", "query_string": "f_state=new"}, headers=hdr_a)
            assert r_sv.status_code == 201
            sv_id = r_sv.get_json()["saved_view"]["id"]
            assert vc.post(f"/admin/_api/children/saved-views/{sv_id}/delete", headers=hdr_v).status_code == 403
            assert ac.post("/admin/_api/children/saved-views/missing/delete", headers=hdr_a).status_code == 404
            assert ac.post(f"/admin/_api/children/saved-views/{sv_id}/delete", headers=hdr_a).status_code == 200
            # HTML form redirect flow
            assert ac.post("/admin/_api/children/saved-views", data={CSRF_FORM_FIELD: csrf_a, "name": "Form View", "scope": "personal", "query_string": "f_state=done"}).status_code == 302

            # 6. Record Notes API (GET, JSON/HTML POST, pin, delete, RBAC, soft-deleted)
            assert ac.get(f"/admin/_api/children/{c1_id}/notes").status_code == 200
            assert vc.post(f"/admin/_api/children/{c1_id}/notes", json={"body": "hi"}, headers=hdr_v).status_code == 403
            assert ac.post(f"/admin/_api/children/{c1_id}/notes", data="bad", content_type="application/json", headers=hdr_a).status_code == 400
            assert ac.post(f"/admin/_api/children/{c1_id}/notes", json={"body": "  "}, headers=hdr_a).status_code == 422
            r_note = ac.post(f"/admin/_api/children/{c1_id}/notes", json={"body": "**Checked**", "pinned": True}, headers=hdr_a)
            assert r_note.status_code == 201
            note_id = r_note.get_json()["note"]["id"]

            assert ac.post(f"/admin/_api/children/{c1_id}/notes/missing/pin", headers=hdr_a).status_code == 404
            assert ac.post(f"/admin/_api/children/{c1_id}/notes/{note_id}/pin", headers=hdr_a).status_code == 200
            assert vc.post(f"/admin/_api/children/{c1_id}/notes/{note_id}/delete", headers=hdr_v).status_code == 403
            assert ac.post(f"/admin/_api/children/{c1_id}/notes/missing/delete", headers=hdr_a).status_code == 404
            assert ac.post(f"/admin/_api/children/{c1_id}/notes/{note_id}/delete", headers=hdr_a).status_code == 200

            # 7. Quick-Delete (soft delete + already trashed 409 + hard delete) & Notifications
            assert ac.post(f"/admin/_api/disabled-parents/{p2_id}/quick-delete", headers=hdr_a).status_code == 403
            assert ac.post(f"/admin/_api/children/{c_locked_id}/quick-delete", headers=hdr_a).status_code == 403
            assert ac.post(f"/admin/_api/gov-children/{c1_id}/quick-delete", headers=hdr_a).status_code == 409
            r_qd_soft = ac.post(f"/admin/_api/children/{c1_id}/quick-delete", headers=hdr_a)
            assert r_qd_soft.status_code == 200 and r_qd_soft.get_json()["soft"] is True
            assert ac.post(f"/admin/_api/children/{c1_id}/quick-delete", headers=hdr_a).status_code == 409
            assert ac.patch(f"/admin/_api/children/{c1_id}/quick-edit", json={"field": "state", "value": "done"}, headers=hdr_a).status_code == 409
            assert ac.get(f"/admin/_api/children/{c1_id}/quick-edit-form").status_code == 409
            assert ac.get(f"/admin/_api/children/{c1_id}/notes", headers=hdr_a).status_code == 404
            r_qd_hard = ac.post(f"/admin/_api/parents/{p2_id}/quick-delete", headers=hdr_a)
            assert r_qd_hard.status_code == 200 and r_qd_hard.get_json()["soft"] is False

            assert ac.get("/admin/_api/notifications").status_code == 200
        finally:
            deck.close()


def test_iam_routes_privilege_escalation_guards_and_password_rotation() -> None:
    with sqlite_memory_engine() as eng:
        ApiBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "iam-routes-secret-32-bytes-long!"
        app.config["TESTING"] = True

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_super = auth.create_group(name="super", label="Super", permissions=frozenset({"*"}))
        g_mgr = auth.create_group(name="iam_mgr", label="IAM Mgr", permissions=frozenset({"iam:manage", "parents:view"}))
        g_basic = auth.create_group(name="basic", label="Basic", permissions=frozenset({"parents:view"}))

        u_root = auth.create_user(username="root", password="RootPassword1!", is_superuser=True, group_ids=[g_super.id])
        auth.create_user(username="mgr", password="MgrPassword1!", is_superuser=False, group_ids=[g_mgr.id])
        u_plain = auth.create_user(username="plain", password="PlainPassword1!", is_superuser=False, group_ids=[g_basic.id])

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            session_store=InMemorySessionStore(),
        )
        deck.register(ApiParentView)

        try:
            # 1. Non-superuser IAM manager privilege-escalation guards
            mc = app.test_client()
            csrf_m = _login_csrf(mc, "mgr", "MgrPassword1!")

            assert mc.get("/admin/_security/users?page=bad").status_code == 200
            assert mc.get(f"/admin/_security/users?edit={u_plain.id}").status_code == 200

            # Blocked: granting superuser, wildcard direct perm, or privileged group
            assert mc.post("/admin/_security/users/create", data={CSRF_FORM_FIELD: csrf_m, "username": "x1", "password": "ValidPass123!", "is_superuser": "1"}).status_code == 403
            assert mc.post("/admin/_security/users/create", data={CSRF_FORM_FIELD: csrf_m, "username": "x2", "password": "ValidPass123!", "direct_permissions": "*"}).status_code == 403
            assert mc.post("/admin/_security/users/create", data={CSRF_FORM_FIELD: csrf_m, "username": "x3", "password": "ValidPass123!", "group_ids": [g_super.id]}).status_code == 403

            # Blocked: modifying, bulk-deactivating, resetting password, or deleting a superuser
            assert mc.post(f"/admin/_security/users/{u_root.id}/update", data={CSRF_FORM_FIELD: csrf_m, "display_name": "Pwned"}).status_code == 403
            assert mc.post("/admin/_security/users/bulk", data={CSRF_FORM_FIELD: csrf_m, "action": "deactivate", "user_ids": [u_root.id]}).status_code == 403
            assert mc.post(f"/admin/_security/users/{u_root.id}/reset-password", data={CSRF_FORM_FIELD: csrf_m, "new_password": "NewPassword1!"}).status_code == 403
            assert mc.post(f"/admin/_security/users/{u_root.id}/delete", data={CSRF_FORM_FIELD: csrf_m}).status_code == 403

            # Blocked: updating non-super user to escalate to superuser / wildcard / privileged group
            assert mc.post(f"/admin/_security/users/{u_plain.id}/update", data={CSRF_FORM_FIELD: csrf_m, "is_superuser": "1"}).status_code == 403
            assert mc.post(f"/admin/_security/users/{u_plain.id}/update", data={CSRF_FORM_FIELD: csrf_m, "direct_permissions": "iam:manage"}).status_code == 403
            assert mc.post(f"/admin/_security/users/{u_plain.id}/update", data={CSRF_FORM_FIELD: csrf_m, "group_ids": [g_super.id]}).status_code == 403

            # Blocked: creating, modifying, or deleting privileged groups
            assert mc.post("/admin/_security/groups/create", data={CSRF_FORM_FIELD: csrf_m, "name": "badg", "perm": "*"}).status_code == 403
            assert mc.post(f"/admin/_security/groups/{g_super.id}/update", data={CSRF_FORM_FIELD: csrf_m, "label": "X"}).status_code == 403
            assert mc.post(f"/admin/_security/groups/{g_basic.id}/update", data={CSRF_FORM_FIELD: csrf_m, "label": "B", "extra_permissions": "iam:manage"}).status_code == 403
            assert mc.post(f"/admin/_security/groups/{g_super.id}/delete", data={CSRF_FORM_FIELD: csrf_m}).status_code == 403

            # Invalid bulk action & empty selection gracefully redirect
            assert mc.post("/admin/_security/users/bulk", data={CSRF_FORM_FIELD: csrf_m, "action": "bogus"}).status_code == 302
            assert mc.post("/admin/_security/users/bulk", data={CSRF_FORM_FIELD: csrf_m, "action": "deactivate"}).status_code == 302

            # 2. Superuser full CRUD on users & groups (incl. JSON & per-model field rules + 404s + errors)
            rc = app.test_client()
            csrf_r = _login_csrf(rc, "root", "RootPassword1!")

            assert rc.post("/admin/_security/users/missing/update", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404
            assert rc.post("/admin/_security/users/missing/reset-password", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404
            assert rc.post("/admin/_security/users/missing/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404

            # Validation errors flash & redirect cleanly
            assert rc.post("/admin/_security/users/create", data={CSRF_FORM_FIELD: csrf_r, "username": "badpw", "password": "123"}).status_code == 302
            assert rc.post(f"/admin/_security/users/{u_plain.id}/reset-password", data={CSRF_FORM_FIELD: csrf_r, "new_password": "123"}).status_code == 302

            # Valid create, update (deactivate revokes sessions), bulk activate, reset password, delete
            assert rc.post("/admin/_security/users/create", data={CSRF_FORM_FIELD: csrf_r, "username": "temp_op", "password": "TempPassword1!", "is_active": "1", "direct_permissions": "parents:view"}).status_code == 302
            temp_rec = auth.get_user_by_username("temp_op")
            assert temp_rec is not None
            assert rc.post(f"/admin/_security/users/{temp_rec.id}/update", data={CSRF_FORM_FIELD: csrf_r, "display_name": "Temp", "is_active": "0"}).status_code == 302
            assert rc.post("/admin/_security/users/bulk", data={CSRF_FORM_FIELD: csrf_r, "action": "activate", "user_ids": [temp_rec.id]}).status_code == 302
            assert rc.post(f"/admin/_security/users/{temp_rec.id}/reset-password", data={CSRF_FORM_FIELD: csrf_r, "new_password": "RotatedTemp1!"}).status_code == 302
            assert rc.post(f"/admin/_security/users/{temp_rec.id}/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302

            # Groups: invalid JSON rules, valid JSON & per-model rules, update, delete, 404
            assert rc.post("/admin/_security/groups/create", data={CSRF_FORM_FIELD: csrf_r, "name": "badjson", "hidden_fields_json": "{broken"}).status_code == 302
            assert rc.post("/admin/_security/groups/create", data={CSRF_FORM_FIELD: csrf_r, "name": "notobj", "hidden_fields_json": "[]"}).status_code == 302
            assert rc.post(
                "/admin/_security/groups/create",
                data={
                    CSRF_FORM_FIELD: csrf_r,
                    "name": "analysts",
                    "label": "Analysts",
                    "perm": "parents:view",
                    "extra_permissions": "audit:view",
                    "hidden_fields_json": '{"parents": ["active"]}',
                    "readonly_fields__parents": "name",
                },
            ).status_code == 302
            analysts = auth.get_group_by_name("analysts")
            assert analysts is not None
            assert rc.get(f"/admin/_security/groups?edit={analysts.id}").status_code == 200
            assert rc.post(f"/admin/_security/groups/{analysts.id}/update", data={CSRF_FORM_FIELD: csrf_r, "label": "Analysts v2", "perm": "parents:view"}).status_code == 302
            assert rc.post(f"/admin/_security/groups/{analysts.id}/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert rc.post("/admin/_security/groups/missing/update", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404
            assert rc.post("/admin/_security/groups/missing/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404

            # 3. Self-service password rotation (mismatch, bad current, success preserving MFA flag)
            with rc.session_transaction() as sess:
                sess[MFA_VERIFIED_KEY] = True
            assert rc.get("/admin/_security/password").status_code == 200
            assert rc.post("/admin/_security/password", data={CSRF_FORM_FIELD: csrf_r, "current_password": "RootPassword1!", "new_password": "NewRootPass1!", "confirm_password": "Diff!"}).status_code == 302
            assert rc.post("/admin/_security/password", data={CSRF_FORM_FIELD: csrf_r, "current_password": "Wrong", "new_password": "NewRootPass1!", "confirm_password": "NewRootPass1!"}).status_code == 302
            r_pw = rc.post("/admin/_security/password", data={CSRF_FORM_FIELD: csrf_r, "current_password": "RootPassword1!", "new_password": "NewRootPass1!", "confirm_password": "NewRootPass1!"})
            assert r_pw.status_code == 302
            with rc.session_transaction() as sess:
                assert sess.get(MFA_VERIFIED_KEY) is True
        finally:
            deck.close()


def test_internal_api_quick_forms_integrity_lookup_and_delete_impact() -> None:
    with sqlite_memory_engine() as eng:
        ApiBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            p1 = ApiParent(name="Acme")
            p2 = ApiParent(name="Beta")
            s.add_all([p1, p2])
            s.flush()
            c1 = ApiChild(code="CH-1", parent_id=p1.id)
            c2 = ApiChild(code="CH-2", parent_id=p1.id)
            s.add_all([c1, c2])
            s.commit()
            p1_id, p2_id, c1_id = p1.id, p2.id, c1.id

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "api-quick-forms-secret-32-bytes!"
        app.config["TESTING"] = True
        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role("viewer", permissions=frozenset({"children:view", "parents:view"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u1", username="admin", roles=("admin",), is_superuser=True),
                    password="AdminPassword1!",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u2", username="viewer", roles=("viewer",)),
                    password="ViewerPassword1!",
                ),
            ],
        )
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            note_store=InMemoryRecordNoteStore(),
            approval_store=False,
            session_store=InMemorySessionStore(),
        )
        deck.register(ApiParentView, ApiChildView, ApiFileChildView)

        try:
            c = app.test_client()
            csrf = _login_csrf(c, "admin", "AdminPassword1!")

            # Quick-create duplicate unique name -> 422 IntegrityError HTML; empty required -> 422 ValidationError
            assert c.get("/admin/_api/parents/quick-create").status_code == 200
            assert c.post("/admin/_api/parents/quick-create", data={CSRF_FORM_FIELD: csrf, "name": "Acme"}).status_code == 422
            assert c.post("/admin/_api/parents/quick-create", data={CSRF_FORM_FIELD: csrf, "name": ""}).status_code == 422

            # Quick-edit-form validation error (amount=999.00) & IntegrityError (duplicate code) -> 422
            assert c.get(f"/admin/_api/children/{c1_id}/quick-edit-form").status_code == 200
            assert c.post(
                f"/admin/_api/children/{c1_id}/quick-edit-form",
                data={CSRF_FORM_FIELD: csrf, "code": "CH-1", "state": "new", "amount": "999.00"},
            ).status_code == 422
            assert c.post(
                f"/admin/_api/children/{c1_id}/quick-edit-form",
                data={CSRF_FORM_FIELD: csrf, "code": "CH-2", "state": "new", "amount": "10.00"},
            ).status_code == 422
            assert c.post(
                f"/admin/_api/children/{c1_id}/quick-edit-form",
                data={CSRF_FORM_FIELD: csrf, "code": "CH-1", "state": "done", "amount": "20.00"},
            ).status_code == 200

            # Quick-edit PATCH invalid FK scope -> 422; custom validate error -> 422; valid FK update -> 200
            r_fk_bad = c.patch(
                f"/admin/_api/children/{c1_id}/quick-edit",
                json={"field": "parent_id", "value": "999999"},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_fk_bad.status_code == 422
            r_val_bad = c.patch(
                f"/admin/_api/children/{c1_id}/quick-edit",
                json={"field": "amount", "value": "999.00"},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_val_bad.status_code == 422
            r_fk_ok = c.patch(
                f"/admin/_api/children/{c1_id}/quick-edit",
                json={"field": "parent_id", "value": str(p2_id)},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_fk_ok.status_code == 200

            # Record notes permission boundaries (viewer cannot pin/delete) & soft-deleted guard (404)
            r_note = c.post(
                f"/admin/_api/children/{c1_id}/notes",
                json={"body": "Escalation context"},
                headers={CSRF_HEADER_NAME: csrf, "Accept": "application/json"},
            )
            assert r_note.status_code == 201
            note_id = r_note.get_json()["note"]["id"]

            c_viewer = app.test_client()
            csrf_v = _login_csrf(c_viewer, "viewer", "ViewerPassword1!")
            assert c_viewer.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/pin",
                headers={CSRF_HEADER_NAME: csrf_v, "Accept": "application/json"},
            ).status_code == 403
            assert c_viewer.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/pin",
                data={CSRF_FORM_FIELD: csrf_v},
            ).status_code == 403
            assert c_viewer.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/delete",
                headers={CSRF_HEADER_NAME: csrf_v, "Accept": "application/json"},
            ).status_code == 403
            assert c_viewer.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/delete",
                data={CSRF_FORM_FIELD: csrf_v},
            ).status_code == 403

            # Lookup modal, global search, and delete-impact JSON APIs
            assert c.get("/admin/_api/parents/lookup?q=Acme").status_code == 200
            assert c.get("/admin/_api/search?q=Acme").status_code == 200
            r_imp = c.post(
                "/admin/_api/parents/delete-impact",
                json={"pks": [str(p1_id)]},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_imp.status_code == 200
            assert r_imp.get_json()["target_count"] == 1

            # Quick-delete on soft-delete view (first succeeds soft, second 409 already trashed)
            assert c.post(f"/admin/_api/children/{c1_id}/quick-delete", headers={CSRF_HEADER_NAME: csrf}).status_code == 200
            assert c.post(f"/admin/_api/children/{c1_id}/quick-delete", headers={CSRF_HEADER_NAME: csrf}).status_code == 409

            # Trashed records reject note pin/delete with 404 (JSON & HTML)
            assert c.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/pin",
                headers={CSRF_HEADER_NAME: csrf, "Accept": "application/json"},
            ).status_code == 404
            assert c.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/pin",
                data={CSRF_FORM_FIELD: csrf},
            ).status_code == 404
            assert c.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/delete",
                headers={CSRF_HEADER_NAME: csrf, "Accept": "application/json"},
            ).status_code == 404
            assert c.post(
                f"/admin/_api/children/{c1_id}/notes/{note_id}/delete",
                data={CSRF_FORM_FIELD: csrf},
            ).status_code == 404
        finally:
            deck.close()


def test_internal_api_drawer_scoping_quick_create_approval_and_delete_impact_acl() -> None:
    from flask_deck.exceptions import ValidationError

    class _ScopedChildView(ModelView):
        model = ApiChild
        slug = "scoped-children"

        def scope_query(self, stmt: Any, user: Any) -> Any:
            _ = user
            return stmt.where(ApiChild.code != "HIDDEN-CH")

        def can_delete_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.locked

        def on_model_delete(self, obj: Any, *, user: Any) -> None:
            _ = user
            if obj.code == "VETO-DEL":
                raise ValidationError({"__all__": ["Delete vetoed by business rule"]})

    class _DrawerParentView(ModelView):
        model = ApiParent
        slug = "drawer-parents"
        relations_display = ("children",)

        def requires_approval(self, user: Any, operation: str, *, obj: Any = None, payload: Any = None) -> bool:
            _ = (user, obj)
            return operation == "create" and isinstance(payload, dict) and payload.get("name") == "NEEDS-APPROVAL"

    with sqlite_memory_engine() as eng:
        ApiBase.metadata.create_all(eng)
        SL = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SL() as s:
            p1 = ApiParent(name="Visible Parent")
            s.add(p1)
            s.flush()
            c_vis = ApiChild(code="VIS-CH", parent_id=p1.id)
            c_hid = ApiChild(code="HIDDEN-CH", parent_id=p1.id)
            c_veto = ApiChild(code="VETO-DEL", parent_id=p1.id)
            c_lock = ApiChild(code="LOCK-CH", parent_id=p1.id, locked=True)
            s.add_all([c_vis, c_hid, c_veto, c_lock])
            s.commit()
            p1_id = p1.id
            c_vis_id, c_veto_id, c_lock_id = c_vis.id, c_veto.id, c_lock.id

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "api-reg-wave4-secret-32-bytes!!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SL,
            engine=eng,
            allow_insecure_open=True,
            approval_store=InMemoryApprovalStore(),
            audit_store=False,
        )
        deck.register(_DrawerParentView, _ScopedChildView)
        try:
            c = app.test_client()
            csrf = _extract_csrf_open(c, "/admin/")

            # 1. Drawer & Detail scope relations_display via target view's scope_query
            r_dr = c.get(f"/admin/_api/drawer-parents/{p1_id}/drawer")
            assert r_dr.status_code == 200
            dr_html = r_dr.get_data(as_text=True)
            assert "VIS-CH" in dr_html and "HIDDEN-CH" not in dr_html

            r_det = c.get(f"/admin/drawer-parents/{p1_id}")
            assert r_det.status_code == 200
            det_html = r_det.get_data(as_text=True)
            assert "VIS-CH" in det_html and "HIDDEN-CH" not in det_html

            # 2. api_quick_create passes POST payload to requires_approval (409 when gated, 200 when ungated)
            assert c.post(
                "/admin/_api/drawer-parents/quick-create",
                data={CSRF_FORM_FIELD: csrf, "name": "NEEDS-APPROVAL"},
            ).status_code == 409
            r_qc_ok = c.post(
                "/admin/_api/drawer-parents/quick-create",
                data={CSRF_FORM_FIELD: csrf, "name": "Allowed Quick"},
            )
            assert r_qc_ok.status_code == 201 and r_qc_ok.get_json()["ok"] is True

            # 3. api_quick_delete converts ValidationError from on_model_delete into HTTP 422 cleanly
            r_qd_veto = c.post(
                f"/admin/_api/scoped-children/{c_veto_id}/quick-delete",
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_qd_veto.status_code == 422

            # 4. api_delete_impact fails closed (403) when a locked record is included, and deduplicates allowed PKs
            assert c.post(
                "/admin/_api/scoped-children/delete-impact",
                json={"pks": [str(c_vis_id), str(c_lock_id)]},
                headers={CSRF_HEADER_NAME: csrf},
            ).status_code == 403
            r_imp = c.post(
                "/admin/_api/scoped-children/delete-impact",
                json={"pks": [str(c_vis_id), str(c_vis_id)]},
                headers={CSRF_HEADER_NAME: csrf},
            )
            assert r_imp.status_code == 200
            assert r_imp.get_json()["target_count"] == 1

            # 5. api_lookup caps huge page numbers cleanly
            assert c.get("/admin/_api/drawer-parents/lookup?page=9999999").status_code == 200
        finally:
            deck.close()


def _extract_csrf_open(client: Any, url: str) -> str:
    html = client.get(url).get_data(as_text=True)
    for marker in ('name="deck-csrf" content="', 'name="csrf-token" content="', f'name="{CSRF_FORM_FIELD}" value="'):
        idx = html.find(marker)
        if idx != -1:
            start = idx + len(marker)
            return html[start : html.find('"', start)]
    raise AssertionError(f"CSRF token missing on {url}")
