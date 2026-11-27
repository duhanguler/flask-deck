"""Behavioral contract tests for the headless REST API v1 and OpenAPI 3.1 generator."""

from __future__ import annotations

import enum
import uuid
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from flask_deck import (
    ActionField,
    Deck,
    DeckUser,
    InMemoryAPIKeyStore,
    InMemoryApprovalStore,
    ModelView,
    RBACAuthProvider,
    Role,
    action,
    build_api_key_record,
)
from flask_deck.rest_api import _current_obj_to_form_strings, json_safe_value
from tests._backends import sqlite_memory_engine


class RestStatus(enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class RestBase(DeclarativeBase):
    pass


class RestItem(RestBase):
    __tablename__ = "rest_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    status: Mapped[RestStatus] = mapped_column(sa.Enum(RestStatus), default=RestStatus.DRAFT, nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("0.00"), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    meta: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)


class RestComposite(RestBase):
    __tablename__ = "rest_composite"
    tenant: Mapped[str] = mapped_column(sa.String(20), primary_key=True)
    seq: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(60), nullable=False)


class RestItemView(ModelView):
    model = RestItem
    slug = "items"
    columns = ("code", "status", "amount", "active", "version")
    searchable_columns = ("code",)
    filterable_columns = ("status", "active")
    sortable_columns = ("id", "code", "amount")
    soft_delete_column = "deleted_at"
    version_column = "version"

    def can_view_record(self, obj: Any, user: Any) -> bool:
        return not (obj.code == "SECRET-VIEW" and user is not None and not user.is_superuser)

    def can_edit_record(self, obj: Any, user: Any) -> bool:
        return not obj.locked

    def can_delete_record(self, obj: Any, user: Any) -> bool:
        return not obj.locked

    @action(
        "publish",
        label="Publish Items",
        fields=(
            ActionField(
                "target",
                "select",
                label="Target State",
                choices=(("active", "Active"), ("archived", "Archived")),
                required=True,
            ),
        ),
    )
    def publish(self, records: list[RestItem], form_data: Any, user: Any) -> str:
        target = form_data.get("target", "active")
        if target == "archived" and any(r.code == "FAIL-ACT" for r in records):
            raise ValueError("Cannot archive FAIL-ACT")
        for r in records:
            r.status = RestStatus(target)
        return f"Updated {len(records)} item(s)"


class RestApprovalView(ModelView):
    model = RestItem
    slug = "governed-items"
    name = "GovernedItem"
    plural_name = "Governed Items"
    soft_delete_column = "deleted_at"
    version_column = "version"
    approval_required = ("create", "edit", "delete")

    @action("approve_act", label="Governed Action", require_approval=True)
    def approve_act(self, records: list[RestItem], form_data: Any, user: Any) -> str:
        return f"Ran on {len(records)}"


class RestDisabledView(ModelView):
    model = RestItem
    slug = "disabled-items"
    can_view = False
    can_create = False
    can_edit = False
    can_delete = False


class RestReadOnlyView(ModelView):
    model = RestItem
    slug = "ro-items"
    can_create = False
    can_edit = False
    can_delete = False


class RestCompositeView(ModelView):
    model = RestComposite
    slug = "composites"

    @action("retag", label="Retag")
    def retag(self, records: list[RestComposite], form_data: Any, user: Any) -> str:
        for r in records:
            r.label = f"{r.label}*"
        return f"Retagged {len(records)}"


@contextmanager
def _build_rest_app(*, enable_approvals: bool = True) -> Any:
    with sqlite_memory_engine() as eng:
        RestBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "rest-contract-secret-32-bytes!!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[
                Role("superadmin", permissions=frozenset({"*"})),
                Role(
                    "operator",
                    permissions=frozenset(
                        {
                            "items:view",
                            "items:create",
                            "items:edit",
                            "items:delete",
                            "items:action:publish",
                            "governed-items:view",
                            "governed-items:create",
                            "governed-items:edit",
                            "governed-items:delete",
                            "governed-items:action:approve_act",
                        }
                    ),
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="secret-pass",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="op", username="op", roles=("operator",)),
                    password="secret-pass",
                ),
            ],
        )
        key_store = InMemoryAPIKeyStore()
        admin_tok, admin_rec = build_api_key_record(
            name="admin-key", owner_id="admin", owner_name="Admin", scopes=("*",), is_superuser=True
        )
        op_tok, op_rec = build_api_key_record(
            name="op-key",
            owner_id="op",
            owner_name="Operator",
            scopes=(
                "items:*",
                "governed-items:*",
            ),
            roles=("operator",),
        )
        key_store.create(admin_rec)
        key_store.create(op_rec)

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            api_key_store=key_store,
            approval_store=InMemoryApprovalStore() if enable_approvals else False,
            enable_rest_api=True,
        )
        deck.register(RestItemView, RestApprovalView, RestDisabledView, RestReadOnlyView, RestCompositeView)
        try:
            yield app, deck, eng, admin_tok, op_tok
        finally:
            deck.close()


def test_json_safe_value_and_form_string_helpers() -> None:
    uid = uuid.uuid4()
    assert json_safe_value(RestStatus.ACTIVE) == "active"
    assert json_safe_value(date(2026, 5, 1)) == "2026-05-01"
    assert json_safe_value(time(12, 30)) == "12:30:00"
    assert json_safe_value(Decimal("42.50")) == "42.50"
    assert json_safe_value(uid) == str(uid)
    assert json_safe_value(b"abc") == "<bytes:3>"
    assert json_safe_value({"k": [1, RestStatus.DRAFT]}) == {"k": [1, "draft"]}
    assert json_safe_value(object()).startswith("<object")

    with _build_rest_app() as (_app, deck, _eng, _a, _o):
        view = deck.get_view("items")
        it = RestItem(
            code="X",
            status=RestStatus.ACTIVE,
            amount=Decimal("10.00"),
            active=True,
            meta={"a": 1},
            deleted_at=None,
        )
        assert _current_obj_to_form_strings(it, "deleted_at", view) == [""]
        assert _current_obj_to_form_strings(it, "active", view) == ["true"]
        assert _current_obj_to_form_strings(it, "status", view) == ["active"]
        assert _current_obj_to_form_strings(it, "meta", view) == ['{"a": 1}']
        assert _current_obj_to_form_strings(it, "code", view) == ["X"]
        assert _current_obj_to_form_strings(it, "nonexistent", view) == []


def test_rest_api_crud_occ_soft_delete_actions_and_openapi_contracts() -> None:
    with _build_rest_app() as (app, _deck, _eng, admin_tok, op_tok):
        admin_hdr = {"Authorization": f"Bearer {admin_tok}"}
        op_hdr = {"Authorization": f"Bearer {op_tok}"}
        client = app.test_client()
        # OpenAPI 3.1 spec + models listing omit disabled models
        spec = client.get("/admin/_api/v1/openapi.json", headers=admin_hdr).get_json()
        assert spec["openapi"] == "3.1.0"
        assert "/admin/_api/v1/items" in spec["paths"]
        assert "/admin/_api/v1/disabled-items" not in spec["paths"]
        item_props = spec["components"]["schemas"]["RestItem"]["properties"]
        assert item_props["amount"]["type"] == "number"
        assert item_props["active"]["type"] == "boolean"
        assert item_props["meta"]["type"] == "object"

        models_resp = client.get("/admin/_api/v1/models", headers=admin_hdr).get_json()
        slugs = {m["slug"] for m in models_resp["models"]}
        assert "items" in slugs and "disabled-items" not in slugs

        # Disabled / read-only enforcement
        assert client.get("/admin/_api/v1/disabled-items", headers=admin_hdr).status_code == 404
        assert client.get("/admin/_api/v1/disabled-items/1", headers=admin_hdr).status_code == 404
        assert client.post("/admin/_api/v1/ro-items", json={"code": "A"}, headers=admin_hdr).status_code == 403
        assert client.post("/admin/_api/v1/items", data="not-json", headers=admin_hdr).status_code == 400

        # Create item + duplicate unique constraint -> 409
        r_create = client.post(
            "/admin/_api/v1/items",
            json={"code": "SKU-01", "status": "draft", "amount": "19.99", "active": True, "meta": {"tier": 1}},
            headers=admin_hdr,
        )
        assert r_create.status_code == 201
        etag_v1 = r_create.headers["ETag"]
        created = r_create.get_json()
        pk = created["_pk"]

        r_dup = client.post(
            "/admin/_api/v1/items",
            json={"code": "SKU-01", "status": "draft", "amount": "1.00"},
            headers=admin_hdr,
        )
        assert r_dup.status_code == 409

        # Invalid page / page_size gracefully fall back to defaults
        r_list = client.get(
            "/admin/_api/v1/items?page=bad&page_size=nope&f_status=draft",
            headers=admin_hdr,
        )
        assert r_list.status_code == 200
        assert r_list.get_json()["total"] == 1

        # GET item returns ETag; PATCH with stale If-Match returns 409; valid PATCH bumps version_column
        r_get = client.get(f"/admin/_api/v1/items/{pk}", headers=admin_hdr)
        assert r_get.status_code == 200 and r_get.headers["ETag"] == etag_v1

        assert (
            client.patch(
                f"/admin/_api/v1/items/{pk}",
                json={"amount": "25.00"},
                headers={**admin_hdr, "If-Match": '"stale-token"'},
            ).status_code
            == 409
        )
        assert client.patch(f"/admin/_api/v1/items/{pk}", data="bad", headers=admin_hdr).status_code == 400
        assert (
            client.patch(f"/admin/_api/v1/items/{pk}", json={"unknown_field": "x"}, headers=admin_hdr).status_code
            == 422
        )

        r_patch = client.patch(
            f"/admin/_api/v1/items/{pk}",
            json={"amount": "25.00", "status": "active"},
            headers={**admin_hdr, "If-Match": etag_v1},
        )
        assert r_patch.status_code == 200
        assert r_patch.get_json()["version"] == 2

        # Per-record authorization hooks (can_view_record / can_edit_record / can_delete_record)
        r_secret = client.post("/admin/_api/v1/items", json={"code": "SECRET-VIEW"}, headers=admin_hdr)
        secret_pk = r_secret.get_json()["_pk"]
        assert client.get(f"/admin/_api/v1/items/{secret_pk}", headers=op_hdr).status_code == 403

        r_locked = client.post("/admin/_api/v1/items", json={"code": "LOCK-1", "locked": True}, headers=admin_hdr)
        locked_pk = r_locked.get_json()["_pk"]
        assert client.patch(f"/admin/_api/v1/items/{locked_pk}", json={"amount": "5.00"}, headers=admin_hdr).status_code == 403
        assert client.delete(f"/admin/_api/v1/items/{locked_pk}", headers=admin_hdr).status_code == 403

        # Read-only model PATCH/DELETE return 403
        assert client.patch(f"/admin/_api/v1/ro-items/{pk}", json={"amount": "1.00"}, headers=admin_hdr).status_code == 403
        assert client.delete(f"/admin/_api/v1/ro-items/{pk}", headers=admin_hdr).status_code == 403

        # Action endpoint: unknown 404, non-dict 400, missing pks 422, bad params 422, bad choice 422, handler error 422, success 200
        assert client.post("/admin/_api/v1/items/actions/nope", json={"pks": [pk]}, headers=admin_hdr).status_code == 404
        assert client.post("/admin/_api/v1/items/actions/publish", json=["not-a-dict"], headers=admin_hdr).status_code == 400
        assert client.post("/admin/_api/v1/items/actions/publish", json={"pks": []}, headers=admin_hdr).status_code == 422
        assert client.post("/admin/_api/v1/items/actions/publish", json={"pks": ["99999"]}, headers=admin_hdr).status_code == 404
        assert client.post("/admin/_api/v1/items/actions/publish", json={"pks": [pk], "params": "bad"}, headers=admin_hdr).status_code == 422
        assert client.post("/admin/_api/v1/items/actions/publish", json={"pks": [pk], "params": {}}, headers=admin_hdr).status_code == 422
        assert client.post("/admin/_api/v1/items/actions/publish", json={"pks": [pk], "params": {"target": "bogus"}}, headers=admin_hdr).status_code == 422

        r_fail_it = client.post("/admin/_api/v1/items", json={"code": "FAIL-ACT"}, headers=admin_hdr)
        fail_pk = r_fail_it.get_json()["_pk"]
        assert (
            client.post(
                "/admin/_api/v1/items/actions/publish",
                json={"pks": [fail_pk], "params": {"target": "archived"}},
                headers=admin_hdr,
            ).status_code
            == 422
        )
        r_act_ok = client.post(
            "/admin/_api/v1/items/actions/publish",
            json={"pks": [pk], "params": {"target": "archived"}},
            headers=admin_hdr,
        )
        assert r_act_ok.status_code == 200 and r_act_ok.get_json()["count"] == 1

        # Composite PK action execution
        r_comp = client.post(
            "/admin/_api/v1/composites",
            json={"tenant": "eu", "seq": 1, "label": "node"},
            headers=admin_hdr,
        )
        assert r_comp.status_code == 201
        comp_pk = r_comp.get_json()["_pk"]
        assert (
            client.post(
                "/admin/_api/v1/composites/actions/retag",
                json={"pks": [comp_pk]},
                headers=admin_hdr,
            ).status_code
            == 200
        )

        # Soft delete -> PATCH rejected 409 -> force delete removes permanently
        r_soft = client.delete(f"/admin/_api/v1/items/{pk}", headers=admin_hdr)
        assert r_soft.status_code == 200 and r_soft.get_json()["soft"] is True
        assert client.patch(f"/admin/_api/v1/items/{pk}", json={"amount": "1.00"}, headers=admin_hdr).status_code == 409
        r_force = client.delete(f"/admin/_api/v1/items/{pk}?force=1", headers=admin_hdr)
        assert r_force.status_code == 200 and r_force.get_json()["soft"] is False


def test_rest_api_four_eyes_approvals_queue_and_access_controls() -> None:
    with _build_rest_app(enable_approvals=True) as (app, _deck, _eng, admin_tok, op_tok):
        admin_hdr = {"Authorization": f"Bearer {admin_tok}"}
        op_hdr = {"Authorization": f"Bearer {op_tok}"}
        client = app.test_client()
        # Seed a baseline row directly via items so governed-items can propose edit/delete/action
        base = client.post("/admin/_api/v1/items", json={"code": "GOV-1", "amount": "50.00"}, headers=admin_hdr).get_json()
        pk = base["_pk"]

        # Create, edit, delete, and action on governed-items queue 202 approvals
        r_c = client.post(
            "/admin/_api/v1/governed-items",
            json={"code": "GOV-NEW", "_reason": "New SKU"},
            headers=op_hdr,
        )
        assert r_c.status_code == 202
        appr_c_id = r_c.get_json()["approval_id"]

        r_e = client.patch(
            f"/admin/_api/v1/governed-items/{pk}",
            json={"amount": "99.00", "_reason": "Adjust price"},
            headers=op_hdr,
        )
        assert r_e.status_code == 202

        r_d = client.delete(f"/admin/_api/v1/governed-items/{pk}", headers=op_hdr)
        assert r_d.status_code == 202

        r_a = client.post(
            "/admin/_api/v1/governed-items/actions/approve_act",
            json={"pks": [pk], "_reason": "Batch"},
            headers=op_hdr,
        )
        assert r_a.status_code == 202

        # Approvals listing: admin allowed, operator without approvals:view denied 403
        assert client.get("/admin/_api/v1/approvals?status=pending", headers=admin_hdr).status_code == 200
        assert client.get("/admin/_api/v1/approvals", headers=op_hdr).status_code == 403

        # Approval detail: requester may view own request; unknown ID -> 404
        assert client.get(f"/admin/_api/v1/approvals/{appr_c_id}", headers=op_hdr).status_code == 200
        assert client.get("/admin/_api/v1/approvals/does-not-exist", headers=admin_hdr).status_code == 404

        # Another requester's approval is forbidden to operator
        r_admin_c = client.post(
            "/admin/_api/v1/governed-items",
            json={"code": "GOV-ADMIN"},
            headers=admin_hdr,
        )
        assert client.get(f"/admin/_api/v1/approvals/{r_admin_c.get_json()['approval_id']}", headers=op_hdr).status_code == 403

    # Disabled approval store returns 404 cleanly
    with _build_rest_app(enable_approvals=False) as (app2, _deck2, _eng2, admin_tok2, _):
        c2 = app2.test_client()
        hdr2 = {"Authorization": f"Bearer {admin_tok2}"}
        assert c2.get("/admin/_api/v1/approvals", headers=hdr2).status_code == 404
        assert c2.get("/admin/_api/v1/approvals/any", headers=hdr2).status_code == 404


def test_rest_api_action_payload_precedence_nonlist_pks_and_approval_diff_redaction() -> None:
    class RedactedGovernedView(ModelView):
        model = RestItem
        slug = "redacted-items"
        approval_required = ("edit", "delete")

        @action("safe_act", label="Safe Action", require_approval=True)
        def safe_act(self, records: list[RestItem], form_data: Any, user: Any) -> str:
            _ = (form_data, user)
            return f"Ran {len(records)}"

    with sqlite_memory_engine() as eng:
        RestBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SessionLocal() as s:
            it = RestItem(code="SECRET-CODE-99", meta={"api_secret": "raw-token"})
            s.add(it)
            s.commit()
            pk = str(it.id)

        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role(
                    "fls_reviewer",
                    permissions=frozenset(
                        {
                            "redacted-items:view",
                            "redacted-items:delete",
                            "redacted-items:action:safe_act",
                            "approvals:view",
                        }
                    ),
                    hidden_fields={"redacted-items": frozenset({"meta"})},
                    masked_fields={"redacted-items": frozenset({"code"})},
                ),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="adm", username="adm", roles=("admin",), is_superuser=True),
                    password="secret",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="rev", username="rev", roles=("fls_reviewer",)),
                    password="secret",
                ),
            ],
        )
        keys = InMemoryAPIKeyStore()
        tok, rec = build_api_key_record(
            name="rev",
            owner_id="rev",
            owner_name="Reviewer",
            scopes=("redacted-items:*", "approvals:view"),
            roles=("fls_reviewer",),
        )
        keys.create(rec)
        approvals = InMemoryApprovalStore()

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "rest-bug-hunt-secret-32-bytes!!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            api_key_store=keys,
            approval_store=approvals,
            enable_rest_api=True,
        )
        deck.register(RedactedGovernedView)
        try:
            client = app.test_client()
            hdr = {"Authorization": f"Bearer {tok}"}

            # 1. Non-list 'pks' returns 422 instead of iterating characters of a string
            assert client.post(
                "/admin/_api/v1/redacted-items/actions/safe_act",
                json={"pks": pk},
                headers=hdr,
            ).status_code == 422

            # 2. Untrusted params cannot overwrite trusted 'action_name' or 'pks' in approval payload
            r_act = client.post(
                "/admin/_api/v1/redacted-items/actions/safe_act",
                json={
                    "pks": [pk],
                    "params": {"action_name": "evil_override", "pks": ["99999"]},
                },
                headers=hdr,
            )
            assert r_act.status_code == 202
            act_req = approvals.get(r_act.get_json()["approval_id"])
            assert act_req is not None
            assert act_req.payload["action_name"] == "safe_act"
            assert act_req.payload["pks"] == [pk]

            # 3. Approval endpoints strip hidden_fields & mask masked_fields in diff for FLS roles
            r_del = client.delete(f"/admin/_api/v1/redacted-items/{pk}", headers=hdr)
            assert r_del.status_code == 202
            del_id = r_del.get_json()["approval_id"]
            detail = client.get(f"/admin/_api/v1/approvals/{del_id}", headers=hdr).get_json()
            assert "meta" not in detail["diff"]
            assert "raw-token" not in str(detail["diff"])
            assert "SECRET-CODE-99" not in str(detail["diff"])

            listing = client.get("/admin/_api/v1/approvals", headers=hdr).get_json()
            assert "raw-token" not in str(listing["items"])
            assert "SECRET-CODE-99" not in str(listing["items"])
        finally:
            deck.close()
