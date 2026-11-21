from __future__ import annotations

from typing import Any

import sqlalchemy as sa

from flask_deck.adapters.sqlalchemy import encode_pk
from tests.conftest import CompositeMembership, Item, ItemNote, extract_csrf, login_as


def test_flask_sqlalchemy_dual_adapter_crud(fsa_app: tuple[Any, Any, Any]) -> None:
    app, _db, _deck = fsa_app
    client = app.test_client()

    resp = client.get("/admin/widget-models/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "FSA Widget 1" in html
    csrf = extract_csrf(html)

    create_resp = client.post(
        "/admin/widget-models/new",
        data={"name": "FSA Widget 2", "enabled": "true", "_csrf_token": csrf},
        follow_redirects=True,
    )
    assert create_resp.status_code == 200
    assert "FSA Widget 2" in create_resp.get_data(as_text=True)


def test_pure_sqlalchemy_crud_m2m_and_inlines(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # Create with M2M tags + JSON payload + Inline child note
    resp = client.post(
        "/admin/items/new",
        data={
            "_csrf_token": csrf,
            "code": "ITM-099",
            "title": "Edge Gateway",
            "email": "edge@alpha.io",
            "status": "active",
            "price": "320.00",
            "quantity": "4",
            "is_active": "true",
            "tenant_id": "1",
            "payload": '{"region": "eu-west-1"}',
            "tags": ["1", "2"],
            "inline__item-notes__0__body": "Provisioned automatically",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "ITM-099" in resp.get_data(as_text=True)

    with SessionLocal() as sess:
        created = sess.scalar(sa.select(Item).where(Item.code == "ITM-099"))
        assert created is not None
        assert len(created.tags) == 2
        assert len(created.notes) == 1
        assert created.notes[0].body == "Provisioned automatically"
        item_id = created.id
        note_id = created.notes[0].id

    # Detail page & Slide-Over Drawer
    detail = client.get(f"/admin/items/{item_id}")
    assert detail.status_code == 200
    assert "Edge Gateway" in detail.get_data(as_text=True)

    drawer = client.get(f"/admin/_api/items/{item_id}/drawer")
    assert drawer.status_code == 200
    d_html = drawer.get_data(as_text=True)
    assert "Overview" in d_html
    assert "Relations" in d_html
    assert "Audit" in d_html

    # Edit record + update & add inline child + delete previous inline
    edit_page = client.get(f"/admin/items/{item_id}/edit")
    assert edit_page.status_code == 200
    edit_resp = client.post(
        f"/admin/items/{item_id}/edit",
        data={
            "_csrf_token": csrf,
            "code": "ITM-099",
            "title": "Edge Gateway v2",
            "status": "archived",
            "price": "350.00",
            "quantity": "5",
            "is_active": "true",
            "tenant_id": "1",
            "inline__item-notes__0___pk": str(note_id),
            "inline__item-notes__0___delete": "1",
            "inline__item-notes__1__body": "Replaced note",
        },
        follow_redirects=True,
    )
    assert edit_resp.status_code == 200
    assert "Edge Gateway v2" in edit_resp.get_data(as_text=True)

    with SessionLocal() as sess:
        notes = list(sess.scalars(sa.select(ItemNote).where(ItemNote.item_id == item_id)).all())
        assert [n.body for n in notes] == ["Replaced note"]

    # Inline Quick-Edit PATCH
    patch_resp = client.patch(
        f"/admin/_api/items/{item_id}/quick-edit",
        json={"field": "is_active", "value": False},
        headers={"X-Deck-CSRFToken": csrf},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["value"] is False

    # FK Autocomplete API
    fk_resp = client.get("/admin/_api/fk/tenants?q=Alpha")
    assert fk_resp.status_code == 200
    fk_items = fk_resp.get_json()["items"]
    assert len(fk_items) == 1
    assert fk_items[0]["label"] == "Alpha Corp"

    # Custom Bulk Action
    act_resp = client.post(
        "/admin/items/action/activate",
        data={"_csrf_token": csrf, "selected_pks": [str(item_id)]},
        follow_redirects=True,
    )
    assert act_resp.status_code == 200
    assert "Activated 1 items" in act_resp.get_data(as_text=True)

    # Delete
    del_resp = client.post(
        f"/admin/items/{item_id}/delete",
        data={"_csrf_token": csrf},
        follow_redirects=True,
    )
    assert del_resp.status_code == 200
    with SessionLocal() as sess:
        assert sess.get(Item, item_id) is None


def test_composite_pk_detail_and_edit(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    pk_encoded = encode_pk((1, "u-10"))
    resp = client.get(f"/admin/composite-memberships/{pk_encoded}")
    assert resp.status_code == 200
    assert "owner" in resp.get_data(as_text=True)

    edit = client.post(
        f"/admin/composite-memberships/{pk_encoded}/edit",
        data={"_csrf_token": csrf, "role_name": "superowner"},
        follow_redirects=True,
    )
    assert edit.status_code == 200
    with SessionLocal() as sess:
        row = sess.get(CompositeMembership, (1, "u-10"))
        assert row is not None and row.role_name == "superowner"


def test_form_validation_errors_preserve_response(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    resp = client.post(
        "/admin/items/new",
        data={
            "_csrf_token": csrf,
            "code": "ITM-BAD",
            "title": "Bad JSON Item",
            "price": "not-a-decimal",
            "payload": "{broken json",
            "tenant_id": "1",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Must be a valid decimal value." in body
    assert "Invalid JSON" in body
