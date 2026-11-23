from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.pool import StaticPool

from flask_deck.audit import SQLAlchemyAuditStore, compute_diff, make_audit_entry
from tests.conftest import Item, login_as


def test_compute_diff_redacts_sensitive_fields() -> None:
    diff = compute_diff(
        {"title": "Old", "password_hash": "hash1", "api_token": "tok1"},
        {"title": "New", "password_hash": "hash2", "api_token": "tok2"},
        sensitive_fields={"password_hash"},
    )
    assert diff["title"] == {"old": "Old", "new": "New"}
    assert diff["password_hash"] == {"old": "[REDACTED]", "new": "[REDACTED]"}
    assert diff["api_token"] == {"old": "[REDACTED]", "new": "[REDACTED]"}


def test_sqlalchemy_audit_store_persistence_and_filtering() -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    try:
        store = SQLAlchemyAuditStore(engine)
        e1 = make_audit_entry(
            actor_id="u1",
            actor_name="Alice",
            actor_ip="127.0.0.1",
            action="update",
            model_slug="orders",
            model_label="Order",
            record_pk="10",
            record_repr="ORD-10",
            changes={"status": {"old": "pending", "new": "paid"}},
        )
        e2 = make_audit_entry(
            actor_id="u2",
            actor_name="Bob",
            actor_ip="127.0.0.1",
            action="delete",
            model_slug="users",
            model_label="User",
            record_pk="5",
            record_repr="bob@acme.dev",
        )
        store.record(e1)
        store.record(e2)

        all_entries, total = store.list_entries()
        assert total == 2
        assert len(all_entries) == 2

        only_orders, count_o = store.list_entries(model_slug="orders", action="update", search="paid")
        assert count_o == 1
        assert only_orders[0].id == e1.id
        assert store.get_entry(e1.id) is not None
    finally:
        engine.dispose()


def test_audit_ledger_and_one_click_revert_flow(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, audit_store = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # Mutate title on Item #1
    edit = client.post(
        "/admin/items/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ITM-001",
            "title": "Accidental Rename",
            "status": "active",
            "price": "199.50",
            "quantity": "3",
            "is_active": "true",
            "tenant_id": "1",
        },
        follow_redirects=True,
    )
    assert edit.status_code == 200

    entries, total = audit_store.list_entries(model_slug="items", action="update")
    assert total == 1
    upd = entries[0]
    assert upd.changes["title"] == {"old": "Primary Server", "new": "Accidental Rename"}

    # Audit page displays diff and Revert button
    audit_page = client.get("/admin/_audit")
    assert audit_page.status_code == 200
    html = audit_page.get_data(as_text=True)
    assert "Accidental Rename" in html
    assert "Revert" in html

    # Execute Safe Revert
    rev = client.post(
        f"/admin/_audit/{upd.id}/revert",
        data={"_csrf_token": csrf},
        follow_redirects=True,
    )
    assert rev.status_code == 200
    assert "Reverted 1 field(s)" in rev.get_data(as_text=True)

    with SessionLocal() as sess:
        restored = sess.get(Item, 1)
        assert restored is not None
        assert restored.title == "Primary Server"

    reverts, rev_count = audit_store.list_entries(action="revert")
    assert rev_count == 1
    assert reverts[0].changes["title"] == {"old": "Accidental Rename", "new": "Primary Server"}
