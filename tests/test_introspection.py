from __future__ import annotations

import uuid

import pytest

from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk
from flask_deck.exceptions import InvalidPKError
from flask_deck.introspection import humanize, introspect_model, pluralize, slugify
from tests.conftest import CompositeMembership, Item, Tenant


def test_introspect_sqlalchemy2_types_and_sensitivity() -> None:
    meta = introspect_model(Item)
    assert meta.name == "Item"
    assert meta.slug == "items"
    assert meta.fields_by_name["status"].field_type == "enum"
    assert len(meta.fields_by_name["status"].choices) == 3
    assert meta.fields_by_name["price"].field_type == "decimal"
    assert meta.fields_by_name["is_active"].field_type == "boolean"
    assert meta.fields_by_name["external_uuid"].field_type == "uuid"
    assert meta.fields_by_name["due_date"].field_type == "date"
    assert meta.fields_by_name["created_at"].field_type == "datetime"
    assert meta.fields_by_name["payload"].field_type == "json"
    assert meta.fields_by_name["description"].field_type == "text"
    assert meta.fields_by_name["email"].field_type == "email"
    assert meta.fields_by_name["website_url"].field_type == "url"

    # Sensitive & heavy fields detected automatically
    assert "password_hash" in meta.sensitive_fields
    assert "api_token" in meta.sensitive_fields
    assert "description" in meta.heavy_fields
    assert "payload" in meta.heavy_fields

    # Index & FK resolution
    assert "code" in meta.indexed_fields
    assert "title" in meta.indexed_fields
    assert meta.fields_by_name["tenant_id"].fk_target_model is Tenant
    assert meta.fk_column_to_rel["tenant_id"].name == "tenant"


def test_single_and_composite_pk_roundtrip() -> None:
    item_meta = introspect_model(Item)
    encoded = encode_pk((42,))
    assert encoded == "42"
    assert decode_pk(encoded, item_meta) == (42,)

    with pytest.raises(InvalidPKError):
        decode_pk("not-an-int", item_meta)

    comp_meta = introspect_model(CompositeMembership)
    assert len(comp_meta.primary_keys) == 2
    comp_enc = encode_pk((7, "user-abc"))
    assert comp_enc.startswith("ck:")
    assert decode_pk(comp_enc, comp_meta) == (7, "user-abc")

    with pytest.raises(InvalidPKError):
        decode_pk("bad-composite", comp_meta)
    with pytest.raises(InvalidPKError):
        decode_pk("ck:invalid!!!", comp_meta)


def test_uuid_pk_encoding() -> None:
    uid = uuid.uuid4()
    assert encode_pk((uid,)) == str(uid)


def test_naming_helpers() -> None:
    assert humanize("order_item_id") == "Order Item"
    assert humanize("SupportTicket") == "Support Ticket"
    assert pluralize("Category") == "Categories"
    assert pluralize("Status") == "Statuses"
    assert slugify("OrderItem") == "order-items"
