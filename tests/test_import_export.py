from __future__ import annotations

import io
import json
import re
from decimal import Decimal
from typing import Any

import sqlalchemy as sa

from tests.conftest import Item, StatusEnum, login_as

_TOKEN_RE = re.compile(r'name="preview_token"\s+value="([^"]+)"')


def test_streaming_export_formats_and_csv_formula_protection(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle

    with SessionLocal() as sess:
        sess.add(
            Item(
                code="ITM-INJ",
                title="=CMD|' /C calc'!A0",
                status=StatusEnum.ACTIVE,
                price=Decimal("10.00"),
                tenant_id=1,
            )
        )
        sess.commit()

    client = app.test_client()
    login_as(client, "admin", "admin-password")

    # CSV export neutralizes formula injection and NEVER leaks password_hash / api_token
    csv_resp = client.get("/admin/items/export.csv")
    assert csv_resp.status_code == 200
    csv_text = csv_resp.get_data(as_text=True)
    assert "password_hash" not in csv_text
    assert "api_token" not in csv_text
    assert "'=CMD|" in csv_text

    # JSON & JSONL export respecting search filter
    json_resp = client.get("/admin/items/export.json?q=ITM-001")
    assert json_resp.status_code == 200
    rows = json.loads(json_resp.get_data(as_text=True))
    assert len(rows) == 1
    assert rows[0]["code"] == "ITM-001"
    assert "password_hash" not in rows[0]

    jsonl_resp = client.get("/admin/items/export.jsonl?ids=1")
    assert jsonl_resp.status_code == 200
    lines = [json.loads(line) for line in jsonl_resp.get_data(as_text=True).strip().splitlines()]
    assert len(lines) == 1
    assert lines[0]["id"] == 1


def test_dry_run_savepoint_rollback_and_atomic_commit(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, audit_store = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    csv_payload = (
        b"code,title,status,price,tenant_id\n"
        b"ITM-001,Primary Server Upgraded,active,249.00,1\n"
        b"ITM-NEW-1,Fresh Worker,active,89.50,1\n"
        b"ITM-BAD-1,Broken Price,active,not_a_num,1\n"
    )

    # Step 1: Dry-Run Preview
    preview = client.post(
        "/admin/items/import",
        data={
            "_csrf_token": csrf,
            "step": "preview",
            "upsert_key": "code",
            "file": (io.BytesIO(csv_payload), "items.csv"),
        },
        content_type="multipart/form-data",
    )
    assert preview.status_code == 200
    html = preview.get_data(as_text=True)
    assert "~ UPDATE" in html
    assert "+ INSERT" in html
    assert "! ERROR" in html
    assert "Primary Server Upgraded" in html

    # Verify SAVEPOINT rolled back cleanly — ZERO changes in database!
    with SessionLocal() as sess:
        orig = sess.scalar(sa.select(Item).where(Item.code == "ITM-001"))
        assert orig is not None and orig.title == "Primary Server"
        assert sess.scalar(sa.select(Item).where(Item.code == "ITM-NEW-1")) is None

    m = _TOKEN_RE.search(html)
    assert m is not None
    token = m.group(1)

    # Step 2: Commit with skip_errors=1
    commit = client.post(
        "/admin/items/import",
        data={
            "_csrf_token": csrf,
            "step": "commit",
            "preview_token": token,
            "skip_errors": "1",
        },
        follow_redirects=True,
    )
    assert commit.status_code == 200
    assert "Import committed: 1 created, 1 updated." in commit.get_data(as_text=True)

    with SessionLocal() as sess:
        upgraded = sess.scalar(sa.select(Item).where(Item.code == "ITM-001"))
        created = sess.scalar(sa.select(Item).where(Item.code == "ITM-NEW-1"))
        assert upgraded is not None and upgraded.title == "Primary Server Upgraded"
        assert created is not None and created.price == Decimal("89.50")

    entries, _ = audit_store.list_entries(action="import")
    assert len(entries) == 1
    assert entries[0].metadata["created"] == 1
    assert entries[0].metadata["updated"] == 1


def test_json_import_and_size_limits(sa_bundle: tuple[Any, ...]) -> None:
    app, deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    json_payload = json.dumps(
        [{"code": "ITM-JSON-1", "title": "JSON Node", "status": "draft", "price": "15.00", "tenant_id": 1}]
    ).encode()

    resp = client.post(
        "/admin/items/import",
        data={
            "_csrf_token": csrf,
            "step": "preview",
            "file": (io.BytesIO(json_payload), "batch.json"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert "+ INSERT" in resp.get_data(as_text=True)

    # Oversized payload rejected cleanly before full parse
    huge = b"a" * (deck.config.max_upload_bytes + 128)
    over = client.post(
        "/admin/items/import",
        data={
            "_csrf_token": csrf,
            "step": "preview",
            "file": (io.BytesIO(huge), "huge.csv"),
        },
        content_type="multipart/form-data",
    )
    assert over.status_code == 200
    assert "exceeds maximum allowed size" in over.get_data(as_text=True)
