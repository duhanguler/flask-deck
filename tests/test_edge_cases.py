from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from flask_deck import (
    AvatarFormatter,
    BadgeFormatter,
    BooleanIconFormatter,
    CodeFormatter,
    CurrencyFormatter,
    DeckConfig,
    ProgressBarFormatter,
    RelativeTimeFormatter,
)
from flask_deck.security import mask_value, sanitize_csv_cell
from tests.conftest import login_as


def test_config_validation_bounds() -> None:
    with pytest.raises(ValueError):
        DeckConfig(page_size=0)
    with pytest.raises(ValueError):
        DeckConfig(max_page_size=5000)
    with pytest.raises(ValueError):
        DeckConfig(max_upload_bytes=100)
    with pytest.raises(ValueError):
        DeckConfig(max_import_rows=0)
    with pytest.raises(ValueError):
        DeckConfig(url_prefix="admin")


def test_formatters_and_masking_edge_cases() -> None:
    assert "—" in str(BadgeFormatter().format(None))
    assert "—" in str(CurrencyFormatter().format(None))
    assert "$-12.50" in str(CurrencyFormatter().format(Decimal("-12.50"))) or "-$12.50" in str(
        CurrencyFormatter().format(Decimal("-12.50"))
    )
    assert "—" in str(RelativeTimeFormatter().format(None))
    now = datetime.now(timezone.utc)
    assert "s ago" in str(RelativeTimeFormatter().format(now - timedelta(seconds=10)))
    assert "m ago" in str(RelativeTimeFormatter().format(now - timedelta(minutes=5)))
    assert "h ago" in str(RelativeTimeFormatter().format(now - timedelta(hours=3)))
    assert "d ago" in str(RelativeTimeFormatter().format(now - timedelta(days=4)))
    assert "—" in str(BooleanIconFormatter().format(None))
    assert "—" in str(CodeFormatter().format(None))
    assert "…" in str(CodeFormatter(max_chars=6).format("abcdefghij"))
    assert "—" in str(AvatarFormatter().format(None))
    assert "AL" in str(AvatarFormatter().format("Ada Lindholm"))
    assert "—" in str(ProgressBarFormatter().format(None))
    assert "dk-prog-fill-danger" in str(
        ProgressBarFormatter(warn_below=50, danger_below=20).format(10)
    )
    assert "dk-prog-fill-warn" in str(
        ProgressBarFormatter(warn_below=50, danger_below=20).format(35)
    )

    assert mask_value(None) is None
    assert mask_value("") == ""
    assert mask_value("abc") == "••••"
    assert mask_value("1234567890") == "••••7890"
    assert mask_value("duhan@example.com") == "d***@example.com"
    assert sanitize_csv_cell("  +SUM(A1:A2)") == "'  +SUM(A1:A2)"
    assert sanitize_csv_cell(Decimal("-42.50")) == "-42.50"


def test_date_presets_multi_enum_null_filters_and_pure_example(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    login_as(client, "admin", "admin-password")

    for qs in (
        "?f_created_at__preset=today",
        "?f_created_at__preset=7d",
        "?f_created_at__preset=30d",
        "?f_created_at__preset=month",
        "?f_status=active,draft",
        "?f_is_active=true",
        "?f_is_active=false",
        "?f_price__lte=250",
        "?f_status__null=false",
        "?sort=price&dir=asc",
    ):
        resp = client.get(f"/admin/items/{qs}")
        assert resp.status_code == 200, f"Filter query failed: {qs}"

    # Verify standalone pure SQLAlchemy example boots and serves login cleanly
    from examples.pure_sqlalchemy_app import create_app as create_pure_app

    pure = create_pure_app()
    pc = pure.test_client()
    assert pc.get("/admin/login").status_code == 200
