from __future__ import annotations

from typing import Any

from flask_deck.charts import (
    render_area_chart,
    render_bar_chart,
    render_donut_chart,
    render_sparkline,
)
from tests.conftest import login_as


def test_default_dashboard_and_cmdk_search(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    login_as(client, "admin", "admin-password")

    resp = client.get("/admin/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Operations Overview" in html
    assert "Schema Distribution" in html
    assert "<svg" in html
    assert "style=" not in html

    # ⌘K Live Search API
    s1 = client.get("/admin/_api/search?q=Primary")
    assert s1.status_code == 200
    results = s1.get_json()["results"]
    assert any(r["kind"] == "record" and "Primary Server" in r["title"] for r in results)

    # Navigation matching on short/empty query
    s2 = client.get("/admin/_api/search?q=")
    assert s2.status_code == 200
    assert any(r["kind"] == "model" and r["title"] == "Items" for r in s2.get_json()["results"])


def test_pure_svg_charts_escape_xss_and_zero_inline_styles() -> None:
    xss = '<script>alert("xss")</script>'
    area = str(
        render_area_chart(
            [xss, "Day 2", "Day 3"],
            [{"name": xss, "data": [10, 25, 18], "tone": "primary"}],
        )
    )
    bar = str(render_bar_chart([xss, "B"], [{"name": "Sales", "data": [5, 12], "tone": "ok"}]))
    donut = str(
        render_donut_chart([xss, "Other"], [{"data": [70, 30]}], center_label=xss)
    )
    spark = str(render_sparkline([1, 4, 2, 8], tone="ok"))

    for svg in (area, bar, donut, spark):
        assert "<svg" in svg
        assert "<script>" not in svg
        assert "style=" not in svg
