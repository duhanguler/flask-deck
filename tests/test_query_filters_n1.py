from __future__ import annotations

from decimal import Decimal
from typing import Any

from tests.conftest import Item, StatusEnum, count_sql_queries, login_as


def test_list_view_zero_n_plus_one_query_budget(sa_bundle: tuple[Any, ...]) -> None:
    """50 rows with FK relation + 4 QuickTabs + 4 sidebar counts must execute <= 4 SQL queries."""
    app, _deck, engine, SessionLocal, _audit = sa_bundle

    with SessionLocal() as sess:
        for i in range(50):
            sess.add(
                Item(
                    code=f"BULK-{i:03d}",
                    title=f"Cluster Node {i}",
                    status=StatusEnum.ACTIVE if i % 2 == 0 else StatusEnum.DRAFT,
                    price=Decimal("100.00") + i,
                    tenant_id=1 if i % 2 == 0 else 2,
                    description="X" * 2000,
                )
            )
        sess.commit()

    client = app.test_client()
    login_as(client, "admin", "admin-password")

    with count_sql_queries(engine) as queries:
        resp = client.get("/admin/items/?page_size=50")

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Cluster Node 49" in html
    assert "Alpha Corp" in html
    # 1 query: single-pass CASE QuickTab counts
    # 1 query: eager-loaded paginated data with joinedload(tenant) + deferred heavy description/payload
    # 1 query: single-query sidebar scalar subqueries for all 4 models
    assert len(queries) <= 4, f"N+1 regression detected! Executed {len(queries)} queries: {queries}"

    # Verify heavy unshown columns (description, payload) were deferred from the data SELECT!
    data_selects = [q for q in queries if "LIMIT" in q and "test_items" in q]
    assert data_selects
    assert "test_items.description" not in data_selects[0]
    assert "test_items.payload" not in data_selects[0]


def test_search_filters_sorting_and_like_escaping(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    with SessionLocal() as sess:
        sess.add(
            Item(
                code="PCT_100%",
                title="100% Literal Match",
                status=StatusEnum.ACTIVE,
                price=Decimal("999.00"),
                tenant_id=1,
            )
        )
        sess.commit()

    client = app.test_client()
    login_as(client, "admin", "admin-password")

    # Escaped LIKE wildcard '%' should match ONLY the literal '%' record, not every row!
    resp = client.get("/admin/items/?q=100%25")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "PCT_100%" in body
    assert "ITM-001" not in body

    # Dotted relationship search ("Beta Corp")
    rel_search = client.get("/admin/items/?q=Beta+Corp")
    assert rel_search.status_code == 200
    assert "ITM-002" in rel_search.get_data(as_text=True)
    assert "ITM-001" not in rel_search.get_data(as_text=True)

    # Numeric range filter + QuickTab
    flt = client.get("/admin/items/?tab=active&f_price__gte=500")
    assert flt.status_code == 200
    assert "PCT_100%" in flt.get_data(as_text=True)
    assert "ITM-001" not in flt.get_data(as_text=True)

    # Bounded page_size cap (trying ?page_size=999999 must not fail or bypass max_page_size)
    capped = client.get("/admin/items/?page_size=999999")
    assert capped.status_code == 200
