"""E2E browser tests for Four-Eyes Approvals, SQL Console SVG charts, IAM, Theme, RTL i18n, and Mobile."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import (
    PageGuardState,
    assert_dom_csp_hygiene,
    assert_no_horizontal_overflow,
    login_as,
)

pytestmark = pytest.mark.e2e


def test_approvals_queue_sql_console_svg_chart_iam_and_schema(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")

    # 1. Four-Eyes Approvals: review and approve an AI agent proposal
    page.goto(f"{demo_server_url}/admin/_approvals", wait_until="domcontentloaded")
    ai_card = page.locator("section.dk-panel", has_text="Claude Ops MCP Agent").first
    expect(ai_card).to_be_visible()
    ai_card.locator("input[name='review_note']").first.fill("Approved via Playwright E2E")
    ai_card.get_by_role("button", name="Approve & Execute").click()
    expect(page.locator("[role='status']")).to_be_visible()

    page.goto(f"{demo_server_url}/admin/_approvals?status=approved", wait_until="domcontentloaded")
    expect(page.locator("main")).to_contain_text("Approved via Playwright E2E")
    assert_dom_csp_hygiene(page)

    # 2. Read-Only SQL Console: open saved BI query and verify pure-SVG visualization + table
    page.goto(f"{demo_server_url}/admin/_sql", wait_until="domcontentloaded")
    page.get_by_role("link", name="Active MRR by Plan Tier (USD)").click()
    expect(page).to_have_url(re.compile(r"[?&]saved=sq-bi-plan-mrr"))
    expect(page.locator("#dk-sql-editor")).to_contain_text("demo_organizations")
    page.get_by_role("button", name="Run Query").click()
    expect(page.locator("section.dk-panel", has_text="Query Visualization").locator("svg")).to_be_visible()
    expect(page.locator("table.dk-table tbody tr").first).to_be_visible()
    assert_dom_csp_hygiene(page)

    # 3. IAM Users & Schema ERD render cleanly under strict CSP
    page.goto(f"{demo_server_url}/admin/_security/users", wait_until="domcontentloaded")
    expect(page.locator("main")).to_contain_text("admin@acme.dev")
    assert_dom_csp_hygiene(page)

    page.goto(f"{demo_server_url}/admin/_schema", wait_until="domcontentloaded")
    expect(page.locator("main")).to_contain_text("demo_orders")
    assert_dom_csp_hygiene(page)


def test_theme_persistence_arabic_rtl_timezone_and_mobile_viewport(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")

    # 1. Dark <-> Swiss Light theme toggle persists across reload via localStorage
    html_el = page.locator("html")
    initial_theme = html_el.get_attribute("data-theme") or "dark"
    expected_theme = "light" if initial_theme == "dark" else "dark"

    page.get_by_role("button", name="Toggle theme").click()
    expect(html_el).to_have_attribute("data-theme", expected_theme)
    page.reload(wait_until="domcontentloaded")
    expect(html_el).to_have_attribute("data-theme", expected_theme)

    # 2. Arabic RTL locale + Europe/Istanbul timezone preference persistence
    page.get_by_role("button", name="Locale and timezone preferences").click()
    prefs_pop = page.locator("#dk-prefs-pop")
    expect(prefs_pop).to_be_visible()
    prefs_pop.locator("#dk-pref-locale").select_option("ar")
    prefs_pop.locator("#dk-pref-tz").select_option("Europe/Istanbul")
    prefs_pop.locator("button[type='submit']").click()

    expect(html_el).to_have_attribute("lang", "ar")
    expect(html_el).to_have_attribute("dir", "rtl")
    expect(page.locator("footer.dk-statusbar")).to_contain_text("Europe/Istanbul")
    assert_dom_csp_hygiene(page)

    # Switch back to English LTR for mobile layout checks
    page.get_by_role("button", name="Locale and timezone preferences").click()
    prefs_pop.locator("#dk-pref-locale").select_option("en")
    prefs_pop.locator("button[type='submit']").click()
    expect(html_el).to_have_attribute("lang", "en")
    expect(html_el).to_have_attribute("dir", "ltr")

    # 3. Mobile 390x844 viewport: zero horizontal overflow + sidebar toggle works cleanly
    page.set_viewport_size({"width": 390, "height": 844})
    for path in ("/admin/", "/admin/orders/"):
        page.goto(f"{demo_server_url}{path}", wait_until="domcontentloaded")
        assert_no_horizontal_overflow(page)
        assert_dom_csp_hygiene(page)

    shell = page.locator("#dk-shell")
    page.get_by_role("button", name="Toggle sidebar").click()
    expect(shell).to_have_class(re.compile(r"dk-mobile-open"))
    assert_no_horizontal_overflow(page)
