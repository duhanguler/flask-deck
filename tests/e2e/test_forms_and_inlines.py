"""E2E browser tests for forms, FK lookup/slide-over drawers, inline editors, and Audit revert."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import PageGuardState, assert_dom_csp_hygiene, login_as

pytestmark = pytest.mark.e2e


def test_order_edit_fk_lookup_slide_over_inlines_audit_diff_and_revert(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")
    page.goto(f"{demo_server_url}/admin/orders/", wait_until="domcontentloaded")

    # Open the first order's Edit page
    first_edit = page.locator("a[aria-label^='Edit ']").first
    first_edit.click()
    expect(page).to_have_url(re.compile(r"/admin/orders/\d+/edit"))
    assert_dom_csp_hygiene(page)

    # 1. FK Lookup drawer opens, searches, and selects a related organization (cascades dependent Customer)
    page.get_by_role("button", name="Lookup Organization").click()
    drawer = page.get_by_role("dialog", name="Record Inspector")
    expect(drawer).to_be_visible()
    expect(drawer.locator("[data-deck-lookup-root]")).to_be_visible()
    drawer.locator("button[data-deck-lookup-pick]").first.click()
    expect(drawer).to_be_hidden()

    # Dependent Customer FK is cleared on org change; pick a valid customer via Lookup drawer
    page.get_by_role("button", name="Lookup Customer").click()
    expect(drawer).to_be_visible()
    expect(drawer.locator("[data-deck-lookup-root]")).to_be_visible()
    drawer.locator("button[data-deck-lookup-pick]").first.click()
    expect(drawer).to_be_hidden()

    # 2. FK Quick Peek slide-over opens related record cleanly
    page.get_by_role("button", name="Quick peek Organization").click()
    expect(drawer).to_be_visible()
    expect(drawer.locator("[data-deck-drawer-root]")).to_be_visible()
    assert_dom_csp_hygiene(page)
    drawer.get_by_role("button", name="Close drawer").click()
    expect(drawer).to_be_hidden()

    # 3. Collapsible inline Line Items: add a row and remove it cleanly
    inline_details = page.locator("details.dk-fieldset-details", has_text="Line Items")
    expect(inline_details).to_be_visible()
    initial_rows = inline_details.locator("[data-inline-row]").count()
    inline_details.get_by_role("button", name="Add Row").click()
    expect(inline_details.locator("[data-inline-row]")).to_have_count(initial_rows + 1)
    inline_details.locator("[data-inline-row]").last.locator("[data-deck-del-inline]").click()
    expect(inline_details.locator("[data-inline-row]")).to_have_count(initial_rows)

    # 4. Switch to Billing & Markdown Notes tab, update total_cents, and save
    page.locator("button[data-deck-form-tab]", has_text="Billing & Markdown Notes").click()
    total_input = page.locator("#fld_total_cents")
    expect(total_input).to_be_visible()
    original_total = total_input.input_value()
    new_total = str(int(original_total or "10000") + 777)
    total_input.fill(new_total)

    page.locator("button[data-save-btn='save']").last.click()
    expect(page).to_have_url(re.compile(r"/admin/orders/\d+$"))
    expect(page.locator("[role='status']")).to_contain_text("Saved changes")

    # 5. Audit Ledger records exact field-level diff and supports Safe Revert
    page.goto(f"{demo_server_url}/admin/_audit?model=orders&action=update", wait_until="domcontentloaded")
    first_diff_row = page.locator("tbody tr").first
    expect(first_diff_row).to_contain_text("total_cents")
    expect(first_diff_row).to_contain_text(new_total)

    first_diff_row.get_by_role("button", name="Revert").click()
    confirm_dialog = page.get_by_role("dialog", name="Confirm action")
    expect(confirm_dialog).to_be_visible()
    confirm_dialog.locator("#dk-confirm-go").click()
    expect(page.locator("[role='status']")).to_be_visible()
    assert_dom_csp_hygiene(page)
