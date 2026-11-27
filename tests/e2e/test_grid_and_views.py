"""E2E browser tests for data grids, date hierarchy, lazy facets, Quick Peek, Kanban, Tree, and ⌘K."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import PageGuardState, assert_dom_csp_hygiene, login_as

pytestmark = pytest.mark.e2e


def test_orders_date_hierarchy_lazy_facets_and_quick_peek_notes(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")
    page.goto(f"{demo_server_url}/admin/orders/", wait_until="domcontentloaded")

    # 1. Date hierarchy drilldown updates URL and renders active chip
    dh_nav = page.get_by_role("navigation", name="Date hierarchy")
    expect(dh_nav).to_be_visible()
    first_year_chip = dh_nav.locator("a.dk-filter-chip").first
    first_year_chip.click()
    expect(page).to_have_url(re.compile(r"[?&]dh=\d{4}"))
    assert_dom_csp_hygiene(page)

    # Reset back to unfiltered Orders list
    page.get_by_role("link", name="Reset").click()
    expect(page).not_to_have_url(re.compile(r"[?&]dh="))

    # 2. Opening Filters triggers lazy facet counts hydration
    page.get_by_role("button", name=re.compile(r"^Filters")).click()
    filter_panel = page.locator("#dk-filter-panel")
    expect(filter_panel).to_be_visible()
    expect(filter_panel).to_have_attribute("data-facets-loaded", "1")
    expect(filter_panel.locator("select#f_status option[value='paid']")).to_contain_text("(")

    # 3. Quick Peek 4-tab drawer + persisted internal note
    first_peek = page.locator("button[aria-label^='Quick peek ']").first
    first_peek_label = first_peek.get_attribute("aria-label") or ""
    first_peek.click()

    drawer = page.get_by_role("dialog", name="Record Inspector")
    expect(drawer).to_be_visible()
    expect(drawer.locator("[data-deck-drawer-panel='fields']")).to_be_visible()

    drawer.locator("button[data-deck-drawer-tab='relations']").click()
    expect(drawer.locator("[data-deck-drawer-panel='relations']")).to_be_visible()

    drawer.locator("button[data-deck-drawer-tab='history']").click()
    expect(drawer.locator("[data-deck-drawer-panel='history']")).to_be_visible()

    drawer.locator("button[data-deck-drawer-tab='notes']").click()
    notes_panel = drawer.locator("[data-deck-drawer-panel='notes']")
    expect(notes_panel).to_be_visible()
    assert_dom_csp_hygiene(page)

    note_marker = "Playwright E2E verified billing reconciliation"
    notes_panel.locator("textarea[name='body']").fill(note_marker)
    notes_panel.get_by_role("button", name="Add Note").click()
    expect(page).to_have_url(re.compile(r"/admin/orders/\d+$"))
    expect(page.locator("[role='status']")).to_contain_text("Added record note")

    # Re-open the same record's Quick Peek drawer and verify note persisted in DB
    page.goto(f"{demo_server_url}/admin/orders/", wait_until="domcontentloaded")
    page.locator(f"button[aria-label='{first_peek_label}']").click()
    expect(drawer).to_be_visible()
    drawer.locator("button[data-deck-drawer-tab='notes']").click()
    expect(drawer.locator("[data-deck-drawer-panel='notes']")).to_contain_text(note_marker)


def test_kanban_board_transition_tree_view_and_cmdk_palette(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")

    # 1. Kanban drag-and-drop transitions ticket status and persists across reload
    page.goto(f"{demo_server_url}/admin/tickets/?view=board", wait_until="domcontentloaded")
    open_card = page.locator("[data-kanban-col='open'] [data-kanban-card]").first
    expect(open_card).to_be_visible()
    moved_pk = open_card.get_attribute("data-pk")
    assert moved_pk

    target_zone = page.locator("[data-kanban-dropzone='in_progress']")
    with page.expect_response(
        lambda r: f"/tickets/{moved_pk}/quick-edit" in r.url
        and r.request.method == "PATCH"
        and r.status == 200
    ):
        open_card.drag_to(
            target_zone,
            source_position={"x": 40, "y": 20},
            target_position={"x": 40, "y": 20},
        )

    page.reload(wait_until="domcontentloaded")
    expect(
        page.locator(f"[data-kanban-col='in_progress'] [data-kanban-card][data-pk='{moved_pk}']")
    ).to_be_visible()
    assert_dom_csp_hygiene(page)

    # 2. Fleet Topology hierarchical Tree view renders indented nodes cleanly
    page.goto(f"{demo_server_url}/admin/infrastructure/?view=tree", wait_until="domcontentloaded")
    expect(page.locator(".dk-tree-cell").first).to_be_visible()
    assert page.locator(".dk-tree-cell").count() >= 5
    assert_dom_csp_hygiene(page)

    # 3. ⌘K Command Palette searches live across models/records and navigates cleanly
    page.get_by_role("button", name="Open command palette").click()
    cmdk_dialog = page.get_by_role("dialog", name="Command Palette")
    expect(cmdk_dialog).to_be_visible()
    cmdk_input = cmdk_dialog.locator("#dk-cmdk-input")
    cmdk_input.fill("Northstar")
    northstar_item = cmdk_dialog.get_by_role("button", name=re.compile(r"Northstar Robotics")).first
    expect(northstar_item).to_be_visible()
    northstar_item.click()
    expect(page).to_have_url(re.compile(r"/admin/organizations/\d+"))
    assert_dom_csp_hygiene(page)
