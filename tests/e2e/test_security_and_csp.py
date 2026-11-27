"""E2E browser tests for authentication, Strict Nonce CSP, Air-Gap isolation, and RBAC."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import PageGuardState, assert_dom_csp_hygiene, login_as

pytestmark = pytest.mark.e2e


def test_login_strict_csp_air_gap_and_dom_hygiene_across_core_views(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, guard = guarded_page
    page.goto(f"{demo_server_url}/admin/login", wait_until="domcontentloaded")
    assert_dom_csp_hygiene(page)

    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")
    assert_dom_csp_hygiene(page)

    core_paths = (
        "/admin/",
        "/admin/organizations/",
        "/admin/orders/",
        "/admin/tickets/",
        "/admin/products/?view=gallery",
        "/admin/infrastructure/?view=tree",
        "/admin/_approvals",
        "/admin/_audit",
        "/admin/_sql",
        "/admin/_rbac",
        "/admin/_schema",
        "/admin/_security/users",
        "/admin/_diagnostics",
    )
    for path in core_paths:
        resp = page.goto(f"{demo_server_url}{path}", wait_until="domcontentloaded")
        assert resp is not None and resp.status == 200, f"Unexpected status on {path}: {resp}"
        assert_dom_csp_hygiene(page)

    assert guard.html_responses_checked >= len(core_paths)


def test_role_switcher_enforces_pii_masking_readonly_and_logout(
    guarded_page: tuple[Page, PageGuardState],
    demo_server_url: str,
) -> None:
    page, _guard = guarded_page
    login_as(page, demo_server_url, "admin@acme.dev", "deck-demo-2026")

    # Superadmin sees unmasked emails on /admin/users/
    page.goto(f"{demo_server_url}/admin/users/", wait_until="domcontentloaded")
    email_cells = page.locator("td[data-col='email']")
    expect(email_cells.first).to_be_visible()
    expect(email_cells.first).to_contain_text("@")
    expect(email_cells.first).not_to_contain_text("***")

    # Switch to Support Engineer role -> PII emails must be masked
    page.locator("button.dk-role-sw-btn", has_text="support").click()
    expect(page.locator(".dk-user-role")).to_contain_text("support")
    expect(page.locator("td[data-col='email']").first).to_contain_text("***")

    # Switch to Compliance Auditor role -> read-only, no create button on Orders
    page.locator("button.dk-role-sw-btn", has_text="auditor").click()
    expect(page.locator(".dk-user-role")).to_contain_text("auditor")
    page.goto(f"{demo_server_url}/admin/orders/", wait_until="domcontentloaded")
    expect(page.locator("#dk-new-record-btn")).to_have_count(0)

    # Switch back to Superadmin and sign out cleanly
    page.locator("button.dk-role-sw-btn", has_text="superadmin").click()
    expect(page.locator(".dk-user-role")).to_contain_text("superadmin")
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(re.compile(r"/admin/login"))
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    # Verify session was revoked (protected page redirects back to login)
    page.goto(f"{demo_server_url}/admin/", wait_until="domcontentloaded")
    expect(page).to_have_url(re.compile(r"/admin/login"))
