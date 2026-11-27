"""Shared Playwright browser fixtures with automatic Air-Gap, Strict-CSP, and zero-error gates."""

from __future__ import annotations

import contextlib
import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from werkzeug.serving import make_server

from flask_deck.demo import create_demo_app

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import (
    Browser,
    ConsoleMessage,
    Page,
    Request,
    Response,
    expect,
    sync_playwright,
)

_CSP_VIOLATION_INIT_SCRIPT = """
(() => {
  window.__deckCspViolations = [];
  window.addEventListener("securitypolicyviolation", (ev) => {
    const entry = {
      directive: ev.violatedDirective || ev.effectiveDirective || "",
      blockedURI: ev.blockedURI || "",
      sourceFile: ev.sourceFile || "",
      lineNumber: ev.lineNumber || 0,
    };
    window.__deckCspViolations.push(entry);
    if (typeof window.__deckReportCspViolation === "function") {
      try {
        window.__deckReportCspViolation(entry);
      } catch (_err) {
        // Ignore teardown race when context is closing
      }
    }
  });
})();
"""

_INLINE_HANDLER_SELECTOR = (
    "[onclick],[onchange],[onsubmit],[onerror],[onload],"
    "[onfocus],[onblur],[oninput],[onmouseover],[onkeydown],[onkeyup]"
)


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Iterator[None]:
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


@pytest.fixture(scope="session")
def chromium_browser() -> Iterator[Browser]:
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True)
    try:
        yield browser
    finally:
        browser.close()
        pw.stop()


@pytest.fixture(scope="module")
def demo_server_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Run an isolated showcase demo server on an ephemeral loopback port per E2E module."""
    db_dir = tmp_path_factory.mktemp("deck_e2e_db")
    db_path = db_dir / "showcase.db"
    app = create_demo_app(
        db_uri=f"sqlite:///{db_path}",
        seed_profile="showcase",
        demo_safe_mode=False,
        auto_daily_reset=False,
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
        for deck in app.extensions.get("flask_deck", {}).values():
            deck.close()
            if deck.adapter is not None:
                deck.adapter.dispose()


class PageGuardState:
    """Collects security and runtime violations observed during a browser test."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.external_requests: list[str] = []
        self.header_violations: list[str] = []
        self.page_errors: list[str] = []
        self.console_errors: list[str] = []
        self.csp_violations: list[dict[str, Any]] = []
        self.html_responses_checked: int = 0

    def assert_clean(self) -> None:
        assert not self.external_requests, f"Air-gap violation (outbound requests): {self.external_requests}"
        assert not self.header_violations, f"Security header violations: {self.header_violations}"
        assert not self.page_errors, f"Uncaught page errors: {self.page_errors}"
        assert not self.console_errors, f"Console errors: {self.console_errors}"
        assert not self.csp_violations, f"Browser CSP violations: {self.csp_violations}"


@pytest.fixture
def guarded_page(
    chromium_browser: Browser,
    demo_server_url: str,
    request: pytest.FixtureRequest,
) -> Iterator[tuple[Page, PageGuardState]]:
    """Fresh isolated BrowserContext + Page enforcing Air-Gap, Strict-CSP, and zero JS errors."""
    context = chromium_browser.new_context(viewport={"width": 1440, "height": 900})
    guard = PageGuardState(demo_server_url)
    context.expose_function(
        "__deckReportCspViolation",
        lambda entry: guard.csp_violations.append(entry),
    )
    context.add_init_script(_CSP_VIOLATION_INIT_SCRIPT)
    context.tracing.start(screenshots=True, snapshots=True, sources=False)
    page = context.new_page()
    page.set_default_timeout(10_000)

    def _on_request(req: Request) -> None:
        url = req.url
        allowed = (
            url.startswith(demo_server_url)
            or url.startswith("data:")
            or url.startswith("blob:")
            or url.startswith("about:")
        )
        if not allowed:
            guard.external_requests.append(url)

    def _on_response(resp: Response) -> None:
        if not resp.url.startswith(demo_server_url):
            return
        ctype = (resp.headers.get("content-type") or "").lower()
        if "text/html" not in ctype or resp.status >= 400 or resp.status in {301, 302, 303, 307, 308}:
            return
        # Partial AJAX fragments returned for drawers/lookups still carry security headers on full docs;
        # check full documents (main frame navigations) for strict CSP + frame/nosniff headers.
        if resp.request.resource_type != "document":
            return
        guard.html_responses_checked += 1
        csp = resp.headers.get("content-security-policy", "")
        if "default-src 'none'" not in csp:
            guard.header_violations.append(f"{resp.url}: missing default-src 'none' in CSP ({csp!r})")
        if "'nonce-" not in csp:
            guard.header_violations.append(f"{resp.url}: missing script nonce in CSP ({csp!r})")
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            guard.header_violations.append(f"{resp.url}: forbidden unsafe-* in CSP ({csp!r})")
        if resp.headers.get("x-frame-options", "").upper() != "DENY":
            guard.header_violations.append(f"{resp.url}: X-Frame-Options != DENY")
        if resp.headers.get("x-content-type-options", "").lower() != "nosniff":
            guard.header_violations.append(f"{resp.url}: X-Content-Type-Options != nosniff")

    def _on_pageerror(err: Exception) -> None:
        guard.page_errors.append(str(err))

    def _on_console(msg: ConsoleMessage) -> None:
        if msg.type == "error":
            guard.console_errors.append(msg.text)

    page.on("request", _on_request)
    page.on("response", _on_response)
    page.on("pageerror", _on_pageerror)
    page.on("console", _on_console)

    try:
        yield page, guard
        try:
            violations = page.evaluate("() => window.__deckCspViolations || []")
            if isinstance(violations, list):
                for item in violations:
                    if item not in guard.csp_violations:
                        guard.csp_violations.append(item)
        except Exception:
            pass
    finally:
        failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)
        results_dir = Path("test-results")
        if failed:
            results_dir.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(Exception):
                page.screenshot(path=str(results_dir / f"{safe_name}.png"), full_page=True)
            context.tracing.stop(path=str(results_dir / f"{safe_name}.zip"))
        else:
            context.tracing.stop()
        context.close()

    if not failed:
        guard.assert_clean()


def login_as(page: Page, base_url: str, username: str, password: str) -> None:
    """Authenticate cleanly through the login form using accessible labels."""
    page.goto(f"{base_url}/admin/login", wait_until="domcontentloaded")
    page.get_by_label("Username / Email").fill(username)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page).to_have_url(re.compile(r"/admin/?$"))


def assert_dom_csp_hygiene(page: Page) -> None:
    """Verify the rendered DOM contains zero <style>, zero inline style=, and zero on*= handlers."""
    counts = page.evaluate(
        """(handlerSelector) => ({
            styleTags: document.querySelectorAll('style').length,
            inlineStyles: document.querySelectorAll('[style]').length,
            inlineHandlers: document.querySelectorAll(handlerSelector).length,
        })""",
        _INLINE_HANDLER_SELECTOR,
    )
    assert counts["styleTags"] == 0, f"Found forbidden <style> tags on {page.url}: {counts}"
    assert counts["inlineStyles"] == 0, f"Found forbidden inline style= attributes on {page.url}: {counts}"
    assert counts["inlineHandlers"] == 0, f"Found forbidden on*= handlers on {page.url}: {counts}"


def assert_no_horizontal_overflow(page: Page) -> None:
    """Verify zero unintended horizontal scrolling at the current viewport width."""
    overflow = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 1, f"Horizontal overflow of {overflow}px detected on {page.url}"
