from __future__ import annotations

import io
import re
from decimal import Decimal
from typing import Any

from flask_deck.formatters import LinkFormatter
from tests.conftest import Item, ItemNote, extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\bstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\bon(?:click|change|submit|load|error|mouseover|focus)\s*=", re.IGNORECASE)
_TOKEN_RE = re.compile(r'name="preview_token"\s+value="([^"]+)"')


def test_strict_csp_headers_and_zero_inline_styles_or_handlers(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    login_as(client, "admin", "admin-password")

    pages = [
        "/admin/",
        "/admin/items/",
        "/admin/items/new",
        "/admin/items/1",
        "/admin/items/1/edit",
        "/admin/items/import",
        "/admin/_audit",
        "/admin/_rbac",
    ]
    seen_nonces: set[str] = set()
    for url in pages:
        resp = client.get(url)
        assert resp.status_code == 200, f"Unexpected status on {url}"
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp
        assert "style-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "frame-ancestors 'none'" in csp
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert "no-store" in resp.headers.get("Cache-Control", "")

        m = re.search(r"'nonce-([^']+)'", csp)
        assert m is not None
        seen_nonces.add(m.group(1))

        html = resp.get_data(as_text=True)
        assert not _INLINE_STYLE_RE.search(html), f"Inline style= found on {url}"
        assert not _INLINE_HANDLER_RE.search(html), f"Inline event handler found on {url}"

    # Every request gets a distinct cryptographic nonce
    assert len(seen_nonces) == len(pages)


def test_csrf_and_cross_origin_rejection_across_mutations(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # Missing CSRF token rejected
    assert client.post("/admin/items/1/delete").status_code == 403
    assert client.patch("/admin/_api/items/1/quick-edit", json={"field": "is_active", "value": False}).status_code == 403
    assert client.post("/admin/logout").status_code == 403

    # Forged CSRF token rejected
    assert client.post("/admin/items/1/delete", data={"_csrf_token": "forged-token"}).status_code == 403

    # Cross-site Sec-Fetch-Site rejected even WITH valid CSRF token!
    evil_fetch = client.patch(
        "/admin/_api/items/1/quick-edit",
        json={"field": "is_active", "value": False},
        headers={"X-Deck-CSRFToken": csrf, "Sec-Fetch-Site": "cross-site"},
    )
    assert evil_fetch.status_code == 403

    # Evil Origin header rejected even WITH valid CSRF token!
    evil_origin = client.post(
        "/admin/items/1/delete",
        data={"_csrf_token": csrf},
        headers={"Origin": "https://evil.example"},
    )
    assert evil_origin.status_code == 403

    # Origin: null without Sec-Fetch-Site: same-origin (e.g. sandboxed iframe CSRF) is rejected!
    null_origin_evil = client.post(
        "/admin/items/1/delete",
        data={"_csrf_token": csrf},
        headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"},
    )
    assert null_origin_evil.status_code == 403

    # Origin: null WITH browser-verified Sec-Fetch-Site: same-origin is permitted
    null_origin_ok = client.patch(
        "/admin/_api/items/1/quick-edit",
        json={"field": "is_active", "value": True},
        headers={"X-Deck-CSRFToken": csrf, "Origin": "null", "Sec-Fetch-Site": "same-origin"},
    )
    assert null_origin_ok.status_code == 200


def test_mass_assignment_cannot_overwrite_readonly_hidden_or_sensitive_fields(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "alpha_editor", "alpha-password")

    # Attempt to tamper with price (readonly), quantity (hidden), password_hash (sensitive), and id (PK)
    resp = client.post(
        "/admin/items/1/edit",
        data={
            "_csrf_token": csrf,
            "id": "999",
            "code": "ITM-001",
            "title": "Legitimate Title Update",
            "status": "active",
            "price": "0.01",
            "quantity": "9999",
            "password_hash": "hacked-hash",
            "api_token": "hacked-token",
            "tenant_id": "1",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with SessionLocal() as sess:
        item = sess.get(Item, 1)
        assert item is not None
        assert item.title == "Legitimate Title Update"
        assert item.price == Decimal("199.50")  # readonly untouched!
        assert item.quantity == 3  # hidden untouched!
        assert item.password_hash == "secret-hash-val"  # sensitive untouched!
        assert item.api_token == "tok_live_secret"  # sensitive untouched!


def test_cross_tenant_and_inline_child_idor_blocked(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "alpha_editor", "alpha-password")

    # Cross-tenant direct PK guessing must return 404 on EVERY surface
    assert client.get("/admin/items/2").status_code == 404
    assert client.get("/admin/items/2/edit").status_code == 404
    assert client.get("/admin/_api/items/2/drawer").status_code == 404
    assert (
        client.patch(
            "/admin/_api/items/2/quick-edit",
            json={"field": "is_active", "value": True},
            headers={"X-Deck-CSRFToken": csrf},
        ).status_code
        == 404
    )

    # Global ⌘K search must NOT leak tenant 2 records
    search = client.get("/admin/_api/search?q=Backup")
    assert search.status_code == 200
    assert not any("ITM-002" in r["title"] for r in search.get_json()["results"])

    # Inline child IDOR: submitting item 2's note PK (#2) inside item 1's edit form -> 403!
    idor = client.post(
        "/admin/items/1/edit",
        data={
            "_csrf_token": csrf,
            "code": "ITM-001",
            "title": "Primary Server",
            "status": "active",
            "tenant_id": "1",
            "inline__item-notes__0___pk": "2",
            "inline__item-notes__0__body": "HIJACKED BETA NOTE",
        },
    )
    assert idor.status_code == 403
    with SessionLocal() as sess:
        beta_note = sess.get(ItemNote, 2)
        assert beta_note is not None
        assert beta_note.body == "Beta confidential note"


def test_xss_escaping_and_javascript_url_blocking(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # LinkFormatter blocks javascript: and data: XSS URLs
    lf = LinkFormatter()
    bad_js = str(lf.format("javascript:alert(1)"))
    assert "href=" not in bad_js
    bad_data = str(lf.format("data:text/html,<script>alert(1)</script>"))
    assert "href=" not in bad_data
    good_url = str(lf.format("https://example.com/docs"))
    assert 'href="https://example.com/docs"' in good_url

    # Submitting javascript: into URL column is rejected by form validation
    bad_form = client.post(
        "/admin/items/new",
        data={
            "_csrf_token": csrf,
            "code": "ITM-XSS",
            "title": '<script>alert("xss")</script>',
            "website_url": "javascript:alert(1)",
            "tenant_id": "1",
        },
    )
    assert bad_form.status_code == 200
    assert "URL must start with http://, https://, or /." in bad_form.get_data(as_text=True)

    # Storing HTML script tag in text field is strictly auto-escaped in list & detail
    ok_form = client.post(
        "/admin/items/new",
        data={
            "_csrf_token": csrf,
            "code": "ITM-ESC",
            "title": '<script>alert("owned")</script>',
            "website_url": "https://safe.example",
            "tenant_id": "1",
        },
        follow_redirects=True,
    )
    assert ok_form.status_code == 200
    html = ok_form.get_data(as_text=True)
    assert '<script>alert("owned")</script>' not in html
    assert "&lt;script&gt;" in html


def test_sqli_sort_injection_and_open_redirect_blocked(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()

    # Open redirect attempts on login must fall back to /admin/
    for evil_next in ("https://evil.com", "//evil.com/phish", "/\\evil.com"):
        login_page = client.get(f"/admin/login?next={evil_next}")
        csrf = extract_csrf(login_page.get_data(as_text=True))
        res = client.post(
            "/admin/login",
            data={
                "_csrf_token": csrf,
                "username": "admin",
                "password": "admin-password",
                "next": evil_next,
            },
            follow_redirects=False,
        )
        assert res.status_code == 302
        assert res.headers["Location"].endswith("/admin/")
        client.post("/admin/logout", data={"_csrf_token": extract_csrf(client.get("/admin/").get_data(as_text=True))})

    login_as(client, "admin", "admin-password")
    # SQLi attempt via sort & filter parameters falls back safely to default sort with 200 OK
    sqli = client.get("/admin/items/?sort=id;DROP+TABLE+test_items--&f_status=active'+OR+'1'='1")
    assert sqli.status_code == 200


def test_import_preview_token_single_use_and_cross_user_theft_blocked(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client_admin = app.test_client()
    client_alpha = app.test_client()
    csrf_admin = login_as(client_admin, "admin", "admin-password")
    csrf_alpha = login_as(client_alpha, "alpha_editor", "alpha-password")

    csv_data = b"code,title,status,price,tenant_id\nITM-TOK-1,Token Node,active,10.00,1\n"
    prev = client_admin.post(
        "/admin/items/import",
        data={"_csrf_token": csrf_admin, "step": "preview", "file": (io.BytesIO(csv_data), "t.csv")},
        content_type="multipart/form-data",
    )
    m = _TOKEN_RE.search(prev.get_data(as_text=True))
    assert m is not None
    token = m.group(1)

    # Another authenticated user trying to hijack admin's preview token -> rejected!
    theft = client_alpha.post(
        "/admin/items/import",
        data={"_csrf_token": csrf_alpha, "step": "commit", "preview_token": token},
    )
    assert "expired, already used, or invalid" in theft.get_data(as_text=True)

    # Admin commits once -> succeeds
    ok = client_admin.post(
        "/admin/items/import",
        data={"_csrf_token": csrf_admin, "step": "commit", "preview_token": token},
        follow_redirects=True,
    )
    assert "Import committed: 1 created" in ok.get_data(as_text=True)

    # Replaying the same token a second time -> rejected!
    replay = client_admin.post(
        "/admin/items/import",
        data={"_csrf_token": csrf_admin, "step": "commit", "preview_token": token},
    )
    assert "expired, already used, or invalid" in replay.get_data(as_text=True)


def test_brute_force_login_rate_limiting_lockout(sa_bundle: tuple[Any, ...]) -> None:
    app, _deck, _engine, _SessionLocal, _audit = sa_bundle
    client = app.test_client()
    csrf = extract_csrf(client.get("/admin/login").get_data(as_text=True))

    for _ in range(5):
        r = client.post(
            "/admin/login",
            data={"_csrf_token": csrf, "username": "admin", "password": "wrong-password"},
        )
        assert r.status_code == 200

    # 6th attempt triggers HTTP 429 + Retry-After lockout
    locked = client.post(
        "/admin/login",
        data={"_csrf_token": csrf, "username": "admin", "password": "admin-password"},
    )
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) >= 1


def test_production_type_to_confirm_safeguard_enforced_server_side(sa_bundle: tuple[Any, ...]) -> None:
    app, deck, _engine, SessionLocal, _audit = sa_bundle
    # Temporarily switch config to production to test server-side Type-to-Confirm gate
    from dataclasses import replace

    deck.config = replace(deck.config, environment="production", require_confirm_text_in_prod=True)
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # Missing confirm_text -> blocked!
    blocked = client.post(
        "/admin/items/action/delete",
        data={"_csrf_token": csrf, "selected_pks": ["2"]},
        follow_redirects=True,
    )
    assert "Production safeguard" in blocked.get_data(as_text=True)
    with SessionLocal() as sess:
        assert sess.get(Item, 2) is not None

    # Exact phrase "DELETE 1" -> allowed!
    allowed = client.post(
        "/admin/items/action/delete",
        data={"_csrf_token": csrf, "selected_pks": ["2"], "confirm_text": "DELETE 1"},
        follow_redirects=True,
    )
    assert "Deleted 1 Items" in allowed.get_data(as_text=True)
    with SessionLocal() as sess:
        assert sess.get(Item, 2) is None
