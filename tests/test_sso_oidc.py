"""Behavioral & cryptographic verification tests for OAuth2 / OIDC PKCE SSO."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
from collections.abc import Mapping
from typing import Any

import pytest
from flask import Flask, session

from flask_deck.auth import DeckUser, RBACAuthProvider, Role
from flask_deck.sso import (
    SSO_USER_SESSION_KEY,
    OIDCAuthProvider,
    OIDCProviderConfig,
    _decode_jwt_parts,
    _default_http_transport,
    generate_pkce_pair,
)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _make_fake_jwt(header: Mapping[str, Any], claims: Mapping[str, Any], sig: bytes = b"sig") -> str:
    h = _b64u(json.dumps(header).encode("utf-8"))
    c = _b64u(json.dumps(claims).encode("utf-8"))
    s = _b64u(sig)
    return f"{h}.{c}.{s}"


def test_oidc_provider_presets_https_enforcement_and_jwt_decoder() -> None:
    g = OIDCProviderConfig.google(client_id="cid", client_secret="sec")
    assert g.require_verified_email is True
    assert OIDCProviderConfig.github(client_id="cid", client_secret="sec").name == "github"
    assert OIDCProviderConfig.okta(domain="https://acme.okta.com/", client_id="cid", client_secret="sec").issuer_url == "https://acme.okta.com/oauth2/default"
    assert OIDCProviderConfig.entra(tenant_id="t1", client_id="cid", client_secret="sec").name == "entra"
    assert OIDCProviderConfig.keycloak(base_url="https://idp.acme.dev/", realm="ops", client_id="cid", client_secret="sec").issuer_url == "https://idp.acme.dev/realms/ops"

    with pytest.raises(ValueError, match="https://"):
        OIDCProviderConfig(name="bad", label="Bad", client_id="c", client_secret="s", issuer_url="http://idp.local")
    with pytest.raises(ValueError, match="https://"):
        OIDCProviderConfig(name="bad2", label="Bad", client_id="c", client_secret="s")
    with pytest.raises(ValueError, match="https://"):
        _default_http_transport("GET", "http://insecure.local", {}, None, 1.0)

    # JWT decoder error handling
    with pytest.raises(PermissionError, match="Malformed"):
        _decode_jwt_parts("not-a-jwt")
    with pytest.raises(PermissionError, match="Invalid"):
        _decode_jwt_parts("!!!.!!!.!!!")
    with pytest.raises(PermissionError, match="JSON objects"):
        _decode_jwt_parts(f"{_b64u(b'[]')}.{_b64u(b'{}')}.{_b64u(b'x')}")

    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43 and "=" not in challenge


def test_oidc_discovery_pkce_callback_claims_and_error_resilience() -> None:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "oidc-test-secret-32-bytes-long!"

    calls: list[tuple[str, str]] = []
    scenario: dict[str, Any] = {
        "disc_status": 200,
        "disc_body": {
            "authorization_endpoint": "https://idp.acme.dev/auth",
            "token_endpoint": "https://idp.acme.dev/token",
            "userinfo_endpoint": "https://idp.acme.dev/userinfo",
            "jwks_uri": "https://idp.acme.dev/jwks",
        },
        "token_status": 200,
        "token_body": {},
        "userinfo_status": 200,
        "userinfo_body": {},
        "jwks_status": 200,
        "jwks_body": {"keys": []},
    }

    def fake_transport(
        method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> tuple[int, dict[str, Any]]:
        _ = (headers, body, timeout)
        calls.append((method, url))
        if url.endswith("/.well-known/openid-configuration"):
            return scenario["disc_status"], scenario["disc_body"]
        if url.endswith("/token"):
            return scenario["token_status"], scenario["token_body"]
        if url.endswith("/userinfo"):
            return scenario["userinfo_status"], scenario["userinfo_body"]
        if url.endswith("/jwks"):
            return scenario["jwks_status"], scenario["jwks_body"]
        return 404, {}

    cfg = OIDCProviderConfig(
        name="acme",
        label="Acme SSO",
        client_id="deck-client",
        client_secret="deck-secret",
        issuer_url="https://idp.acme.dev",
        role_claim="groups",
        role_mapping={"ops-team": "operator", "sec-team": "auditor"},
        superuser_groups=frozenset({"platform-root"}),
        allowed_domains=frozenset({"acme.dev"}),
        require_verified_email=True,
    )
    provider = OIDCAuthProvider(
        roles=[
            Role("viewer", permissions=frozenset({"*:view"})),
            Role("operator", permissions=frozenset({"*:view", "*:edit"})),
            Role("auditor", permissions=frozenset({"audit:view"})),
        ],
        providers=[cfg],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="local1", username="local", roles=("viewer",)),
                password="pass1234",
            )
        ],
        http_transport=fake_transport,
    )

    with app.test_request_context("/admin/login"):
        # Discovery + PKCE S256 redirect
        auth_url = provider.build_authorize_redirect(
            "acme", redirect_uri="https://app.acme.dev/cb", next_url="/admin/orders/"
        )
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query)
        assert qs["code_challenge_method"] == ["S256"]
        state = qs["state"][0]
        nonce = qs["nonce"][0]

        # Discovery cache prevents duplicate .well-known requests
        disc_calls_before = sum(1 for _, u in calls if "openid-configuration" in u)
        assert disc_calls_before == 1

        # Complete valid callback with signed-header id_token + string role_claim
        scenario["token_body"] = {
            "access_token": "tok-123",
            "id_token": _make_fake_jwt(
                {"alg": "RS256", "kid": "k1"},
                {
                    "iss": "https://idp.acme.dev",
                    "aud": ["deck-client"],
                    "exp": int(time.time()) + 300,
                    "nonce": nonce,
                    "sub": "u-99",
                },
            ),
        }
        scenario["userinfo_body"] = {
            "email": "ada@acme.dev",
            "email_verified": True,
            "name": "Ada Lovelace",
            "groups": "ops-team",
        }
        user, next_url = provider.complete_callback(
            "acme", code="auth-code", state=state, redirect_uri="https://app.acme.dev/cb"
        )
        assert next_url == "/admin/orders/"
        assert user.id == "sso:acme:u-99"
        assert user.roles == ("operator",)
        assert user.is_superuser is False

        # Login & session restore + corrupted SSO session payload fallback
        provider.login_user(user)
        restored = provider.get_current_user()
        assert restored is not None and restored.id == user.id
        session[SSO_USER_SESSION_KEY] = {"id": "sso:wrong"}
        assert provider.get_current_user() is None

        # Local password user restore
        local_user = provider.authenticate("local", "pass1234")
        assert local_user is not None
        provider.login_user(local_user)
        assert provider.get_current_user() == local_user

        # Security boundary checks: bad state, missing code, alg=none, expired/bad exp, aud/iss/nonce mismatch, domain, unverified email
        def _start() -> tuple[str, str]:
            u = provider.build_authorize_redirect("acme", redirect_uri="https://app.acme.dev/cb")
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)
            return q["state"][0], q["nonce"][0]

        st, _ = _start()
        with pytest.raises(PermissionError, match="state"):
            provider.complete_callback("acme", code="c", state="wrong", redirect_uri="https://app.acme.dev/cb")

        st, _ = _start()
        with pytest.raises(PermissionError, match="Missing SSO authorization code"):
            provider.complete_callback("acme", code="", state=st, redirect_uri="https://app.acme.dev/cb")

        st, nc = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "none"}, {"nonce": nc})}
        with pytest.raises(PermissionError, match="alg=none"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, _ = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "RS256"}, {"nonce": "wrong"})}
        with pytest.raises(PermissionError, match="nonce"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, nc = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "RS256"}, {"nonce": nc, "exp": "bad"})}
        with pytest.raises(PermissionError, match="invalid exp"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, nc = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "RS256"}, {"nonce": nc, "exp": int(time.time()) - 600})}
        with pytest.raises(PermissionError, match="expired"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, nc = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "RS256"}, {"nonce": nc, "aud": "other"})}
        with pytest.raises(PermissionError, match="audience"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, nc = _start()
        scenario["token_body"] = {"access_token": "t", "id_token": _make_fake_jwt({"alg": "RS256"}, {"nonce": nc, "iss": "https://evil.example"})}
        with pytest.raises(PermissionError, match="issuer"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        # Userinfo failure, missing sub, unverified email, disallowed domain, superuser group
        st, _ = _start()
        scenario["token_body"] = {"access_token": "t"}
        scenario["userinfo_status"] = 401
        with pytest.raises(PermissionError, match="userinfo"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        scenario["userinfo_status"] = 200
        st, _ = _start()
        scenario["userinfo_body"] = {"email_verified": False}
        with pytest.raises(PermissionError, match="user identifier"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, _ = _start()
        scenario["userinfo_body"] = {"sub": "1", "email": "a@acme.dev", "email_verified": False}
        with pytest.raises(PermissionError, match="not verified"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        st, _ = _start()
        scenario["userinfo_body"] = {"sub": "1", "email": "intruder@evil.org", "email_verified": True}
        with pytest.raises(PermissionError, match="not permitted"):
            provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")

        # Superuser group + invalid groups type fallback
        st, _ = _start()
        scenario["userinfo_body"] = {"sub": "2", "email": "root@acme.dev", "email_verified": True, "groups": ["platform-root"]}
        su_user, _ = provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")
        assert su_user.is_superuser is True and su_user.roles == ("viewer",)

        st, _ = _start()
        scenario["userinfo_body"] = {"sub": "3", "email": "u@acme.dev", "email_verified": True, "groups": 12345}
        plain_user, _ = provider.complete_callback("acme", code="c", state=st, redirect_uri="https://app.acme.dev/cb")
        assert plain_user.roles == ("viewer",)

        # Discovery error + non-https discovered endpoint + require_id_token_signature missing token/JWKS
        bad_cfg = OIDCProviderConfig(
            name="strict",
            label="Strict",
            client_id="c",
            client_secret="s",
            issuer_url="https://strict.idp.dev",
            require_id_token_signature=True,
        )
        p_strict = OIDCAuthProvider(roles=[Role("viewer")], providers=[bad_cfg], http_transport=fake_transport)
        scenario["disc_status"] = 500
        with pytest.raises(PermissionError, match="discovery failed"):
            p_strict.build_authorize_redirect("strict", redirect_uri="https://app/cb")

        scenario["disc_status"] = 200
        scenario["disc_body"] = {"authorization_endpoint": "http://not-https/auth"}
        with pytest.raises(PermissionError, match="must use https://"):
            p_strict.build_authorize_redirect("strict", redirect_uri="https://app/cb")

        scenario["disc_body"] = {"authorization_endpoint": "https://strict.idp.dev/auth"}
        p_strict._discovery_cache.clear()
        with pytest.raises(PermissionError, match="could not be resolved"):
            p_strict.build_authorize_redirect("strict", redirect_uri="https://app/cb")

        # require_id_token_signature missing id_token & JWKS failure
        sig_cfg = OIDCProviderConfig(
            name="sig",
            label="Sig",
            client_id="c",
            client_secret="s",
            authorize_url="https://sig.dev/auth",
            token_url="https://sig.dev/token",
            userinfo_url="https://sig.dev/userinfo",
            jwks_uri="https://sig.dev/jwks",
            require_id_token_signature=True,
        )
        p_sig = OIDCAuthProvider(roles=[Role("viewer")], providers=[sig_cfg], http_transport=fake_transport)
        u_sig = p_sig.build_authorize_redirect("sig", redirect_uri="https://app/cb")
        st_sig = urllib.parse.parse_qs(urllib.parse.urlsplit(u_sig).query)["state"][0]
        scenario["token_body"] = {"access_token": "t"}
        with pytest.raises(PermissionError, match="required id_token"):
            p_sig.complete_callback("sig", code="c", state=st_sig, redirect_uri="https://app/cb")

        scenario["jwks_status"] = 500
        with pytest.raises(PermissionError, match="JWKS"):
            p_sig._fetch_jwks(sig_cfg, "https://sig.dev/jwks")
        scenario["jwks_status"] = 200
        scenario["jwks_body"] = {"keys": [{"kty": "RSA", "kid": "1"}]}
        assert len(p_sig._fetch_jwks(sig_cfg, "https://sig.dev/jwks")) == 1
        assert len(p_sig._fetch_jwks(sig_cfg, "https://sig.dev/jwks")) == 1  # cached

    # Default HTTP transport error handling (mocked opener)
    class _FakeHTTPErrOpener:
        def open(self, req: Any, timeout: float) -> Any:
            raise urllib.error.HTTPError(req.full_url, 400, "Bad", {}, None)  # type: ignore[arg-type]

    class _FakeURLErrOpener:
        def open(self, req: Any, timeout: float) -> Any:
            raise urllib.error.URLError("down")

    import flask_deck.sso as sso_mod

    orig_opener = sso_mod.urllib.request.build_opener
    try:
        sso_mod.urllib.request.build_opener = lambda *a, **kw: _FakeHTTPErrOpener()  # type: ignore[assignment]
        st_code, err_payload = _default_http_transport("GET", "https://idp.dev/x", {}, None, 1.0)
        assert st_code == 400 and "error" in err_payload

        sso_mod.urllib.request.build_opener = lambda *a, **kw: _FakeURLErrOpener()  # type: ignore[assignment]
        with pytest.raises(PermissionError, match="communication failed"):
            _default_http_transport("GET", "https://idp.dev/x", {}, None, 1.0)
    finally:
        sso_mod.urllib.request.build_opener = orig_opener
