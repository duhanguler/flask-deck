from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from flask import session

from flask_deck.auth import DeckUser, RBACAccount, RBACAuthProvider, Role
from flask_deck.events import _NoRedirectHandler

SSO_STATE_KEY = "_deck_sso_state"
SSO_VERIFIER_KEY = "_deck_sso_verifier"
SSO_NONCE_KEY = "_deck_sso_nonce"
SSO_NEXT_KEY = "_deck_sso_next"
SSO_USER_SESSION_KEY = "_deck_sso_user"

HTTPTransport = Callable[
    [str, str, Mapping[str, str], bytes | None, float],
    tuple[int, dict[str, Any]],
]


def _default_http_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, dict[str, Any]]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("OIDC endpoints must use https://")
    req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(256 * 1024).decode("utf-8")
            parsed_json = json.loads(raw)
            if not isinstance(parsed_json, dict):
                raise PermissionError("OIDC provider returned non-object JSON payload.")
            return int(resp.status), parsed_json
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read(16 * 1024).decode("utf-8", errors="ignore")
            err_json = json.loads(err_body)
            payload = err_json if isinstance(err_json, dict) else {"error": err_body}
        except Exception:
            payload = {"error": str(exc)}
        return int(exc.code), payload
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PermissionError(f"OIDC provider communication failed: {exc}") from exc


def generate_pkce_pair() -> tuple[str, str]:
    """Generate RFC 7636 PKCE (code_verifier, S256 code_challenge)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


@dataclass(frozen=True, slots=True)
class OIDCProviderConfig:
    """Declarative OAuth2 / OIDC identity provider configuration (Google, GitHub, Okta, Keycloak)."""

    name: str
    label: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    role_claim: str = "groups"
    role_mapping: Mapping[str, str] = field(default_factory=dict)
    default_role: str = "viewer"
    superuser_groups: frozenset[str] = field(default_factory=frozenset)
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    require_verified_email: bool = False
    timeout: float = 8.0

    def __post_init__(self) -> None:
        for attr in ("authorize_url", "token_url", "userinfo_url"):
            val = getattr(self, attr)
            if urllib.parse.urlsplit(val).scheme.lower() != "https":
                raise ValueError(f"OIDCProviderConfig.{attr} must use https://")


class OIDCAuthProvider(RBACAuthProvider):
    """RBAC auth provider adding OAuth2 / OIDC PKCE S256 SSO login alongside optional passwords."""

    def __init__(
        self,
        *,
        roles: Sequence[Role],
        providers: Sequence[OIDCProviderConfig],
        accounts: Sequence[RBACAccount] = (),
        http_transport: HTTPTransport | None = None,
    ) -> None:
        super().__init__(roles=roles, accounts=accounts)
        self._providers: dict[str, OIDCProviderConfig] = {p.name: p for p in providers}
        self._transport: HTTPTransport = http_transport or _default_http_transport
        self.supports_login_form = True

    def get_sso_providers(self) -> Sequence[OIDCProviderConfig]:
        return tuple(self._providers.values())

    def get_sso_provider(self, name: str) -> OIDCProviderConfig | None:
        return self._providers.get(name)

    def build_authorize_redirect(
        self,
        provider_name: str,
        *,
        redirect_uri: str,
        next_url: str = "",
    ) -> str:
        """Create PKCE S256 challenge + CSRF state in session and return provider authorize URL."""
        cfg = self._providers.get(provider_name)
        if cfg is None:
            raise ValueError(f"Unknown OIDC provider: {provider_name!r}")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce_pair()

        session[SSO_STATE_KEY] = f"{provider_name}:{state}"
        session[SSO_VERIFIER_KEY] = verifier
        session[SSO_NONCE_KEY] = nonce
        session[SSO_NEXT_KEY] = next_url

        params = {
            "response_type": "code",
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(cfg.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        sep = "&" if "?" in cfg.authorize_url else "?"
        return f"{cfg.authorize_url}{sep}{urllib.parse.urlencode(params)}"

    def complete_callback(
        self,
        provider_name: str,
        *,
        code: str,
        state: str,
        redirect_uri: str,
    ) -> tuple[DeckUser, str]:
        """Validate state CSRF, exchange PKCE code for token, fetch userinfo, and map RBAC roles."""
        cfg = self._providers.get(provider_name)
        if cfg is None:
            raise ValueError(f"Unknown OIDC provider: {provider_name!r}")

        expected_state_raw = str(session.pop(SSO_STATE_KEY, ""))
        verifier = str(session.pop(SSO_VERIFIER_KEY, ""))
        session.pop(SSO_NONCE_KEY, None)
        next_url = str(session.pop(SSO_NEXT_KEY, ""))

        expected_state = f"{provider_name}:{state}"
        if not state or not expected_state_raw or not hmac.compare_digest(expected_state_raw, expected_state):
            raise PermissionError("Invalid or expired SSO state parameter.")
        if not code or not verifier:
            raise PermissionError("Missing SSO authorization code or PKCE verifier.")

        token_body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "code_verifier": verifier,
            }
        ).encode("utf-8")
        status, token_data = self._transport(
            "POST",
            cfg.token_url,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            token_body,
            cfg.timeout,
        )
        if status >= 400 or not token_data.get("access_token"):
            raise PermissionError("SSO token exchange failed.")

        access_token = str(token_data["access_token"])
        u_status, profile = self._transport(
            "GET",
            cfg.userinfo_url,
            {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            None,
            cfg.timeout,
        )
        if u_status >= 400:
            raise PermissionError("SSO userinfo lookup failed.")

        email = str(profile.get("email") or "").strip().lower()
        email_verified = profile.get("email_verified")
        sub = str(profile.get("sub") or profile.get("id") or "")
        if not sub:
            if email and email_verified is not False:
                sub = email
            else:
                raise PermissionError("SSO profile did not return a user identifier.")

        if cfg.allowed_domains:
            if email_verified is False or (
                cfg.require_verified_email and email_verified is not True
            ):
                raise PermissionError("SSO account email address is not verified.")
            domain = email.split("@", 1)[1] if "@" in email else ""
            if domain not in {d.lower() for d in cfg.allowed_domains}:
                raise PermissionError(f"Email domain '{domain or 'unknown'}' is not permitted.")

        raw_groups = profile.get(cfg.role_claim, ())
        if isinstance(raw_groups, str):
            groups = [raw_groups]
        elif isinstance(raw_groups, Sequence):
            groups = [str(g) for g in raw_groups]
        else:
            groups = []

        mapped_roles = [cfg.role_mapping[g] for g in groups if g in cfg.role_mapping]
        roles = tuple(dict.fromkeys(mapped_roles)) or (cfg.default_role,)
        is_super = any(g in cfg.superuser_groups for g in groups)

        user = DeckUser(
            id=f"sso:{cfg.name}:{sub}",
            username=email or sub,
            display_name=str(profile.get("name") or email or sub),
            email=email,
            roles=roles,
            is_superuser=is_super,
            metadata={"sso_provider": cfg.name},
        )
        return user, next_url

    def login_user(self, user: DeckUser) -> None:
        super().login_user(user)
        if user.id.startswith("sso:"):
            session[SSO_USER_SESSION_KEY] = {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "email": user.email,
                "roles": list(user.roles),
                "is_superuser": user.is_superuser,
            }

    def get_current_user(
        self,
        *,
        idle_timeout: int = 1800,
        absolute_timeout: int = 43200,
    ) -> DeckUser | None:
        user_id = self._validate_session_timestamps(
            idle_timeout=idle_timeout,
            absolute_timeout=absolute_timeout,
        )
        if user_id is None:
            return None
        if user_id.startswith("sso:"):
            raw = session.get(SSO_USER_SESSION_KEY)
            if isinstance(raw, Mapping) and str(raw.get("id")) == user_id:
                return DeckUser(
                    id=user_id,
                    username=str(raw.get("username", user_id)),
                    display_name=str(raw.get("display_name", "")),
                    email=str(raw.get("email", "")),
                    roles=tuple(str(r) for r in raw.get("roles", ())),
                    is_superuser=bool(raw.get("is_superuser", False)),
                )
            return None
        acc = self._accounts_by_id.get(user_id)
        return acc.user if acc is not None else None
