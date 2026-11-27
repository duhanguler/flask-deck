from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
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


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _decode_jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise PermissionError("Malformed OIDC id_token JWT.")
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        signature = _b64url_decode(parts[2])
    except Exception as exc:
        raise PermissionError(f"Invalid OIDC id_token encoding: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise PermissionError("OIDC id_token header/claims must be JSON objects.")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, claims, signing_input, signature


def _verify_jwk_signature(
    header: Mapping[str, Any],
    signing_input: bytes,
    signature: bytes,
    jwks_keys: Sequence[Mapping[str, Any]],
) -> None:
    """Verify RSA/EC JWS signature using optional ``cryptography`` library."""
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives import hashes  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric import (  # type: ignore[import-not-found]
            ec,
            padding,
            rsa,
            utils,
        )
    except ImportError as exc:
        raise PermissionError(
            "cryptography package is required for id_token JWKS signature verification "
            "(pip install flask-deck[crypto])."
        ) from exc

    alg = str(header.get("alg") or "")
    kid = header.get("kid")
    candidates = [
        k for k in jwks_keys if not kid or k.get("kid") == kid
    ]
    if not candidates:
        raise PermissionError("No matching JWK found for OIDC id_token kid.")

    rsa_hashes = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
    }
    ec_hashes = {
        "ES256": (hashes.SHA256, 32),
        "ES384": (hashes.SHA384, 48),
        "ES512": (hashes.SHA512, 66),
    }

    for jwk in candidates:
        kty = str(jwk.get("kty") or "")
        if kty == "RSA" and alg in rsa_hashes:
            try:
                n = int.from_bytes(_b64url_decode(str(jwk["n"])), "big")
                e = int.from_bytes(_b64url_decode(str(jwk["e"])), "big")
                pub = rsa.RSAPublicNumbers(e, n).public_key()
            except (KeyError, TypeError, ValueError):
                continue
            try:
                pub.verify(signature, signing_input, padding.PKCS1v15(), rsa_hashes[alg]())
                return
            except InvalidSignature:
                continue
        elif kty == "EC" and alg in ec_hashes:
            hash_cls, coord_len = ec_hashes[alg]
            crv_map: dict[str, ec.EllipticCurve] = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }
            curve = crv_map.get(str(jwk.get("crv") or ""))
            if curve is None or len(signature) != coord_len * 2:
                continue
            try:
                x = int.from_bytes(_b64url_decode(str(jwk["x"])), "big")
                y = int.from_bytes(_b64url_decode(str(jwk["y"])), "big")
                ec_pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
                r = int.from_bytes(signature[:coord_len], "big")
                s = int.from_bytes(signature[coord_len:], "big")
                der_sig = utils.encode_dss_signature(r, s)
            except (KeyError, TypeError, ValueError):
                continue
            try:
                ec_pub.verify(der_sig, signing_input, ec.ECDSA(hash_cls()))
                return
            except InvalidSignature:
                continue
    raise PermissionError("OIDC id_token signature verification failed.")


@dataclass(frozen=True, slots=True)
class OIDCProviderConfig:
    """Declarative OAuth2 / OIDC identity provider configuration (Google, GitHub, Okta, Entra, Keycloak)."""

    name: str
    label: str
    client_id: str
    client_secret: str
    authorize_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    issuer_url: str = ""
    jwks_uri: str = ""
    require_id_token_signature: bool = False
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    role_claim: str = "groups"
    role_mapping: Mapping[str, str] = field(default_factory=dict)
    default_role: str = "viewer"
    superuser_groups: frozenset[str] = field(default_factory=frozenset)
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    require_verified_email: bool = False
    timeout: float = 8.0

    def __post_init__(self) -> None:
        if self.issuer_url and urllib.parse.urlsplit(self.issuer_url).scheme.lower() != "https":
            raise ValueError("OIDCProviderConfig.issuer_url must use https://")
        for attr in ("authorize_url", "token_url", "userinfo_url", "jwks_uri"):
            val = getattr(self, attr)
            if val:
                if urllib.parse.urlsplit(val).scheme.lower() != "https":
                    raise ValueError(f"OIDCProviderConfig.{attr} must use https://")
            elif attr in ("authorize_url", "token_url", "userinfo_url") and not self.issuer_url:
                raise ValueError(f"OIDCProviderConfig.{attr} must use https://")

    @classmethod
    def google(
        cls,
        *,
        client_id: str,
        client_secret: str,
        name: str = "google",
        label: str = "Google",
        **kwargs: Any,
    ) -> OIDCProviderConfig:
        kwargs.setdefault("require_verified_email", True)
        return cls(
            name=name,
            label=label,
            client_id=client_id,
            client_secret=client_secret,
            issuer_url="https://accounts.google.com",
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            **kwargs,
        )

    @classmethod
    def github(
        cls,
        *,
        client_id: str,
        client_secret: str,
        name: str = "github",
        label: str = "GitHub",
        **kwargs: Any,
    ) -> OIDCProviderConfig:
        kwargs.setdefault("scopes", ("read:user", "user:email"))
        return cls(
            name=name,
            label=label,
            client_id=client_id,
            client_secret=client_secret,
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user",
            **kwargs,
        )

    @classmethod
    def okta(
        cls,
        *,
        domain: str,
        client_id: str,
        client_secret: str,
        auth_server: str = "default",
        name: str = "okta",
        label: str = "Okta",
        **kwargs: Any,
    ) -> OIDCProviderConfig:
        clean_domain = domain.removeprefix("https://").rstrip("/")
        issuer = f"https://{clean_domain}/oauth2/{auth_server}"
        return cls(
            name=name,
            label=label,
            client_id=client_id,
            client_secret=client_secret,
            issuer_url=issuer,
            authorize_url=f"{issuer}/v1/authorize",
            token_url=f"{issuer}/v1/token",
            userinfo_url=f"{issuer}/v1/userinfo",
            jwks_uri=f"{issuer}/v1/keys",
            **kwargs,
        )

    @classmethod
    def entra(
        cls,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        name: str = "entra",
        label: str = "Microsoft Entra ID",
        **kwargs: Any,
    ) -> OIDCProviderConfig:
        issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        return cls(
            name=name,
            label=label,
            client_id=client_id,
            client_secret=client_secret,
            issuer_url=issuer,
            authorize_url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
            token_url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/oidc/userinfo",
            jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
            **kwargs,
        )

    @classmethod
    def keycloak(
        cls,
        *,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        name: str = "keycloak",
        label: str = "Keycloak",
        **kwargs: Any,
    ) -> OIDCProviderConfig:
        clean_base = base_url.rstrip("/")
        issuer = f"{clean_base}/realms/{realm}"
        return cls(
            name=name,
            label=label,
            client_id=client_id,
            client_secret=client_secret,
            issuer_url=issuer,
            authorize_url=f"{issuer}/protocol/openid-connect/auth",
            token_url=f"{issuer}/protocol/openid-connect/token",
            userinfo_url=f"{issuer}/protocol/openid-connect/userinfo",
            jwks_uri=f"{issuer}/protocol/openid-connect/certs",
            **kwargs,
        )


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
        self._oidc_lock = threading.Lock()
        self._discovery_cache: dict[str, dict[str, str]] = {}
        self._jwks_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self.supports_login_form = True
        self.supports_password_login = bool(accounts)

    def _discover_provider(self, cfg: OIDCProviderConfig) -> dict[str, str]:
        with self._oidc_lock:
            cached = self._discovery_cache.get(cfg.name)
            if cached is not None:
                return cached
        if not cfg.issuer_url:
            raise PermissionError(f"OIDC provider {cfg.name!r} is missing endpoints and issuer_url.")
        disc_url = cfg.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        status, payload = self._transport(
            "GET",
            disc_url,
            {"Accept": "application/json"},
            None,
            cfg.timeout,
        )
        if status >= 400:
            raise PermissionError(f"OIDC discovery failed for {cfg.name!r} (HTTP {status}).")
        resolved: dict[str, str] = {}
        for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
            val = str(payload.get(key) or "")
            if val:
                if urllib.parse.urlsplit(val).scheme.lower() != "https":
                    raise PermissionError(f"Discovered {key} must use https://")
                resolved[key] = val
        with self._oidc_lock:
            self._discovery_cache[cfg.name] = resolved
        return resolved

    def _resolve_endpoints(self, cfg: OIDCProviderConfig) -> tuple[str, str, str, str]:
        auth_url = cfg.authorize_url
        token_url = cfg.token_url
        userinfo_url = cfg.userinfo_url
        jwks_uri = cfg.jwks_uri
        need_disc = (
            not auth_url
            or not token_url
            or not userinfo_url
            or (cfg.require_id_token_signature and not jwks_uri)
        )
        if need_disc and cfg.issuer_url:
            disc = self._discover_provider(cfg)
            auth_url = auth_url or disc.get("authorization_endpoint", "")
            token_url = token_url or disc.get("token_endpoint", "")
            userinfo_url = userinfo_url or disc.get("userinfo_endpoint", "")
            jwks_uri = jwks_uri or disc.get("jwks_uri", "")
        if not auth_url or not token_url or not userinfo_url:
            raise PermissionError(f"OIDC provider {cfg.name!r} endpoints could not be resolved.")
        return auth_url, token_url, userinfo_url, jwks_uri

    def _fetch_jwks(self, cfg: OIDCProviderConfig, jwks_uri: str) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._oidc_lock:
            cached = self._jwks_cache.get(jwks_uri)
            if cached is not None and cached[0] > now:
                return cached[1]
        status, payload = self._transport(
            "GET",
            jwks_uri,
            {"Accept": "application/json"},
            None,
            cfg.timeout,
        )
        keys = payload.get("keys") if status < 400 else None
        if not isinstance(keys, list):
            raise PermissionError("Failed to fetch OIDC provider JWKS keys.")
        cleaned = [dict(k) for k in keys if isinstance(k, Mapping)]
        with self._oidc_lock:
            self._jwks_cache[jwks_uri] = (now + 300.0, cleaned)
        return cleaned

    def _verify_id_token(
        self,
        cfg: OIDCProviderConfig,
        id_token: str,
        *,
        expected_nonce: str,
        jwks_uri: str,
    ) -> dict[str, Any]:
        header, claims, signing_input, signature = _decode_jwt_parts(id_token)
        alg = str(header.get("alg") or "").lower()
        if not alg or alg == "none":
            raise PermissionError("Unsigned OIDC id_token (alg=none) is rejected.")

        if cfg.require_id_token_signature:
            if not jwks_uri:
                raise PermissionError("OIDC id_token signature verification requires jwks_uri.")
            keys = self._fetch_jwks(cfg, jwks_uri)
            _verify_jwk_signature(header, signing_input, signature, keys)

        if expected_nonce:
            token_nonce = str(claims.get("nonce") or "")
            if not token_nonce or not hmac.compare_digest(expected_nonce, token_nonce):
                raise PermissionError("OIDC id_token nonce mismatch.")

        if "exp" in claims:
            try:
                raw_exp = claims["exp"]
                if isinstance(raw_exp, bool) or (
                    isinstance(raw_exp, float) and not math.isfinite(raw_exp)
                ):
                    raise ValueError("non-finite exp")
                exp_ts = int(raw_exp)
            except (TypeError, ValueError, OverflowError) as exc:
                raise PermissionError("OIDC id_token has invalid exp claim.") from exc
            if exp_ts < int(time.time()) - 60:
                raise PermissionError("OIDC id_token has expired.")

        if "aud" in claims:
            aud = claims["aud"]
            aud_ok = (
                cfg.client_id in [str(a) for a in aud]
                if isinstance(aud, Sequence) and not isinstance(aud, str)
                else str(aud) == cfg.client_id
            )
            if not aud_ok:
                raise PermissionError("OIDC id_token audience mismatch.")

        if cfg.issuer_url and "iss" in claims and (
            str(claims["iss"]).rstrip("/") != cfg.issuer_url.rstrip("/")
        ):
            raise PermissionError("OIDC id_token issuer mismatch.")
        return claims

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

        authorize_url, _, _, _ = self._resolve_endpoints(cfg)
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
        sep = "&" if "?" in authorize_url else "?"
        return f"{authorize_url}{sep}{urllib.parse.urlencode(params)}"

    def complete_callback(
        self,
        provider_name: str,
        *,
        code: str,
        state: str,
        redirect_uri: str,
    ) -> tuple[DeckUser, str]:
        """Validate state CSRF, exchange PKCE code for token, verify id_token, fetch userinfo, and map RBAC roles."""
        cfg = self._providers.get(provider_name)
        if cfg is None:
            raise ValueError(f"Unknown OIDC provider: {provider_name!r}")

        expected_state_raw = str(session.pop(SSO_STATE_KEY, ""))
        verifier = str(session.pop(SSO_VERIFIER_KEY, ""))
        expected_nonce = str(session.pop(SSO_NONCE_KEY, ""))
        next_url = str(session.pop(SSO_NEXT_KEY, ""))

        expected_state = f"{provider_name}:{state}"
        if not state or not expected_state_raw or not hmac.compare_digest(expected_state_raw, expected_state):
            raise PermissionError("Invalid or expired SSO state parameter.")
        if not code or not verifier:
            raise PermissionError("Missing SSO authorization code or PKCE verifier.")

        _, token_url, userinfo_url, jwks_uri = self._resolve_endpoints(cfg)
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
            token_url,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            token_body,
            cfg.timeout,
        )
        if status >= 400 or not token_data.get("access_token"):
            raise PermissionError("SSO token exchange failed.")

        id_claims: dict[str, Any] = {}
        raw_id_token = token_data.get("id_token")
        if isinstance(raw_id_token, str) and raw_id_token:
            id_claims = self._verify_id_token(
                cfg,
                raw_id_token,
                expected_nonce=expected_nonce,
                jwks_uri=jwks_uri,
            )
        elif cfg.require_id_token_signature:
            raise PermissionError("OIDC provider did not return required id_token.")

        access_token = str(token_data["access_token"])
        u_status, userinfo_profile = self._transport(
            "GET",
            userinfo_url,
            {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            None,
            cfg.timeout,
        )
        if u_status >= 400:
            raise PermissionError("SSO userinfo lookup failed.")
        id_sub = str(id_claims.get("sub") or "")
        ui_sub = str(userinfo_profile.get("sub") or "")
        if id_sub and ui_sub and not hmac.compare_digest(id_sub, ui_sub):
            raise PermissionError("SSO userinfo subject does not match verified id_token subject.")
        profile: dict[str, Any] = {**id_claims, **userinfo_profile}

        email = str(profile.get("email") or "").strip().lower()
        email_verified = profile.get("email_verified")
        sub = str(profile.get("sub") or profile.get("id") or "")
        if not sub:
            if email and email_verified is not False:
                sub = email
            else:
                raise PermissionError("SSO profile did not return a user identifier.")

        if email_verified is False or (
            cfg.require_verified_email and email_verified is not True
        ):
            raise PermissionError("SSO account email address is not verified.")

        if cfg.allowed_domains:
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
                "tenant_id": user.tenant_id,
                "metadata": dict(user.metadata),
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
                raw_meta = raw.get("metadata")
                return DeckUser(
                    id=user_id,
                    username=str(raw.get("username", user_id)),
                    display_name=str(raw.get("display_name", "")),
                    email=str(raw.get("email", "")),
                    roles=tuple(str(r) for r in raw.get("roles", ())),
                    is_superuser=bool(raw.get("is_superuser", False)),
                    tenant_id=raw.get("tenant_id"),
                    metadata=dict(raw_meta) if isinstance(raw_meta, Mapping) else {},
                )
            return None
        acc = self._accounts_by_id.get(user_id)
        return acc.user if acc is not None else None
