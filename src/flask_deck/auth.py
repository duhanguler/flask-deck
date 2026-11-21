from __future__ import annotations

import fnmatch
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from flask import session
from werkzeug.security import generate_password_hash

from flask_deck.security import (
    DEFAULT_PASSWORD_HASH_METHOD,
    mask_value,
    rotate_csrf_token,
    verify_password_constant_time,
)

AUTH_USER_KEY = "_deck_auth_user_id"
AUTH_IAT_KEY = "_deck_auth_iat"
AUTH_LAST_KEY = "_deck_auth_last"


@dataclass(frozen=True, slots=True)
class DeckUser:
    """Authenticated principal inside Flask-Deck."""

    id: str
    username: str
    display_name: str = ""
    email: str = ""
    roles: tuple[str, ...] = ("viewer",)
    is_superuser: bool = False
    tenant_id: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.display_name or self.username or self.id


@dataclass(frozen=True, slots=True)
class Role:
    """Declarative RBAC role definition covering model, action, and field rules."""

    name: str
    label: str = ""
    description: str = ""
    permissions: frozenset[str] = field(default_factory=frozenset)
    hidden_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)
    readonly_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)
    masked_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)

    @property
    def display_label(self) -> str:
        return self.label or self.name.replace("_", " ").title()

    def grants(self, permission: str) -> bool:
        for pattern in self.permissions:
            if pattern == "*" or pattern == permission or fnmatch.fnmatchcase(permission, pattern):
                return True
        return False


@dataclass(frozen=True, slots=True)
class RBACAccount:
    """Built-in credential record for RBACAuthProvider."""

    user: DeckUser
    password_hash: str


class AuthProvider(ABC):
    """Pluggable authentication & 4-level RBAC provider contract."""

    supports_login_form: bool = False

    @abstractmethod
    def get_current_user(
        self,
        *,
        idle_timeout: int = 1800,
        absolute_timeout: int = 43200,
    ) -> DeckUser | None:
        """Return the currently authenticated DeckUser, or None if unauthenticated."""

    def authenticate(self, username: str, password: str) -> DeckUser | None:
        """Verify credentials for built-in login form; return DeckUser or None."""
        return None

    def login_user(self, user: DeckUser) -> None:
        """Rotate session safely to prevent session fixation and store auth timestamps."""
        now = int(time.time())
        session.clear()
        session[AUTH_USER_KEY] = user.id
        session[AUTH_IAT_KEY] = now
        session[AUTH_LAST_KEY] = now
        rotate_csrf_token()

    def logout_user(self) -> None:
        """Clear session completely on logout."""
        session.clear()
        rotate_csrf_token()

    def _validate_session_timestamps(
        self,
        *,
        idle_timeout: int,
        absolute_timeout: int,
    ) -> str | None:
        user_id = session.get(AUTH_USER_KEY)
        if not isinstance(user_id, str) or not user_id:
            return None
        now = int(time.time())
        iat = session.get(AUTH_IAT_KEY)
        last = session.get(AUTH_LAST_KEY)
        if not isinstance(iat, int) or not isinstance(last, int):
            session.clear()
            return None
        if absolute_timeout > 0 and (now - iat) > absolute_timeout:
            session.clear()
            return None
        if idle_timeout > 0 and (now - last) > idle_timeout:
            session.clear()
            return None
        session[AUTH_LAST_KEY] = now
        return user_id

    def has_permission(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        """Deny-by-default permission check."""
        if user is None:
            return False
        return user.is_superuser

    def hidden_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        """Return field names completely hidden from user on model_slug."""
        return frozenset()

    def readonly_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        """Return field names user may see but never modify on model_slug."""
        return frozenset()

    def masked_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        """Return field names whose values should be masked for user on model_slug."""
        return frozenset()

    def mask_field_value(
        self,
        user: DeckUser | None,
        model_slug: str,
        field_name: str,
        value: Any,
    ) -> Any:
        if field_name in self.masked_fields_for(user, model_slug):
            return mask_value(value)
        return value

    def get_roles(self) -> Sequence[Role]:
        """Return declared roles for rendering the /_rbac matrix."""
        return ()

    def get_user_by_id(self, user_id: str) -> DeckUser | None:
        """Resolve a DeckUser by user_id when supported by the provider."""
        _ = user_id
        return None


class OpenAuthProvider(AuthProvider):
    """Explicit opt-in open access provider for local development and tests only."""

    supports_login_form = False

    def __init__(self, user: DeckUser | None = None) -> None:
        self._user = user or DeckUser(
            id="local-dev",
            username="developer",
            display_name="Local Developer",
            roles=("admin",),
            is_superuser=True,
        )

    def get_current_user(
        self,
        *,
        idle_timeout: int = 1800,
        absolute_timeout: int = 43200,
    ) -> DeckUser | None:
        return self._user

    def has_permission(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        return user is not None


class BasicAuthProvider(AuthProvider):
    """Password-hash authenticated provider with built-in login form."""

    supports_login_form = True

    def __init__(self, password_hashes: Mapping[str, str]) -> None:
        self._hashes = dict(password_hashes)
        self._users = {
            username: DeckUser(
                id=username,
                username=username,
                display_name=username,
                roles=("admin",),
                is_superuser=True,
            )
            for username in password_hashes
        }

    @classmethod
    def from_plain_passwords(cls, credentials: Mapping[str, str]) -> BasicAuthProvider:
        """Helper for demos/tests that hashes plaintext passwords using pbkdf2:sha256."""
        return cls(
            {
                username: generate_password_hash(password, method=DEFAULT_PASSWORD_HASH_METHOD)
                for username, password in credentials.items()
            }
        )

    def authenticate(self, username: str, password: str) -> DeckUser | None:
        stored_hash = self._hashes.get(username)
        if verify_password_constant_time(stored_hash, password):
            return self._users.get(username)
        return None

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
        return self._users.get(user_id)

    def get_user_by_id(self, user_id: str) -> DeckUser | None:
        return self._users.get(user_id)

    def has_permission(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        return user is not None and user.is_superuser


class RBACAuthProvider(AuthProvider):
    """Full 4-level RBAC provider with built-in login or external user loader."""

    def __init__(
        self,
        *,
        roles: Sequence[Role],
        accounts: Sequence[RBACAccount] = (),
        user_loader: Callable[[], DeckUser | None] | None = None,
    ) -> None:
        self._roles: dict[str, Role] = {r.name: r for r in roles}
        self._accounts_by_username: dict[str, RBACAccount] = {
            acc.user.username.lower(): acc for acc in accounts
        }
        self._accounts_by_id: dict[str, RBACAccount] = {acc.user.id: acc for acc in accounts}
        self._user_loader = user_loader
        self.supports_login_form = bool(accounts)

    @classmethod
    def make_account(
        cls,
        *,
        user: DeckUser,
        password: str | None = None,
        password_hash: str | None = None,
    ) -> RBACAccount:
        if password_hash is None:
            if password is None:
                raise ValueError("Provide either password or password_hash")
            password_hash = generate_password_hash(password, method=DEFAULT_PASSWORD_HASH_METHOD)
        return RBACAccount(user=user, password_hash=password_hash)

    def authenticate(self, username: str, password: str) -> DeckUser | None:
        account = self._accounts_by_username.get(username.strip().lower())
        stored_hash = account.password_hash if account is not None else None
        if verify_password_constant_time(stored_hash, password) and account is not None:
            return account.user
        return None

    def get_current_user(
        self,
        *,
        idle_timeout: int = 1800,
        absolute_timeout: int = 43200,
    ) -> DeckUser | None:
        if self._user_loader is not None:
            return self._user_loader()
        user_id = self._validate_session_timestamps(
            idle_timeout=idle_timeout,
            absolute_timeout=absolute_timeout,
        )
        if user_id is None:
            return None
        account = self._accounts_by_id.get(user_id)
        return account.user if account is not None else None

    def _user_roles(self, user: DeckUser | None) -> list[Role]:
        if user is None:
            return []
        return [self._roles[name] for name in user.roles if name in self._roles]

    def has_permission(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        if user is None:
            return False
        if user.is_superuser:
            return True
        return any(role.grants(permission) for role in self._user_roles(user))

    def _collect_field_rule(
        self,
        user: DeckUser | None,
        model_slug: str,
        attr: str,
    ) -> frozenset[str]:
        if user is None or user.is_superuser:
            return frozenset()
        roles = self._user_roles(user)
        if not roles:
            return frozenset()
        # Filter to roles that actually grant the relevant access on model_slug so an unrelated
        # role (e.g. audit-only) never intersects empty restrictions and wipes out field guards.
        if attr == "readonly_fields":
            relevant = [
                r
                for r in roles
                if r.grants(f"{model_slug}:edit") or r.grants(f"{model_slug}:create")
            ]
        else:
            relevant = [r for r in roles if r.grants(f"{model_slug}:view")]
        target_roles = relevant or roles
        sets: list[frozenset[str]] = []
        for role in target_roles:
            mapping: Mapping[str, frozenset[str]] = getattr(role, attr)
            restricted = set(mapping.get("*", frozenset())) | set(
                mapping.get(model_slug, frozenset())
            )
            sets.append(frozenset(restricted))
        if not sets:
            return frozenset()
        result = set(sets[0])
        for s in sets[1:]:
            result &= s
        return frozenset(result)

    def hidden_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return self._collect_field_rule(user, model_slug, "hidden_fields")

    def readonly_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return self._collect_field_rule(user, model_slug, "readonly_fields")

    def masked_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return self._collect_field_rule(user, model_slug, "masked_fields")

    def get_roles(self) -> Sequence[Role]:
        return tuple(self._roles.values())

    def get_demo_accounts(self) -> Sequence[DeckUser]:
        """Return configured accounts for opt-in non-production demo role switching."""
        return tuple(acc.user for acc in self._accounts_by_id.values())

    def get_account_by_id(self, user_id: str) -> DeckUser | None:
        acc = self._accounts_by_id.get(user_id)
        return acc.user if acc is not None else None

    def get_user_by_id(self, user_id: str) -> DeckUser | None:
        return self.get_account_by_id(user_id)


class FlaskLoginAuthProvider(RBACAuthProvider):
    """Bridge Flask-Login's ``current_user`` into Flask-Deck RBAC."""

    def __init__(
        self,
        *,
        roles: Sequence[Role] = (),
        role_getter: Callable[[Any], Sequence[str]] | None = None,
        superuser_getter: Callable[[Any], bool] | None = None,
        tenant_getter: Callable[[Any], Any] | None = None,
    ) -> None:
        self._role_getter = role_getter
        self._superuser_getter = superuser_getter
        self._tenant_getter = tenant_getter
        super().__init__(roles=roles, user_loader=self._load_from_flask_login)

    def _load_from_flask_login(self) -> DeckUser | None:
        try:
            from flask_login import current_user
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "flask-login must be installed to use FlaskLoginAuthProvider"
            ) from exc

        if current_user is None or not getattr(current_user, "is_authenticated", False):
            return None

        uid = str(getattr(current_user, "id", getattr(current_user, "get_id", lambda: "")()))
        username = str(
            getattr(current_user, "username", getattr(current_user, "email", uid))
        )
        display_name = str(getattr(current_user, "name", getattr(current_user, "full_name", username)))
        email = str(getattr(current_user, "email", ""))

        if self._role_getter is not None:
            roles = tuple(self._role_getter(current_user))
        else:
            raw_roles = getattr(current_user, "roles", getattr(current_user, "role", ()))
            roles = (raw_roles,) if isinstance(raw_roles, str) else tuple(str(r) for r in raw_roles)

        if self._superuser_getter is not None:
            is_super = bool(self._superuser_getter(current_user))
        else:
            is_super = bool(
                getattr(current_user, "is_superuser", getattr(current_user, "is_admin", False))
            )

        tenant_id = self._tenant_getter(current_user) if self._tenant_getter else None
        return DeckUser(
            id=uid,
            username=username,
            display_name=display_name,
            email=email,
            roles=roles,
            is_superuser=is_super,
            tenant_id=tenant_id,
        )
