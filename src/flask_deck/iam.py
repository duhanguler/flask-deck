from __future__ import annotations

import difflib
import hashlib
import json
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

import sqlalchemy as sa
from flask import g, has_request_context
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash

from flask_deck.auth import AuthProvider, DeckUser, Role, collect_role_field_rule
from flask_deck.security import DEFAULT_PASSWORD_HASH_METHOD, verify_password_constant_time

# Compact curated list of universally breached / weak passwords (zero external files/deps).
_COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "00000000",
        "11111111",
        "password",
        "password1",
        "password123",
        "passw0rd",
        "p@ssword",
        "p@ssw0rd",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "admin",
        "admin123",
        "admin1234",
        "administrator",
        "root",
        "root1234",
        "letmein",
        "letmein123",
        "welcome",
        "welcome1",
        "welcome123",
        "iloveyou",
        "changeme",
        "changeme123",
        "abc12345",
        "abcdef12",
        "monkey",
        "dragon",
        "master",
        "football",
        "baseball",
        "shadow",
        "sunshine",
        "princess",
        "trustno1",
        "starwars",
        "superman",
        "batman",
        "secret",
        "secret123",
        "default",
        "test1234",
        "testing123",
        "zaq12wsx",
        "qazwsxedc",
    }
)


@runtime_checkable
class PasswordValidator(Protocol):
    """Pluggable password strength validator protocol (Django AUTH_PASSWORD_VALIDATORS parity)."""

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        """Return an error message string if invalid, or None if valid."""

    def help_text(self) -> str:
        """Return a short user-facing rule description."""


class MinimumLengthValidator:
    """Require passwords to meet a minimum character length."""

    def __init__(self, min_length: int = 8) -> None:
        self.min_length = max(4, int(min_length))

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        _ = (username, email, display_name)
        if len(password) < self.min_length:
            return f"Password must be at least {self.min_length} characters."
        return None

    def help_text(self) -> str:
        return f"At least {self.min_length} characters."


class CommonPasswordValidator:
    """Reject commonly breached / dictionary passwords (case-insensitive)."""

    def __init__(self, extra_common: Sequence[str] = ()) -> None:
        self._blocked = _COMMON_PASSWORDS | frozenset(w.strip().lower() for w in extra_common if w.strip())

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        _ = (username, email, display_name)
        if password.strip().lower() in self._blocked:
            return "Password is too common and easily guessed."
        return None

    def help_text(self) -> str:
        return "Must not be a commonly used password."


class NumericPasswordValidator:
    """Reject entirely numeric passwords."""

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        _ = (username, email, display_name)
        if password.isdigit():
            return "Password cannot be entirely numeric."
        return None

    def help_text(self) -> str:
        return "Cannot be entirely numeric."


class UserAttributeSimilarityValidator:
    """Reject passwords too similar to the user's username, email, or display name."""

    def __init__(self, max_similarity: float = 0.7) -> None:
        self.max_similarity = max(0.3, min(0.95, float(max_similarity)))

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        pwd_low = password.lower()
        candidates: list[str] = []
        for raw in (username, display_name):
            c = raw.strip().lower()
            if len(c) >= 3:
                candidates.append(c)
        if email and "@" in email:
            local_part = email.split("@", 1)[0].strip().lower()
            if len(local_part) >= 3:
                candidates.append(local_part)
        for cand in candidates:
            if cand in pwd_low:
                return "Password is too similar to your account username or email."
            ratio = difflib.SequenceMatcher(None, pwd_low, cand).quick_ratio()
            if ratio >= self.max_similarity:
                return "Password is too similar to your account username or email."
        return None

    def help_text(self) -> str:
        return "Must not resemble your username, display name, or email."


class ComplexityValidator:
    """Require character class diversity (uppercase, lowercase, digit, symbol)."""

    def __init__(
        self,
        *,
        require_upper: bool = True,
        require_lower: bool = True,
        require_digit: bool = True,
        require_symbol: bool = True,
    ) -> None:
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_symbol = require_symbol

    def validate(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> str | None:
        _ = (username, email, display_name)
        missing: list[str] = []
        if self.require_upper and not any(ch.isupper() for ch in password):
            missing.append("an uppercase letter")
        if self.require_lower and not any(ch.islower() for ch in password):
            missing.append("a lowercase letter")
        if self.require_digit and not any(ch.isdigit() for ch in password):
            missing.append("a digit")
        if self.require_symbol and not any(not ch.isalnum() for ch in password):
            missing.append("a symbol")
        if missing:
            return f"Password must include {', '.join(missing)}."
        return None

    def help_text(self) -> str:
        parts: list[str] = []
        if self.require_upper:
            parts.append("uppercase")
        if self.require_lower:
            parts.append("lowercase")
        if self.require_digit:
            parts.append("digit")
        if self.require_symbol:
            parts.append("symbol")
        return f"Include {', '.join(parts)}." if parts else ""


def validate_password_strength(
    password: str,
    validators: Sequence[PasswordValidator] | None = None,
    *,
    username: str = "",
    email: str = "",
    display_name: str = "",
) -> list[str]:
    """Validate ``password`` against all configured validators and return list of error strings."""
    active_validators: Sequence[PasswordValidator] = (
        validators
        if validators is not None
        else (
            MinimumLengthValidator(min_length=8),
            CommonPasswordValidator(),
            NumericPasswordValidator(),
        )
    )
    errors: list[str] = []
    for validator in active_validators:
        msg = validator.validate(
            password,
            username=username,
            email=email,
            display_name=display_name,
        )
        if msg:
            errors.append(msg)
    return errors


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _decode_field_rules(raw: str | None) -> dict[str, frozenset[str]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, frozenset[str]] = {}
    for k, v in parsed.items():
        if isinstance(k, str) and isinstance(v, (list, tuple, set)):
            items = frozenset(str(x).strip() for x in v if str(x).strip())
            if items:
                out[k.strip()] = items
    return out


def _encode_field_rules(rules: Mapping[str, Sequence[str] | frozenset[str]] | None) -> str:
    if not rules:
        return "{}"
    clean: dict[str, list[str]] = {}
    for k, v in rules.items():
        slug = str(k).strip()
        vals = sorted({str(x).strip() for x in v if str(x).strip()})
        if slug and vals:
            clean[slug] = vals
    return json.dumps(clean, separators=(",", ":"), sort_keys=True)


def _decode_str_list(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(x).strip() for x in parsed if str(x).strip())


def _decode_json_dict(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _hash_reset_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IAMGroupRecord:
    """Persisted DB-backed role/group definition mapped 1:1 to :class:`Role`."""

    id: str
    name: str
    label: str
    description: str
    permissions: frozenset[str]
    hidden_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)
    readonly_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)
    masked_fields: Mapping[str, frozenset[str]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_role(self) -> Role:
        return Role(
            name=self.name,
            label=self.label,
            description=self.description,
            permissions=self.permissions,
            hidden_fields=self.hidden_fields,
            readonly_fields=self.readonly_fields,
            masked_fields=self.masked_fields,
        )


@dataclass(frozen=True, slots=True)
class IAMUserRecord:
    """Persisted DB-backed operator account (excludes password hash by default)."""

    id: str
    username: str
    email: str
    display_name: str
    is_active: bool
    is_superuser: bool
    group_ids: tuple[str, ...]
    role_names: tuple[str, ...]
    direct_permissions: frozenset[str] = field(default_factory=frozenset)
    tenant_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: datetime | None = None

    def to_deck_user(self) -> DeckUser:
        return DeckUser(
            id=self.id,
            username=self.username,
            display_name=self.display_name,
            email=self.email,
            roles=self.role_names,
            is_superuser=self.is_superuser,
            tenant_id=self.tenant_id,
            metadata=self.metadata,
            direct_permissions=self.direct_permissions,
        )


@dataclass(slots=True)
class _GroupsCache:
    groups_by_id: dict[str, IAMGroupRecord]
    groups_by_name: dict[str, IAMGroupRecord]
    roles_by_name: dict[str, Role]


class SQLAlchemyAuthProvider(AuthProvider):
    """Optional DB-backed 4-level RBAC provider with scalable SQL IAM, direct user permissions, and password policy."""

    supports_login_form = True
    supports_password_login = True
    supports_password_change = True
    supports_iam_management = True

    def __init__(
        self,
        engine: Engine,
        *,
        table_prefix: str = "_flask_deck_",
        password_min_length: int = 8,
        strict_password_policy: bool = False,
        password_validators: Sequence[PasswordValidator] | None = None,
        demo_account_ids: Sequence[str] = (),
        auto_create_tables: bool = True,
    ) -> None:
        self._engine = engine
        self._password_min_length = max(4, password_min_length)
        self.strict_password_policy: bool = bool(strict_password_policy)
        self._has_custom_password_validators: bool = password_validators is not None
        if password_validators is not None:
            self.password_validators: tuple[PasswordValidator, ...] = tuple(password_validators)
        elif self.strict_password_policy:
            self.password_validators = (
                MinimumLengthValidator(max(12, self._password_min_length)),
                CommonPasswordValidator(),
                NumericPasswordValidator(),
                UserAttributeSimilarityValidator(),
                ComplexityValidator(),
            )
        else:
            self.password_validators = (
                MinimumLengthValidator(self._password_min_length),
                CommonPasswordValidator(),
                NumericPasswordValidator(),
            )
        self._demo_account_ids = tuple(str(x) for x in demo_account_ids)
        self._groups_cache_attr = f"_deck_iam_groups_{id(self)}"
        self._users_cache_attr = f"_deck_iam_users_{id(self)}"
        self._meta = sa.MetaData()
        self._users_tbl = sa.Table(
            f"{table_prefix}users",
            self._meta,
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("username", sa.String(120), unique=True, index=True, nullable=False),
            sa.Column("email", sa.String(255), nullable=False, default=""),
            sa.Column("display_name", sa.String(160), nullable=False, default=""),
            sa.Column("password_hash", sa.String(512), nullable=False),
            sa.Column("is_active", sa.Boolean, nullable=False, default=True),
            sa.Column("is_superuser", sa.Boolean, nullable=False, default=False),
            sa.Column("tenant_id", sa.String(120), nullable=True),
            sa.Column("metadata_json", sa.Text, nullable=False, default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._groups_tbl = sa.Table(
            f"{table_prefix}groups",
            self._meta,
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("name", sa.String(80), unique=True, index=True, nullable=False),
            sa.Column("label", sa.String(120), nullable=False, default=""),
            sa.Column("description", sa.Text, nullable=False, default=""),
            sa.Column("permissions_json", sa.Text, nullable=False, default="[]"),
            sa.Column("hidden_fields_json", sa.Text, nullable=False, default="{}"),
            sa.Column("readonly_fields_json", sa.Text, nullable=False, default="{}"),
            sa.Column("masked_fields_json", sa.Text, nullable=False, default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        self._user_groups_tbl = sa.Table(
            f"{table_prefix}user_groups",
            self._meta,
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey(f"{table_prefix}users.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "group_id",
                sa.String(64),
                sa.ForeignKey(f"{table_prefix}groups.id", ondelete="CASCADE"),
                primary_key=True,
            ),
        )
        self._user_perms_tbl = sa.Table(
            f"{table_prefix}user_permissions",
            self._meta,
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey(f"{table_prefix}users.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("permission", sa.String(160), primary_key=True),
        )
        self._password_resets_tbl = sa.Table(
            f"{table_prefix}password_resets",
            self._meta,
            sa.Column("token_hash", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey(f"{table_prefix}users.id", ondelete="CASCADE"),
                index=True,
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        if auto_create_tables:
            self._meta.create_all(engine, checkfirst=True)

    def _invalidate_cache(self) -> None:
        if has_request_context():
            for attr in (self._groups_cache_attr, self._users_cache_attr):
                if hasattr(g, attr):
                    delattr(g, attr)

    def _load_groups_cache(self) -> _GroupsCache:
        if has_request_context():
            cached = getattr(g, self._groups_cache_attr, None)
            if isinstance(cached, _GroupsCache):
                return cached
        with self._engine.connect() as conn:
            g_rows = conn.execute(
                sa.select(self._groups_tbl).order_by(self._groups_tbl.c.name.asc())
            ).fetchall()
        now = datetime.now(timezone.utc)
        groups_by_id: dict[str, IAMGroupRecord] = {}
        groups_by_name: dict[str, IAMGroupRecord] = {}
        roles_by_name: dict[str, Role] = {}
        for r in g_rows:
            grec = IAMGroupRecord(
                id=str(r.id),
                name=str(r.name),
                label=str(r.label or r.name),
                description=str(r.description or ""),
                permissions=frozenset(_decode_str_list(r.permissions_json)),
                hidden_fields=_decode_field_rules(r.hidden_fields_json),
                readonly_fields=_decode_field_rules(r.readonly_fields_json),
                masked_fields=_decode_field_rules(r.masked_fields_json),
                created_at=_ensure_utc(r.created_at) or now,
                updated_at=_ensure_utc(r.updated_at) or now,
            )
            groups_by_id[grec.id] = grec
            groups_by_name[grec.name] = grec
            roles_by_name[grec.name] = grec.to_role()
        cache = _GroupsCache(
            groups_by_id=groups_by_id,
            groups_by_name=groups_by_name,
            roles_by_name=roles_by_name,
        )
        if has_request_context():
            setattr(g, self._groups_cache_attr, cache)
        return cache

    def _hydrate_users(
        self,
        conn: sa.Connection,
        u_rows: Sequence[Any],
        groups_cache: _GroupsCache,
    ) -> list[tuple[IAMUserRecord, str, DeckUser]]:
        if not u_rows:
            return []
        uids = [str(r.id) for r in u_rows]
        ug_rows = conn.execute(
            sa.select(self._user_groups_tbl).where(self._user_groups_tbl.c.user_id.in_(uids))
        ).fetchall()
        up_rows = conn.execute(
            sa.select(self._user_perms_tbl).where(self._user_perms_tbl.c.user_id.in_(uids))
        ).fetchall()

        ug_map: dict[str, list[str]] = {}
        for link in ug_rows:
            gid = str(link.group_id)
            if gid in groups_cache.groups_by_id:
                ug_map.setdefault(str(link.user_id), []).append(gid)
        up_map: dict[str, set[str]] = {}
        for pr in up_rows:
            perm = str(pr.permission).strip()
            if perm:
                up_map.setdefault(str(pr.user_id), set()).add(perm)

        now = datetime.now(timezone.utc)
        out: list[tuple[IAMUserRecord, str, DeckUser]] = []
        for r in u_rows:
            uid = str(r.id)
            gids = tuple(ug_map.get(uid, ()))
            rnames = tuple(
                groups_cache.groups_by_id[gid].name
                for gid in gids
                if gid in groups_cache.groups_by_id
            )
            dperms = frozenset(up_map.get(uid, ()))
            urec = IAMUserRecord(
                id=uid,
                username=str(r.username),
                email=str(r.email or ""),
                display_name=str(r.display_name or r.username),
                is_active=bool(r.is_active),
                is_superuser=bool(r.is_superuser),
                group_ids=gids,
                role_names=rnames,
                direct_permissions=dperms,
                tenant_id=str(r.tenant_id) if r.tenant_id is not None else None,
                metadata=_decode_json_dict(r.metadata_json),
                created_at=_ensure_utc(r.created_at) or now,
                updated_at=_ensure_utc(r.updated_at) or now,
                last_login_at=_ensure_utc(r.last_login_at),
            )
            out.append((urec, str(r.password_hash), urec.to_deck_user()))
        return out

    def _fetch_user_entry_by_id(self, user_id: str) -> tuple[IAMUserRecord, str, DeckUser] | None:
        ucache: dict[str, tuple[IAMUserRecord, str, DeckUser] | None] = {}
        if has_request_context():
            existing_cache = getattr(g, self._users_cache_attr, None)
            if isinstance(existing_cache, dict):
                ucache = existing_cache
            else:
                setattr(g, self._users_cache_attr, ucache)
            if user_id in ucache:
                return ucache[user_id]

        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._users_tbl).where(self._users_tbl.c.id == user_id)
            ).first()
            hydrated = self._hydrate_users(conn, [row], groups_cache) if row is not None else []
        entry = hydrated[0] if hydrated else None
        if has_request_context():
            ucache[user_id] = entry
        return entry

    def _validate_pwd(
        self,
        password: str,
        *,
        username: str = "",
        email: str = "",
        display_name: str = "",
    ) -> list[str]:
        return validate_password_strength(
            password,
            self.password_validators,
            username=username,
            email=email,
            display_name=display_name,
        )

    def password_help_texts(self) -> tuple[str, ...]:
        return tuple(v.help_text() for v in self.password_validators if v.help_text())

    # ------------------------------------------------------------------
    # AuthProvider Contract
    # ------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> DeckUser | None:
        clean_u = username.strip().lower()
        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._users_tbl).where(
                    sa.func.lower(self._users_tbl.c.username) == clean_u
                )
            ).first()
            hydrated = self._hydrate_users(conn, [row], groups_cache) if row is not None else []
        entry = hydrated[0] if hydrated else None
        stored_hash = entry[1] if entry is not None else None
        ok = verify_password_constant_time(stored_hash, password)
        if not ok or entry is None:
            return None
        urec, _, deck_user = entry
        if not urec.is_active:
            return None
        now = datetime.now(timezone.utc)
        with self._engine.begin() as conn:
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == urec.id)
                .values(last_login_at=now)
            )
        self._invalidate_cache()
        return deck_user

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
        entry = self._fetch_user_entry_by_id(user_id)
        if entry is None or not entry[0].is_active:
            return None
        return entry[2]

    def _user_roles(self, user: DeckUser | None) -> list[Role]:
        if user is None:
            return []
        groups_cache = self._load_groups_cache()
        return [groups_cache.roles_by_name[r] for r in user.roles if r in groups_cache.roles_by_name]

    def has_permission(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        _ = (model_slug, obj)
        if user is None:
            return False
        if user.is_superuser:
            return True
        if user.grants_direct(permission):
            return True
        return any(role.grants(permission) for role in self._user_roles(user))

    def hidden_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "hidden_fields")

    def readonly_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "readonly_fields")

    def masked_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "masked_fields")

    def get_roles(self) -> Sequence[Role]:
        return tuple(self._load_groups_cache().roles_by_name.values())

    def get_user_by_id(self, user_id: str) -> DeckUser | None:
        entry = self._fetch_user_entry_by_id(user_id)
        if entry is None or not entry[0].is_active:
            return None
        return entry[2]

    def get_impersonatable_users(self, actor: DeckUser) -> Sequence[DeckUser]:
        if not actor.is_superuser:
            return ()
        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            u_rows = conn.execute(
                sa.select(self._users_tbl)
                .where(
                    self._users_tbl.c.is_active.is_(True),
                    self._users_tbl.c.is_superuser.is_(False),
                    self._users_tbl.c.id != actor.id,
                )
                .order_by(self._users_tbl.c.username.asc())
                .limit(100)
            ).fetchall()
            hydrated = self._hydrate_users(conn, u_rows, groups_cache)
        return tuple(du for _, _, du in hydrated)

    def get_demo_accounts(self) -> Sequence[DeckUser]:
        if not self._demo_account_ids:
            return ()
        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            u_rows = conn.execute(
                sa.select(self._users_tbl).where(
                    self._users_tbl.c.id.in_(self._demo_account_ids),
                    self._users_tbl.c.is_active.is_(True),
                )
            ).fetchall()
            hydrated = self._hydrate_users(conn, u_rows, groups_cache)
        by_id = {u.id: du for u, _, du in hydrated}
        return tuple(by_id[did] for did in self._demo_account_ids if did in by_id)

    # ------------------------------------------------------------------
    # Group Management
    # ------------------------------------------------------------------

    def list_groups(self) -> list[IAMGroupRecord]:
        return list(self._load_groups_cache().groups_by_id.values())

    def get_group_record(self, group_id: str) -> IAMGroupRecord | None:
        return self._load_groups_cache().groups_by_id.get(group_id)

    def get_group_by_name(self, name: str) -> IAMGroupRecord | None:
        return self._load_groups_cache().groups_by_name.get(name.strip())

    def create_group(
        self,
        *,
        name: str,
        label: str = "",
        description: str = "",
        permissions: Sequence[str] | frozenset[str] = (),
        hidden_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
        readonly_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
        masked_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
        group_id: str | None = None,
    ) -> IAMGroupRecord:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Group name cannot be empty.")
        gcache = self._load_groups_cache()
        if any(grec.name.lower() == clean_name.lower() for grec in gcache.groups_by_id.values()):
            raise ValueError(f"Group '{clean_name}' already exists.")
        gid = group_id or secrets.token_hex(12)
        now = datetime.now(timezone.utc)
        perms = sorted({str(p).strip() for p in permissions if str(p).strip()})
        with self._engine.begin() as conn:
            conn.execute(
                self._groups_tbl.insert().values(
                    id=gid,
                    name=clean_name,
                    label=label.strip() or clean_name.replace("_", " ").title(),
                    description=description.strip(),
                    permissions_json=json.dumps(perms, separators=(",", ":")),
                    hidden_fields_json=_encode_field_rules(hidden_fields),
                    readonly_fields_json=_encode_field_rules(readonly_fields),
                    masked_fields_json=_encode_field_rules(masked_fields),
                    created_at=now,
                    updated_at=now,
                )
            )
        self._invalidate_cache()
        created = self.get_group_record(gid)
        assert created is not None
        return created

    def update_group(
        self,
        group_id: str,
        *,
        label: str | None = None,
        description: str | None = None,
        permissions: Sequence[str] | frozenset[str] | None = None,
        hidden_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
        readonly_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
        masked_fields: Mapping[str, Sequence[str] | frozenset[str]] | None = None,
    ) -> IAMGroupRecord:
        existing = self.get_group_record(group_id)
        if existing is None:
            raise KeyError(f"Unknown group '{group_id}'.")
        values: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
        if label is not None:
            values["label"] = label.strip() or existing.name
        if description is not None:
            values["description"] = description.strip()
        if permissions is not None:
            perms = sorted({str(p).strip() for p in permissions if str(p).strip()})
            values["permissions_json"] = json.dumps(perms, separators=(",", ":"))
        if hidden_fields is not None:
            values["hidden_fields_json"] = _encode_field_rules(hidden_fields)
        if readonly_fields is not None:
            values["readonly_fields_json"] = _encode_field_rules(readonly_fields)
        if masked_fields is not None:
            values["masked_fields_json"] = _encode_field_rules(masked_fields)
        with self._engine.begin() as conn:
            conn.execute(
                self._groups_tbl.update()
                .where(self._groups_tbl.c.id == group_id)
                .values(**values)
            )
        self._invalidate_cache()
        updated = self.get_group_record(group_id)
        assert updated is not None
        return updated

    def delete_group(self, group_id: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                self._user_groups_tbl.delete().where(self._user_groups_tbl.c.group_id == group_id)
            )
            conn.execute(self._groups_tbl.delete().where(self._groups_tbl.c.id == group_id))
        self._invalidate_cache()

    # ------------------------------------------------------------------
    # User, Direct Permission, Bulk & Password Management
    # ------------------------------------------------------------------

    def list_users(self) -> list[IAMUserRecord]:
        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            u_rows = conn.execute(
                sa.select(self._users_tbl).order_by(self._users_tbl.c.username.asc())
            ).fetchall()
            hydrated = self._hydrate_users(conn, u_rows, groups_cache)
        return [entry[0] for entry in hydrated]

    def list_users_paginated(
        self,
        *,
        q: str = "",
        status: str = "",
        group_id: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IAMUserRecord], int]:
        """SQL-filtered, paginated user query avoiding full-table memory loads."""
        safe_page = max(1, int(page))
        safe_size = max(1, min(100, int(page_size)))
        groups_cache = self._load_groups_cache()
        u = self._users_tbl
        preds: list[Any] = []

        clean_q = q.strip()[:120]
        if clean_q:
            esc = clean_q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like_pat = f"%{esc}%"
            preds.append(
                sa.or_(
                    u.c.username.ilike(like_pat, escape="\\"),
                    u.c.email.ilike(like_pat, escape="\\"),
                    u.c.display_name.ilike(like_pat, escape="\\"),
                )
            )
        st_clean = status.strip().lower()
        if st_clean == "active":
            preds.append(u.c.is_active.is_(True))
        elif st_clean == "inactive":
            preds.append(u.c.is_active.is_(False))
        elif st_clean == "superuser":
            preds.append(u.c.is_superuser.is_(True))

        clean_gid = group_id.strip()
        if clean_gid:
            ug = self._user_groups_tbl
            preds.append(
                sa.exists(
                    sa.select(sa.literal(1)).where(
                        ug.c.user_id == u.c.id,
                        ug.c.group_id == clean_gid,
                    )
                )
            )

        with self._engine.connect() as conn:
            cnt_stmt = sa.select(sa.func.count()).select_from(u)
            if preds:
                cnt_stmt = cnt_stmt.where(*preds)
            total = int(conn.execute(cnt_stmt).scalar() or 0)
            pages = max(1, (total + safe_size - 1) // safe_size)
            if safe_page > pages:
                safe_page = pages
            stmt = sa.select(u)
            if preds:
                stmt = stmt.where(*preds)
            stmt = (
                stmt.order_by(u.c.username.asc())
                .limit(safe_size)
                .offset((safe_page - 1) * safe_size)
            )
            u_rows = conn.execute(stmt).fetchall()
            hydrated = self._hydrate_users(conn, u_rows, groups_cache)
        return [entry[0] for entry in hydrated], total

    def get_user_record(self, user_id: str) -> IAMUserRecord | None:
        entry = self._fetch_user_entry_by_id(user_id)
        return entry[0] if entry is not None else None

    def get_user_by_username(self, username: str) -> IAMUserRecord | None:
        clean_u = username.strip().lower()
        if not clean_u:
            return None
        groups_cache = self._load_groups_cache()
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._users_tbl).where(
                    sa.func.lower(self._users_tbl.c.username) == clean_u
                )
            ).first()
            hydrated = self._hydrate_users(conn, [row], groups_cache) if row is not None else []
        return hydrated[0][0] if hydrated else None

    def _other_active_superusers_count(self, conn: sa.Connection, exclude_user_ids: Sequence[str]) -> int:
        u = self._users_tbl
        stmt = sa.select(sa.func.count()).select_from(u).where(
            u.c.is_active.is_(True),
            u.c.is_superuser.is_(True),
        )
        if exclude_user_ids:
            stmt = stmt.where(u.c.id.notin_(list(exclude_user_ids)))
        return int(conn.execute(stmt).scalar() or 0)

    def create_user(
        self,
        *,
        username: str,
        password: str | None = None,
        password_hash: str | None = None,
        email: str = "",
        display_name: str = "",
        is_active: bool = True,
        is_superuser: bool = False,
        group_ids: Sequence[str] = (),
        direct_permissions: Sequence[str] | frozenset[str] = (),
        tenant_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        user_id: str | None = None,
    ) -> IAMUserRecord:
        clean_username = username.strip()
        if not clean_username:
            raise ValueError("Username cannot be empty.")
        if self.get_user_by_username(clean_username) is not None:
            raise ValueError(f"User '{clean_username}' already exists.")
        if password_hash is None:
            if password is None:
                raise ValueError("Password is required.")
            pwd_errs = self._validate_pwd(
                password,
                username=clean_username,
                email=email,
                display_name=display_name,
            )
            if pwd_errs:
                raise ValueError(" ".join(pwd_errs))
            pwd_hash = generate_password_hash(password, method=DEFAULT_PASSWORD_HASH_METHOD)
        else:
            pwd_hash = password_hash

        gcache = self._load_groups_cache()
        uid = user_id or secrets.token_hex(12)
        now = datetime.now(timezone.utc)
        valid_gids = [gid for gid in dict.fromkeys(group_ids) if gid in gcache.groups_by_id]
        clean_perms = sorted({str(p).strip() for p in direct_permissions if str(p).strip()})
        with self._engine.begin() as conn:
            conn.execute(
                self._users_tbl.insert().values(
                    id=uid,
                    username=clean_username,
                    email=email.strip(),
                    display_name=display_name.strip() or clean_username,
                    password_hash=pwd_hash,
                    is_active=bool(is_active),
                    is_superuser=bool(is_superuser),
                    tenant_id=tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None,
                    metadata_json=json.dumps(dict(metadata or {}), separators=(",", ":")),
                    created_at=now,
                    updated_at=now,
                    last_login_at=None,
                )
            )
            if valid_gids:
                conn.execute(
                    self._user_groups_tbl.insert(),
                    [{"user_id": uid, "group_id": gid} for gid in valid_gids],
                )
            if clean_perms:
                conn.execute(
                    self._user_perms_tbl.insert(),
                    [{"user_id": uid, "permission": p} for p in clean_perms],
                )
        self._invalidate_cache()
        created = self.get_user_record(uid)
        assert created is not None
        return created

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        is_active: bool | None = None,
        is_superuser: bool | None = None,
        group_ids: Sequence[str] | None = None,
        direct_permissions: Sequence[str] | frozenset[str] | None = None,
        tenant_id: str | None = None,
    ) -> IAMUserRecord:
        current = self.get_user_record(user_id)
        if current is None:
            raise KeyError(f"Unknown user '{user_id}'.")
        next_active = current.is_active if is_active is None else bool(is_active)
        next_super = current.is_superuser if is_superuser is None else bool(is_superuser)
        gcache = self._load_groups_cache()

        values: dict[str, Any] = {
            "is_active": next_active,
            "is_superuser": next_super,
            "updated_at": datetime.now(timezone.utc),
        }
        if display_name is not None:
            values["display_name"] = display_name.strip() or current.username
        if email is not None:
            values["email"] = email.strip()
        if tenant_id is not None:
            values["tenant_id"] = tenant_id.strip() or None

        with self._engine.begin() as conn:
            if (
                current.is_active
                and current.is_superuser
                and (not next_active or not next_super)
                and self._other_active_superusers_count(conn, [user_id]) == 0
            ):
                raise ValueError("Cannot deactivate or demote the last active superuser.")
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == user_id)
                .values(**values)
            )
            if group_ids is not None:
                valid_gids = [gid for gid in dict.fromkeys(group_ids) if gid in gcache.groups_by_id]
                conn.execute(
                    self._user_groups_tbl.delete().where(self._user_groups_tbl.c.user_id == user_id)
                )
                if valid_gids:
                    conn.execute(
                        self._user_groups_tbl.insert(),
                        [{"user_id": user_id, "group_id": gid} for gid in valid_gids],
                    )
            if direct_permissions is not None:
                clean_perms = sorted({str(p).strip() for p in direct_permissions if str(p).strip()})
                conn.execute(
                    self._user_perms_tbl.delete().where(self._user_perms_tbl.c.user_id == user_id)
                )
                if clean_perms:
                    conn.execute(
                        self._user_perms_tbl.insert(),
                        [{"user_id": user_id, "permission": p} for p in clean_perms],
                    )
        self._invalidate_cache()
        updated = self.get_user_record(user_id)
        assert updated is not None
        return updated

    def bulk_set_active(self, user_ids: Sequence[str], *, is_active: bool) -> list[str]:
        """Atomically activate or deactivate multiple users while protecting the last active superuser."""
        clean_ids = list(dict.fromkeys(str(uid).strip() for uid in user_ids if str(uid).strip()))
        if not clean_ids:
            return []
        with self._engine.begin() as conn:
            if not is_active and self._other_active_superusers_count(conn, clean_ids) == 0:
                # Check if any selected ID is an active superuser
                sel_supers = int(
                    conn.execute(
                        sa.select(sa.func.count())
                        .select_from(self._users_tbl)
                        .where(
                            self._users_tbl.c.id.in_(clean_ids),
                            self._users_tbl.c.is_active.is_(True),
                            self._users_tbl.c.is_superuser.is_(True),
                        )
                    ).scalar()
                    or 0
                )
                if sel_supers > 0:
                    raise ValueError("Cannot deactivate the last active superuser.")
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id.in_(clean_ids))
                .values(is_active=bool(is_active), updated_at=datetime.now(timezone.utc))
            )
        self._invalidate_cache()
        return clean_ids

    def delete_user(self, user_id: str) -> None:
        current = self.get_user_record(user_id)
        if current is None:
            return
        with self._engine.begin() as conn:
            if (
                current.is_active
                and current.is_superuser
                and self._other_active_superusers_count(conn, [user_id]) == 0
            ):
                raise ValueError("Cannot delete the last active superuser.")
            conn.execute(
                self._password_resets_tbl.delete().where(self._password_resets_tbl.c.user_id == user_id)
            )
            conn.execute(
                self._user_perms_tbl.delete().where(self._user_perms_tbl.c.user_id == user_id)
            )
            conn.execute(
                self._user_groups_tbl.delete().where(self._user_groups_tbl.c.user_id == user_id)
            )
            conn.execute(self._users_tbl.delete().where(self._users_tbl.c.id == user_id))
        self._invalidate_cache()

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> tuple[bool, str]:
        entry = self._fetch_user_entry_by_id(user_id)
        stored_hash = entry[1] if entry is not None else None
        ok = verify_password_constant_time(stored_hash, current_password)
        if not ok or entry is None or not entry[0].is_active:
            return False, "Current password is incorrect."
        urec = entry[0]
        pwd_errs = self._validate_pwd(
            new_password,
            username=urec.username,
            email=urec.email,
            display_name=urec.display_name,
        )
        if pwd_errs:
            return False, " ".join(pwd_errs)
        new_hash = generate_password_hash(new_password, method=DEFAULT_PASSWORD_HASH_METHOD)
        with self._engine.begin() as conn:
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == user_id)
                .values(password_hash=new_hash, updated_at=datetime.now(timezone.utc))
            )
        self._invalidate_cache()
        return True, "Password updated successfully."

    def admin_reset_password(self, user_id: str, new_password: str) -> None:
        current = self.get_user_record(user_id)
        if current is None:
            raise KeyError(f"Unknown user '{user_id}'.")
        pwd_errs = self._validate_pwd(
            new_password,
            username=current.username,
            email=current.email,
            display_name=current.display_name,
        )
        if pwd_errs:
            raise ValueError(" ".join(pwd_errs))
        new_hash = generate_password_hash(new_password, method=DEFAULT_PASSWORD_HASH_METHOD)
        with self._engine.begin() as conn:
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == user_id)
                .values(password_hash=new_hash, updated_at=datetime.now(timezone.utc))
            )
        self._invalidate_cache()

    # ------------------------------------------------------------------
    # Opt-In Single-Use Password Reset Tokens (SHA-256 hashed at rest)
    # ------------------------------------------------------------------

    def create_password_reset_token(
        self,
        identifier: str,
        *,
        ttl_seconds: int = 900,
    ) -> tuple[IAMUserRecord, str] | None:
        """Create a single-use SHA-256-hashed reset token for an active user matching username or email."""
        clean_id = identifier.strip().lower()
        if not clean_id:
            return None
        groups_cache = self._load_groups_cache()
        u = self._users_tbl
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(u).where(
                    u.c.is_active.is_(True),
                    sa.or_(
                        sa.func.lower(u.c.username) == clean_id,
                        sa.and_(u.c.email != "", sa.func.lower(u.c.email) == clean_id),
                    ),
                )
            ).first()
            hydrated = self._hydrate_users(conn, [row], groups_cache) if row is not None else []
        if not hydrated:
            return None
        urec = hydrated[0][0]
        raw_token = secrets.token_urlsafe(32)
        tok_hash = _hash_reset_token(raw_token)
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=max(60, int(ttl_seconds)))
        with self._engine.begin() as conn:
            # Prune expired tokens & invalidate prior unused tokens for this user
            conn.execute(
                self._password_resets_tbl.delete().where(
                    sa.or_(
                        self._password_resets_tbl.c.user_id == urec.id,
                        self._password_resets_tbl.c.expires_at < now,
                    )
                )
            )
            conn.execute(
                self._password_resets_tbl.insert().values(
                    token_hash=tok_hash,
                    user_id=urec.id,
                    expires_at=exp,
                    used_at=None,
                    created_at=now,
                )
            )
        return urec, raw_token

    def verify_password_reset_token(self, raw_token: str) -> IAMUserRecord | None:
        """Return active IAMUserRecord if ``raw_token`` is valid, unused, and unexpired."""
        clean_tok = raw_token.strip()
        if not clean_tok or len(clean_tok) > 256:
            return None
        tok_hash = _hash_reset_token(clean_tok)
        now = datetime.now(timezone.utc)
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._password_resets_tbl).where(
                    self._password_resets_tbl.c.token_hash == tok_hash
                )
            ).first()
        if row is None or row.used_at is not None:
            return None
        exp = _ensure_utc(row.expires_at)
        if exp is None or exp < now:
            return None
        urec = self.get_user_record(str(row.user_id))
        if urec is None or not urec.is_active:
            return None
        return urec

    def consume_password_reset_token(
        self,
        raw_token: str,
        new_password: str,
    ) -> tuple[bool, str, IAMUserRecord | None]:
        """Atomically consume a single-use reset token and update the user's password."""
        urec = self.verify_password_reset_token(raw_token)
        if urec is None:
            return False, "This password reset link is invalid or has expired.", None
        pwd_errs = self._validate_pwd(
            new_password,
            username=urec.username,
            email=urec.email,
            display_name=urec.display_name,
        )
        if pwd_errs:
            return False, " ".join(pwd_errs), None
        tok_hash = _hash_reset_token(raw_token.strip())
        now = datetime.now(timezone.utc)
        new_hash = generate_password_hash(new_password, method=DEFAULT_PASSWORD_HASH_METHOD)
        with self._engine.begin() as conn:
            tok_row = conn.execute(
                sa.select(self._password_resets_tbl).where(
                    self._password_resets_tbl.c.token_hash == tok_hash
                )
            ).first()
            if tok_row is None or tok_row.used_at is not None:
                return False, "This password reset link has already been used.", None
            tok_exp = _ensure_utc(tok_row.expires_at)
            if tok_exp is None or tok_exp < now:
                return False, "This password reset link is invalid or has expired.", None
            res = conn.execute(
                self._password_resets_tbl.update()
                .where(
                    self._password_resets_tbl.c.token_hash == tok_hash,
                    self._password_resets_tbl.c.used_at.is_(None),
                )
                .values(used_at=now)
            )
            if res.rowcount != 1:
                return False, "This password reset link has already been used.", None
            u_res = conn.execute(
                self._users_tbl.update()
                .where(
                    self._users_tbl.c.id == urec.id,
                    self._users_tbl.c.is_active.is_(True),
                )
                .values(password_hash=new_hash, updated_at=now)
            )
            if u_res.rowcount != 1:
                return False, "This password reset link is invalid or has expired.", None
        self._invalidate_cache()
        return True, "Your password has been reset. You may now sign in.", urec

    def reset_all(self) -> None:
        """Delete all IAM users, groups, direct permissions, and reset tokens (for demo/test resets)."""
        with self._engine.begin() as conn:
            conn.execute(self._password_resets_tbl.delete())
            conn.execute(self._user_perms_tbl.delete())
            conn.execute(self._user_groups_tbl.delete())
            conn.execute(self._users_tbl.delete())
            conn.execute(self._groups_tbl.delete())
        self._invalidate_cache()


__all__ = [
    "CommonPasswordValidator",
    "ComplexityValidator",
    "IAMGroupRecord",
    "IAMUserRecord",
    "MinimumLengthValidator",
    "NumericPasswordValidator",
    "PasswordValidator",
    "SQLAlchemyAuthProvider",
    "UserAttributeSimilarityValidator",
    "validate_password_strength",
]
