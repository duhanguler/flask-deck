from __future__ import annotations

import json
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from flask import g, has_request_context
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash

from flask_deck.auth import AuthProvider, DeckUser, Role, collect_role_field_rule
from flask_deck.security import DEFAULT_PASSWORD_HASH_METHOD, verify_password_constant_time


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
        )


@dataclass(slots=True)
class _IAMSnapshot:
    users_by_id: dict[str, tuple[IAMUserRecord, str, DeckUser]]
    uid_by_username: dict[str, str]
    groups_by_id: dict[str, IAMGroupRecord]
    groups_by_name: dict[str, IAMGroupRecord]
    roles_by_name: dict[str, Role]


class SQLAlchemyAuthProvider(AuthProvider):
    """Optional DB-backed 4-level RBAC provider with runtime user, group, and password management."""

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
        demo_account_ids: Sequence[str] = (),
        auto_create_tables: bool = True,
    ) -> None:
        self._engine = engine
        self._password_min_length = max(4, password_min_length)
        self._demo_account_ids = tuple(str(x) for x in demo_account_ids)
        self._cache_attr = f"_deck_iam_snap_{id(self)}"
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
        if auto_create_tables:
            self._meta.create_all(engine, checkfirst=True)

    def _invalidate_cache(self) -> None:
        if has_request_context() and hasattr(g, self._cache_attr):
            delattr(g, self._cache_attr)

    def _load_snapshot(self) -> _IAMSnapshot:
        if has_request_context():
            cached = getattr(g, self._cache_attr, None)
            if isinstance(cached, _IAMSnapshot):
                return cached

        with self._engine.connect() as conn:
            g_rows = conn.execute(
                sa.select(self._groups_tbl).order_by(self._groups_tbl.c.name.asc())
            ).fetchall()
            u_rows = conn.execute(
                sa.select(self._users_tbl).order_by(self._users_tbl.c.username.asc())
            ).fetchall()
            ug_rows = conn.execute(sa.select(self._user_groups_tbl)).fetchall()

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

        ug_map: dict[str, list[str]] = {}
        for link in ug_rows:
            if str(link.group_id) in groups_by_id:
                ug_map.setdefault(str(link.user_id), []).append(str(link.group_id))

        users_by_id: dict[str, tuple[IAMUserRecord, str, DeckUser]] = {}
        uid_by_username: dict[str, str] = {}
        for r in u_rows:
            uid = str(r.id)
            gids = tuple(ug_map.get(uid, ()))
            rnames = tuple(groups_by_id[gid].name for gid in gids if gid in groups_by_id)
            urec = IAMUserRecord(
                id=uid,
                username=str(r.username),
                email=str(r.email or ""),
                display_name=str(r.display_name or r.username),
                is_active=bool(r.is_active),
                is_superuser=bool(r.is_superuser),
                group_ids=gids,
                role_names=rnames,
                tenant_id=str(r.tenant_id) if r.tenant_id is not None else None,
                metadata=_decode_json_dict(r.metadata_json),
                created_at=_ensure_utc(r.created_at) or now,
                updated_at=_ensure_utc(r.updated_at) or now,
                last_login_at=_ensure_utc(r.last_login_at),
            )
            users_by_id[uid] = (urec, str(r.password_hash), urec.to_deck_user())
            uid_by_username[urec.username.strip().lower()] = uid

        snap = _IAMSnapshot(
            users_by_id=users_by_id,
            uid_by_username=uid_by_username,
            groups_by_id=groups_by_id,
            groups_by_name=groups_by_name,
            roles_by_name=roles_by_name,
        )
        if has_request_context():
            setattr(g, self._cache_attr, snap)
        return snap

    # ------------------------------------------------------------------
    # AuthProvider Contract
    # ------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> DeckUser | None:
        snap = self._load_snapshot()
        uid = snap.uid_by_username.get(username.strip().lower())
        entry = snap.users_by_id.get(uid) if uid is not None else None
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
        snap = self._load_snapshot()
        entry = snap.users_by_id.get(user_id)
        if entry is None or not entry[0].is_active:
            return None
        return entry[2]

    def _user_roles(self, user: DeckUser | None) -> list[Role]:
        if user is None:
            return []
        snap = self._load_snapshot()
        return [snap.roles_by_name[r] for r in user.roles if r in snap.roles_by_name]

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
        return any(role.grants(permission) for role in self._user_roles(user))

    def hidden_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "hidden_fields")

    def readonly_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "readonly_fields")

    def masked_fields_for(self, user: DeckUser | None, model_slug: str) -> frozenset[str]:
        return collect_role_field_rule(self._user_roles(user), user, model_slug, "masked_fields")

    def get_roles(self) -> Sequence[Role]:
        snap = self._load_snapshot()
        return tuple(snap.roles_by_name.values())

    def get_user_by_id(self, user_id: str) -> DeckUser | None:
        entry = self._load_snapshot().users_by_id.get(user_id)
        if entry is None or not entry[0].is_active:
            return None
        return entry[2]

    def get_impersonatable_users(self, actor: DeckUser) -> Sequence[DeckUser]:
        if not actor.is_superuser:
            return ()
        snap = self._load_snapshot()
        return tuple(
            du
            for urec, _, du in snap.users_by_id.values()
            if urec.is_active and not urec.is_superuser and urec.id != actor.id
        )

    def get_demo_accounts(self) -> Sequence[DeckUser]:
        if not self._demo_account_ids:
            return ()
        snap = self._load_snapshot()
        out: list[DeckUser] = []
        for did in self._demo_account_ids:
            entry = snap.users_by_id.get(did)
            if entry is not None and entry[0].is_active:
                out.append(entry[2])
        return tuple(out)

    # ------------------------------------------------------------------
    # Group Management
    # ------------------------------------------------------------------

    def list_groups(self) -> list[IAMGroupRecord]:
        return list(self._load_snapshot().groups_by_id.values())

    def get_group_record(self, group_id: str) -> IAMGroupRecord | None:
        return self._load_snapshot().groups_by_id.get(group_id)

    def get_group_by_name(self, name: str) -> IAMGroupRecord | None:
        return self._load_snapshot().groups_by_name.get(name.strip())

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
        snap = self._load_snapshot()
        if any(grec.name.lower() == clean_name.lower() for grec in snap.groups_by_id.values()):
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
    # User & Password Management
    # ------------------------------------------------------------------

    def list_users(self) -> list[IAMUserRecord]:
        return [entry[0] for entry in self._load_snapshot().users_by_id.values()]

    def get_user_record(self, user_id: str) -> IAMUserRecord | None:
        entry = self._load_snapshot().users_by_id.get(user_id)
        return entry[0] if entry is not None else None

    def _other_active_superusers(self, snap: _IAMSnapshot, exclude_user_id: str) -> int:
        return sum(
            1
            for urec, _, _ in snap.users_by_id.values()
            if urec.id != exclude_user_id and urec.is_active and urec.is_superuser
        )

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
        tenant_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        user_id: str | None = None,
    ) -> IAMUserRecord:
        clean_username = username.strip()
        if not clean_username:
            raise ValueError("Username cannot be empty.")
        snap = self._load_snapshot()
        if clean_username.lower() in snap.uid_by_username:
            raise ValueError(f"User '{clean_username}' already exists.")
        if password_hash is None:
            if password is None:
                raise ValueError("Password is required.")
            if len(password) < self._password_min_length:
                raise ValueError(
                    f"Password must be at least {self._password_min_length} characters."
                )
            pwd_hash = generate_password_hash(password, method=DEFAULT_PASSWORD_HASH_METHOD)
        else:
            pwd_hash = password_hash

        uid = user_id or secrets.token_hex(12)
        now = datetime.now(timezone.utc)
        valid_gids = [gid for gid in dict.fromkeys(group_ids) if gid in snap.groups_by_id]
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
        tenant_id: str | None = None,
    ) -> IAMUserRecord:
        snap = self._load_snapshot()
        entry = snap.users_by_id.get(user_id)
        if entry is None:
            raise KeyError(f"Unknown user '{user_id}'.")
        current = entry[0]
        next_active = current.is_active if is_active is None else bool(is_active)
        next_super = current.is_superuser if is_superuser is None else bool(is_superuser)
        if (
            current.is_active
            and current.is_superuser
            and (not next_active or not next_super)
            and self._other_active_superusers(snap, user_id) == 0
        ):
            raise ValueError("Cannot deactivate or demote the last active superuser.")

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
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == user_id)
                .values(**values)
            )
            if group_ids is not None:
                valid_gids = [gid for gid in dict.fromkeys(group_ids) if gid in snap.groups_by_id]
                conn.execute(
                    self._user_groups_tbl.delete().where(self._user_groups_tbl.c.user_id == user_id)
                )
                if valid_gids:
                    conn.execute(
                        self._user_groups_tbl.insert(),
                        [{"user_id": user_id, "group_id": gid} for gid in valid_gids],
                    )
        self._invalidate_cache()
        updated = self.get_user_record(user_id)
        assert updated is not None
        return updated

    def delete_user(self, user_id: str) -> None:
        snap = self._load_snapshot()
        entry = snap.users_by_id.get(user_id)
        if entry is None:
            return
        current = entry[0]
        if (
            current.is_active
            and current.is_superuser
            and self._other_active_superusers(snap, user_id) == 0
        ):
            raise ValueError("Cannot delete the last active superuser.")
        with self._engine.begin() as conn:
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
        if len(new_password) < self._password_min_length:
            return False, f"New password must be at least {self._password_min_length} characters."
        snap = self._load_snapshot()
        entry = snap.users_by_id.get(user_id)
        stored_hash = entry[1] if entry is not None else None
        ok = verify_password_constant_time(stored_hash, current_password)
        if not ok or entry is None or not entry[0].is_active:
            return False, "Current password is incorrect."
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
        if len(new_password) < self._password_min_length:
            raise ValueError(
                f"Password must be at least {self._password_min_length} characters."
            )
        snap = self._load_snapshot()
        if user_id not in snap.users_by_id:
            raise KeyError(f"Unknown user '{user_id}'.")
        new_hash = generate_password_hash(new_password, method=DEFAULT_PASSWORD_HASH_METHOD)
        with self._engine.begin() as conn:
            conn.execute(
                self._users_tbl.update()
                .where(self._users_tbl.c.id == user_id)
                .values(password_hash=new_hash, updated_at=datetime.now(timezone.utc))
            )
        self._invalidate_cache()

    def reset_all(self) -> None:
        """Delete all IAM users, groups, and memberships (for demo/test resets)."""
        with self._engine.begin() as conn:
            conn.execute(self._user_groups_tbl.delete())
            conn.execute(self._users_tbl.delete())
            conn.execute(self._groups_tbl.delete())
        self._invalidate_cache()


__all__ = [
    "IAMGroupRecord",
    "IAMUserRecord",
    "SQLAlchemyAuthProvider",
]
