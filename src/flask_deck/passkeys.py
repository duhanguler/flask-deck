from __future__ import annotations

import base64
import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

PASSKEY_REG_CHALLENGE_KEY = "_deck_pk_reg_challenge"
PASSKEY_AUTH_CHALLENGE_KEY = "_deck_pk_auth_challenge"


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _import_webauthn() -> Any:
    try:
        import webauthn  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "webauthn package is required for Passkey support. "
            "Install with: pip install 'flask-deck[webauthn]'"
        ) from exc
    return webauthn


def is_webauthn_available() -> bool:
    try:
        _import_webauthn()
        return True
    except RuntimeError:
        return False


@dataclass(slots=True)
class PasskeyCredential:
    """Registered FIDO2 / WebAuthn passkey credential attached to a DeckUser."""

    credential_id: str  # base64url encoded
    user_id: str
    label: str
    public_key_b64: str
    sign_count: int = 0
    transports: tuple[str, ...] = ()
    created_at: datetime | None = None
    last_used_at: datetime | None = None


@runtime_checkable
class PasskeyStore(Protocol):
    """Persistence contract for WebAuthn / FIDO2 user credentials."""

    def add(self, cred: PasskeyCredential) -> PasskeyCredential: ...

    def get(self, credential_id: str) -> PasskeyCredential | None: ...

    def list_for_user(self, user_id: str) -> list[PasskeyCredential]: ...

    def update_sign_count(self, credential_id: str, sign_count: int) -> None: ...

    def delete(self, credential_id: str, *, user_id: str | None = None) -> bool: ...


class InMemoryPasskeyStore:
    """Thread-safe in-memory WebAuthn credential store."""

    __slots__ = ("_creds", "_lock")

    def __init__(self) -> None:
        self._creds: dict[str, PasskeyCredential] = {}
        self._lock = threading.Lock()

    def add(self, cred: PasskeyCredential) -> PasskeyCredential:
        now = cred.created_at or datetime.now(timezone.utc)
        stored = replace(cred, created_at=now)
        with self._lock:
            self._creds[stored.credential_id] = stored
        return replace(stored)

    def get(self, credential_id: str) -> PasskeyCredential | None:
        with self._lock:
            rec = self._creds.get(credential_id)
            return replace(rec) if rec is not None else None

    def list_for_user(self, user_id: str) -> list[PasskeyCredential]:
        with self._lock:
            return [replace(c) for c in self._creds.values() if c.user_id == user_id]

    def update_sign_count(self, credential_id: str, sign_count: int) -> None:
        with self._lock:
            rec = self._creds.get(credential_id)
            if rec is not None:
                rec.sign_count = int(sign_count)
                rec.last_used_at = datetime.now(timezone.utc)

    def delete(self, credential_id: str, *, user_id: str | None = None) -> bool:
        with self._lock:
            rec = self._creds.get(credential_id)
            if rec is None:
                return False
            if user_id is not None and rec.user_id != user_id:
                return False
            self._creds.pop(credential_id, None)
            return True


class SQLAlchemyPasskeyStore:
    """Persistent SQLAlchemy WebAuthn credential store (`_flask_deck_passkeys`)."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "_flask_deck_passkeys",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("credential_id", sa.String(512), primary_key=True),
            sa.Column("user_id", sa.String(128), nullable=False, index=True),
            sa.Column("label", sa.String(128), nullable=False),
            sa.Column("public_key_b64", sa.Text, nullable=False),
            sa.Column("sign_count", sa.Integer, nullable=False, default=0),
            sa.Column("transports_json", sa.Text, nullable=False, default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_cred(row: Any) -> PasskeyCredential:
        try:
            trans = tuple(str(t) for t in json.loads(row.transports_json or "[]"))
        except Exception:
            trans = ()
        return PasskeyCredential(
            credential_id=str(row.credential_id),
            user_id=str(row.user_id),
            label=str(row.label),
            public_key_b64=str(row.public_key_b64),
            sign_count=int(row.sign_count or 0),
            transports=trans,
            created_at=_ensure_utc(row.created_at),
            last_used_at=_ensure_utc(row.last_used_at),
        )

    def add(self, cred: PasskeyCredential) -> PasskeyCredential:
        now = cred.created_at or datetime.now(timezone.utc)
        with Session(self._engine) as sess:
            sess.execute(
                self._table.delete().where(self._table.c.credential_id == cred.credential_id)
            )
            sess.execute(
                self._table.insert().values(
                    credential_id=cred.credential_id,
                    user_id=cred.user_id,
                    label=cred.label[:128],
                    public_key_b64=cred.public_key_b64,
                    sign_count=int(cred.sign_count),
                    transports_json=json.dumps(list(cred.transports)),
                    created_at=now,
                    last_used_at=cred.last_used_at,
                )
            )
            sess.commit()
        return replace(cred, created_at=now)

    def get(self, credential_id: str) -> PasskeyCredential | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.credential_id == credential_id)
            ).first()
            return self._row_to_cred(row) if row is not None else None

    def list_for_user(self, user_id: str) -> list[PasskeyCredential]:
        with Session(self._engine) as sess:
            rows = sess.execute(
                sa.select(self._table)
                .where(self._table.c.user_id == user_id)
                .order_by(self._table.c.created_at.desc())
            )
            return [self._row_to_cred(r) for r in rows]

    def update_sign_count(self, credential_id: str, sign_count: int) -> None:
        now = datetime.now(timezone.utc)
        with Session(self._engine) as sess:
            sess.execute(
                self._table.update()
                .where(self._table.c.credential_id == credential_id)
                .values(sign_count=int(sign_count), last_used_at=now)
            )
            sess.commit()

    def delete(self, credential_id: str, *, user_id: str | None = None) -> bool:
        conds: list[Any] = [self._table.c.credential_id == credential_id]
        if user_id is not None:
            conds.append(self._table.c.user_id == user_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.delete().where(*conds))
            sess.commit()
            return bool((getattr(res, "rowcount", 0) or 0) > 0)


def begin_passkey_registration(
    *,
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    exclude_credentials: Sequence[PasskeyCredential] = (),
) -> tuple[dict[str, Any], str]:
    """Generate WebAuthn registration options JSON and base64url challenge."""
    wa = _import_webauthn()
    opts = wa.generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id.encode("utf-8"),
        user_name=user_name,
        exclude_credentials=[],
    )
    opts_json = json.loads(wa.options_to_json(opts))
    challenge_b64 = str(opts_json["challenge"])
    return opts_json, challenge_b64


def complete_passkey_registration(
    *,
    credential_json: Any,
    expected_challenge_b64: str,
    expected_origin: str,
    expected_rp_id: str,
    user_id: str,
    label: str = "Passkey",
) -> PasskeyCredential:
    """Verify WebAuthn registration response and return PasskeyCredential to persist."""
    wa = _import_webauthn()
    pad = "=" * (-len(expected_challenge_b64) % 4)
    raw_challenge = base64.urlsafe_b64decode(expected_challenge_b64 + pad)
    verification = wa.verify_registration_response(
        credential=credential_json,
        expected_challenge=raw_challenge,
        expected_origin=expected_origin,
        expected_rp_id=expected_rp_id,
    )
    cred_id_b64 = base64.urlsafe_b64encode(verification.credential_id).decode("ascii").rstrip("=")
    pub_b64 = (
        base64.urlsafe_b64encode(verification.credential_public_key).decode("ascii").rstrip("=")
    )
    return PasskeyCredential(
        credential_id=cred_id_b64,
        user_id=user_id,
        label=label,
        public_key_b64=pub_b64,
        sign_count=int(getattr(verification, "sign_count", 0)),
        created_at=datetime.now(timezone.utc),
    )


def begin_passkey_authentication(
    *,
    rp_id: str,
    allow_credentials: Sequence[PasskeyCredential] = (),
) -> tuple[dict[str, Any], str]:
    """Generate WebAuthn authentication options JSON and base64url challenge."""
    wa = _import_webauthn()
    opts = wa.generate_authentication_options(rp_id=rp_id)
    opts_json = json.loads(wa.options_to_json(opts))
    challenge_b64 = str(opts_json["challenge"])
    return opts_json, challenge_b64


def complete_passkey_authentication(
    *,
    credential_json: Any,
    expected_challenge_b64: str,
    expected_origin: str,
    expected_rp_id: str,
    stored: PasskeyCredential,
) -> int:
    """Verify WebAuthn assertion and return updated sign_count."""
    wa = _import_webauthn()
    c_pad = "=" * (-len(expected_challenge_b64) % 4)
    p_pad = "=" * (-len(stored.public_key_b64) % 4)
    raw_challenge = base64.urlsafe_b64decode(expected_challenge_b64 + c_pad)
    raw_pub = base64.urlsafe_b64decode(stored.public_key_b64 + p_pad)
    verification = wa.verify_authentication_response(
        credential=credential_json,
        expected_challenge=raw_challenge,
        expected_origin=expected_origin,
        expected_rp_id=expected_rp_id,
        credential_public_key=raw_pub,
        credential_current_sign_count=stored.sign_count,
    )
    return int(getattr(verification, "new_sign_count", stored.sign_count + 1))
