from __future__ import annotations

import base64
import enum
import json
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote, unquote

from flask import Flask, g, has_app_context
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from flask_deck.exceptions import InvalidPKError
from flask_deck.introspection import FieldMeta, ModelMeta


class ORMAdapter(ABC):
    """Abstract ORM adapter supporting Flask-SQLAlchemy and pure SQLAlchemy 2.0."""

    @abstractmethod
    def get_session(self) -> Session:
        """Return the active SQLAlchemy Session for the current request."""

    @abstractmethod
    def get_engine(self) -> Engine:
        """Return the underlying primary SQLAlchemy Engine."""

    def get_engines(self) -> dict[str, Engine]:
        """Return mapping of bind_key -> Engine (default bind keyed as 'default')."""
        return {"default": self.get_engine()}

    def get_session_for_bind(self, bind_key: str | None = None) -> Session:
        """Return a Session bound to bind_key (defaults to primary request session)."""
        _ = bind_key
        return self.get_session()

    def register_teardown(self, app: Flask) -> None:
        """Optionally register request teardown hooks on the Flask app."""
        _ = app

    def dispose(self) -> None:
        """Dispose underlying SQLAlchemy engine connection pools cleanly."""
        for eng in self.get_engines().values():
            eng.dispose()


class FlaskSQLAlchemyAdapter(ORMAdapter):
    """Adapter for Flask-SQLAlchemy 3.x ``SQLAlchemy`` instances (supports multi-bind)."""

    __slots__ = ("_app", "_bind_factories", "_binds", "_db", "_dynamic_factories", "_g_key")

    def __init__(self, db: Any, *, binds: Mapping[str, Engine] | None = None) -> None:
        self._db = db
        self._app: Flask | None = getattr(db, "app", None)
        self._binds: dict[str, Engine] = dict(binds or {})
        self._bind_factories: dict[str, sessionmaker[Session]] = {
            name: sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
            for name, eng in self._binds.items()
        }
        self._dynamic_factories: dict[str, sessionmaker[Session]] = {}
        self._g_key = f"_flask_deck_fsa_session_{id(self)}"

    def get_session(self) -> Session:
        return self._db.session  # type: ignore[no-any-return]

    def get_engine(self) -> Engine:
        if not has_app_context() and self._app is not None:
            with self._app.app_context():
                return self._db.engine  # type: ignore[no-any-return]
        return self._db.engine  # type: ignore[no-any-return]

    def get_engines(self) -> dict[str, Engine]:
        if not has_app_context() and self._app is not None:
            with self._app.app_context():
                return self.get_engines()
        out: dict[str, Engine] = {}
        engines_map = getattr(self._db, "engines", None)
        if isinstance(engines_map, Mapping):
            for k, eng in engines_map.items():
                if isinstance(eng, Engine):
                    out["default" if k is None else str(k)] = eng
        if "default" not in out:
            out["default"] = self.get_engine()
        out.update(self._binds)
        return out

    def dispose(self) -> None:
        if not has_app_context() and self._app is not None:
            with self._app.app_context():
                engines = list(self.get_engines().values())
        else:
            try:
                engines = list(self.get_engines().values())
            except RuntimeError:
                engines = list(self._binds.values())
        for eng in engines:
            eng.dispose()

    def get_session_for_bind(self, bind_key: str | None = None) -> Session:
        if not bind_key or bind_key == "default":
            return self.get_session()
        factory = self._bind_factories.get(bind_key) or self._dynamic_factories.get(bind_key)
        if factory is None:
            engines = self.get_engines()
            if bind_key not in engines:
                raise KeyError(f"Unknown SQLAlchemy bind_key: {bind_key!r}")
            factory = sessionmaker(bind=engines[bind_key], autoflush=False, expire_on_commit=False)
            self._dynamic_factories[bind_key] = factory
        key = f"{self._g_key}_{bind_key}"
        existing: Session | None = getattr(g, key, None)
        if existing is None:
            existing = factory()
            setattr(g, key, existing)
        tracked: list[str] = getattr(g, f"{self._g_key}_keys", [])
        if key not in tracked:
            tracked.append(key)
            setattr(g, f"{self._g_key}_keys", tracked)
        return existing

    def register_teardown(self, app: Flask) -> None:
        self._app = app
        keys_attr = f"{self._g_key}_keys"

        @app.teardown_appcontext
        def _close_fsa_bind_sessions(exc: BaseException | None) -> None:
            tracked: list[str] = getattr(g, keys_attr, [])
            for attr in tracked:
                sess: Session | None = getattr(g, attr, None)
                if sess is not None:
                    try:
                        if exc is not None:
                            sess.rollback()
                    except Exception:
                        pass
                    finally:
                        try:
                            sess.close()
                        finally:
                            if hasattr(g, attr):
                                delattr(g, attr)
            if hasattr(g, keys_attr):
                delattr(g, keys_attr)


class PureSQLAlchemyAdapter(ORMAdapter):
    """Adapter for pure SQLAlchemy 2.0 ``sessionmaker`` or ``Engine`` (supports multi-bind)."""

    __slots__ = ("_bind_factories", "_binds", "_engine", "_g_key", "_session_factory")

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session] | Callable[[], Session] | None = None,
        engine: Engine | None = None,
        binds: Mapping[str, Engine] | None = None,
    ) -> None:
        if session_factory is None and engine is None:
            raise ValueError("Provide either session_factory or engine for PureSQLAlchemyAdapter")
        if session_factory is None:
            assert engine is not None
            session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        self._session_factory = session_factory
        self._engine = engine or getattr(session_factory, "kw", {}).get("bind")
        self._binds: dict[str, Engine] = dict(binds or {})
        self._bind_factories: dict[str, sessionmaker[Session]] = {
            name: sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
            for name, eng in self._binds.items()
        }
        self._g_key = f"_flask_deck_sa_session_{id(self)}"

    def get_session(self) -> Session:
        existing: Session | None = getattr(g, self._g_key, None)
        if existing is None:
            existing = self._session_factory()
            setattr(g, self._g_key, existing)
        return existing

    def get_session_for_bind(self, bind_key: str | None = None) -> Session:
        if not bind_key or bind_key == "default":
            return self.get_session()
        if bind_key not in self._bind_factories:
            raise KeyError(f"Unknown SQLAlchemy bind_key: {bind_key!r}")
        key = f"{self._g_key}_{bind_key}"
        existing: Session | None = getattr(g, key, None)
        if existing is None:
            existing = self._bind_factories[bind_key]()
            setattr(g, key, existing)
        return existing

    def get_engine(self) -> Engine:
        if self._engine is not None:
            return self._engine
        sess = self.get_session()
        bind = sess.get_bind()
        if isinstance(bind, Engine):
            self._engine = bind
            return bind
        return bind.engine

    def get_engines(self) -> dict[str, Engine]:
        out: dict[str, Engine] = {"default": self.get_engine()}
        out.update(self._binds)
        return out

    def register_teardown(self, app: Flask) -> None:
        g_key = self._g_key
        bind_keys = tuple(self._bind_factories.keys())

        @app.teardown_appcontext
        def _close_deck_session(exc: BaseException | None) -> None:
            for attr in (g_key, *(f"{g_key}_{bk}" for bk in bind_keys)):
                sess: Session | None = getattr(g, attr, None)
                if sess is not None:
                    try:
                        if exc is not None:
                            sess.rollback()
                    except Exception:
                        pass
                    finally:
                        try:
                            sess.close()
                        finally:
                            if hasattr(g, attr):
                                delattr(g, attr)


def resolve_adapter(
    db: Any | None = None,
    *,
    session_factory: sessionmaker[Session] | Callable[[], Session] | None = None,
    engine: Engine | None = None,
    binds: Mapping[str, Engine] | None = None,
) -> ORMAdapter:
    """Resolve Flask-SQLAlchemy, ORMAdapter, sessionmaker, or Engine into an ORMAdapter."""
    if isinstance(db, ORMAdapter):
        return db
    if db is not None:
        if isinstance(db, Engine):
            return PureSQLAlchemyAdapter(engine=db, binds=binds)
        if callable(db):
            return PureSQLAlchemyAdapter(session_factory=db, engine=engine, binds=binds)
        # Detect Flask-SQLAlchemy without invoking its @property `engine` outside app context.
        db_cls = type(db)
        if hasattr(db, "session") and (hasattr(db_cls, "engine") or hasattr(db, "Model")):
            return FlaskSQLAlchemyAdapter(db, binds=binds)
        raise TypeError(
            "Unsupported db argument. Pass a Flask-SQLAlchemy instance, "
            "SQLAlchemy sessionmaker, Engine, or ORMAdapter."
        )
    return PureSQLAlchemyAdapter(session_factory=session_factory, engine=engine, binds=binds)


_PK_INT64_MIN = -(1 << 63)
_PK_INT64_MAX = (1 << 63) - 1


def coerce_pk_value(raw: Any, field: FieldMeta) -> Any:
    """Strictly coerce a primary key segment to its declared Python type."""
    if raw is None or raw == "":
        raise InvalidPKError(f"Empty primary key for {field.name}")
    try:
        if field.field_type == "integer":
            if isinstance(raw, bool):
                raise InvalidPKError(f"Invalid integer PK: {raw!r}")
            iv = int(raw)
            if iv < _PK_INT64_MIN or iv > _PK_INT64_MAX:
                raise InvalidPKError(f"Integer PK out of 64-bit range: {raw!r}")
            return iv
        if field.field_type == "uuid":
            return raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(raw))
        if field.field_type == "enum" and field.enum_class is not None:
            if isinstance(raw, field.enum_class):
                return raw
            s = str(raw)
            try:
                return field.enum_class(s)
            except ValueError:
                return field.enum_class[s]
        if field.field_type == "date":
            return raw if isinstance(raw, date) and not isinstance(raw, datetime) else date.fromisoformat(str(raw))
        if field.field_type == "datetime":
            return raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw))
        if field.field_type == "decimal":
            val = raw if isinstance(raw, Decimal) else Decimal(str(raw))
            if not val.is_finite():
                raise InvalidPKError(f"Non-finite decimal PK: {raw!r}")
            return val
        if field.python_type is int:
            iv = int(raw)
            if iv < _PK_INT64_MIN or iv > _PK_INT64_MAX:
                raise InvalidPKError(f"Integer PK out of 64-bit range: {raw!r}")
            return iv
        return str(raw)
    except InvalidPKError:
        raise
    except (TypeError, ValueError, KeyError, InvalidOperation) as exc:
        raise InvalidPKError(f"Invalid primary key value for {field.name}: {raw!r}") from exc


def extract_pk(obj: Any, meta: ModelMeta) -> tuple[Any, ...]:
    """Extract primary key values tuple from an ORM instance."""
    return tuple(getattr(obj, pk.name) for pk in meta.primary_keys)


def _pk_part_to_str(val: Any) -> str:
    if isinstance(val, enum.Enum):
        return str(val.value)
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    return str(val)


def encode_pk(values: tuple[Any, ...]) -> str:
    """Encode single or composite primary key values into a URL-safe string."""
    if len(values) == 1:
        text = _pk_part_to_str(values[0])
        if "/" in text or "," in text or text.startswith(("pk:", "ck:")):
            return f"pk:{quote(text, safe='')}"
        return text
    serialized = json.dumps([_pk_part_to_str(v) for v in values], separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(serialized).decode("ascii").rstrip("=")
    return f"ck:{encoded}"


def decode_pk(raw: str, meta: ModelMeta) -> tuple[Any, ...]:
    """Decode and strictly coerce a URL primary key segment back to typed tuple."""
    if not raw:
        raise InvalidPKError("Primary key cannot be empty")
    if len(meta.primary_keys) == 1:
        val = unquote(raw[3:]) if raw.startswith("pk:") else raw
        return (coerce_pk_value(val, meta.primary_keys[0]),)

    if not raw.startswith("ck:"):
        raise InvalidPKError("Malformed composite primary key")
    payload = raw[3:]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        parts = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise InvalidPKError("Malformed composite primary key payload") from exc

    if not isinstance(parts, list) or len(parts) != len(meta.primary_keys):
        raise InvalidPKError("Composite primary key arity mismatch")

    return tuple(
        coerce_pk_value(part, pk_field)
        for part, pk_field in zip(parts, meta.primary_keys, strict=True)
    )
