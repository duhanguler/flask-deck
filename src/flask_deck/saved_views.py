from __future__ import annotations

import re
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

import sqlalchemy as sa
from markupsafe import Markup, escape
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

SavedViewScope = Literal["personal", "team", "role"]

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_RE = re.compile(r"\*([^*]+)\*")
_CODE_RE = re.compile(r"`([^`]+)`")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _is_safe_note_href(raw_url: str) -> bool:
    u = raw_url.strip()
    if not u or "\\" in u or any(ord(ch) < 32 or ord(ch) == 127 for ch in u):
        return False
    low = u.lower()
    if low.startswith("/") and not low.startswith("//"):
        return True
    return low.startswith(("https://", "http://"))


def render_safe_markdown(raw_text: str) -> Markup:
    """Zero-dependency strict-CSP safe subset markdown renderer for record notes."""
    escaped = str(escape(raw_text or ""))

    def _format_inline(text: str) -> str:
        t = _CODE_RE.sub(r'<code class="dk-code">\1</code>', text)
        t = _BOLD_RE.sub(r"<strong>\1</strong>", t)
        return _ITALIC_RE.sub(r"<em>\1</em>", t)

    rendered_lines: list[str] = []
    for line in escaped.splitlines():
        item = line
        bullet = False
        if item.startswith("- ") or item.startswith("* "):
            bullet = True
            item = item[2:]
        # Protect generated <a> links with placeholders so inline formatting never mutates href=""
        anchors: list[str] = []

        def _replace_link(match: re.Match[str], _anchors: list[str] = anchors) -> str:
            label, url = match.group(1), match.group(2)
            if not _is_safe_note_href(url):
                return f"{label} ({url})"
            idx = len(_anchors)
            safe_label = _format_inline(label)
            _anchors.append(
                f'<a href="{url}" rel="noopener noreferrer" target="_blank">{safe_label}</a>'
            )
            return f"\x00DECKLINK{idx}\x00"

        item = _LINK_RE.sub(_replace_link, item)
        item = _format_inline(item)
        for idx, anchor_html in enumerate(anchors):
            item = item.replace(f"\x00DECKLINK{idx}\x00", anchor_html)
        if bullet:
            rendered_lines.append(f"• {item}")
        else:
            rendered_lines.append(item)
    return Markup("<br>".join(rendered_lines))


@dataclass(slots=True)
class SavedViewRecord:
    """Saved filter view scoped to personal operator, shared team, or default role."""

    id: str
    model_slug: str
    name: str
    query_string: str
    scope: SavedViewScope = "personal"
    owner_id: str = ""
    owner_name: str = ""
    default_for_role: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class SavedViewStore(Protocol):
    """Persistence contract for personal, team, and role-default saved views."""

    def list_for_model(
        self,
        model_slug: str,
        *,
        user_id: str,
        roles: Sequence[str] = (),
    ) -> list[SavedViewRecord]: ...

    def get(self, view_id: str) -> SavedViewRecord | None: ...

    def create(self, rec: SavedViewRecord) -> SavedViewRecord: ...

    def delete(
        self, view_id: str, *, actor_id: str, is_superuser: bool = False
    ) -> bool: ...


class InMemorySavedViewStore:
    """Thread-safe in-memory store for shared saved views."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, SavedViewRecord] = {}
        self._lock = threading.Lock()

    def list_for_model(
        self,
        model_slug: str,
        *,
        user_id: str,
        roles: Sequence[str] = (),
    ) -> list[SavedViewRecord]:
        role_set = set(roles)
        with self._lock:
            items = list(self._records.values())
        out = [
            replace(r)
            for r in items
            if r.model_slug == model_slug
            and (
                r.scope == "team"
                or (r.scope == "role" and (r.default_for_role in role_set or r.owner_id == user_id))
                or (r.scope == "personal" and r.owner_id == user_id)
            )
        ]
        epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        out.sort(
            key=lambda r: (
                0 if r.scope == "role" else (1 if r.scope == "team" else 2),
                _ensure_utc(r.created_at) or epoch,
            )
        )
        return out

    def get(self, view_id: str) -> SavedViewRecord | None:
        with self._lock:
            rec = self._records.get(view_id)
            return replace(rec) if rec is not None else None

    def create(self, rec: SavedViewRecord) -> SavedViewRecord:
        stored = replace(rec, id=rec.id or uuid.uuid4().hex[:16])
        with self._lock:
            self._records[stored.id] = stored
        return replace(stored)

    def delete(self, view_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        with self._lock:
            rec = self._records.get(view_id)
            if rec is None:
                return False
            if not is_superuser and rec.owner_id != actor_id:
                return False
            self._records.pop(view_id, None)
            return True


class SQLAlchemySavedViewStore:
    """Persistent SQLAlchemy store for personal, team, and role saved views (`deck_saved_views`)."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "deck_saved_views",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("model_slug", sa.String(128), nullable=False, index=True),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("query_string", sa.Text, nullable=False),
            sa.Column("scope", sa.String(16), nullable=False, default="personal"),
            sa.Column("owner_id", sa.String(128), nullable=False, index=True),
            sa.Column("owner_name", sa.String(128), nullable=False),
            sa.Column("default_for_role", sa.String(64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        self._meta.create_all(engine, checkfirst=True)
        self._lock = threading.Lock()
        self._model_cache: dict[str, tuple[float, tuple[SavedViewRecord, ...]]] = {}

    @staticmethod
    def _row_to_rec(row: Any) -> SavedViewRecord:
        now = datetime.now(timezone.utc)
        return SavedViewRecord(
            id=str(row.id),
            model_slug=str(row.model_slug),
            name=str(row.name),
            query_string=str(row.query_string),
            scope=row.scope,
            owner_id=str(row.owner_id),
            owner_name=str(row.owner_name),
            default_for_role=str(row.default_for_role) if row.default_for_role else None,
            created_at=_ensure_utc(row.created_at) or now,
        )

    def list_for_model(
        self,
        model_slug: str,
        *,
        user_id: str,
        roles: Sequence[str] = (),
    ) -> list[SavedViewRecord]:
        now = time.monotonic()
        cached_rows: tuple[SavedViewRecord, ...] | None = None
        with self._lock:
            hit = self._model_cache.get(model_slug)
            if hit is not None and (now - hit[0]) < 2.0:
                cached_rows = hit[1]
        if cached_rows is None:
            stmt = (
                sa.select(self._table)
                .where(self._table.c.model_slug == model_slug)
                .order_by(self._table.c.created_at.asc())
            )
            with Session(self._engine) as sess:
                loaded = tuple(self._row_to_rec(r) for r in sess.execute(stmt))
            with self._lock:
                if len(self._model_cache) >= 256:
                    self._model_cache.clear()
                self._model_cache[model_slug] = (time.monotonic(), loaded)
            cached_rows = loaded

        role_set = set(roles)
        epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        out = [
            replace(r)
            for r in cached_rows
            if (
                r.scope == "team"
                or (r.scope == "role" and (r.default_for_role in role_set or r.owner_id == user_id))
                or (r.scope == "personal" and r.owner_id == user_id)
            )
        ]
        out.sort(
            key=lambda r: (
                0 if r.scope == "role" else (1 if r.scope == "team" else 2),
                _ensure_utc(r.created_at) or epoch,
            )
        )
        return out

    def get(self, view_id: str) -> SavedViewRecord | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == view_id)
            ).first()
            return self._row_to_rec(row) if row is not None else None

    def create(self, rec: SavedViewRecord) -> SavedViewRecord:
        now = rec.created_at or datetime.now(timezone.utc)
        rid = rec.id or uuid.uuid4().hex[:16]
        with Session(self._engine) as sess:
            sess.execute(
                self._table.insert().values(
                    id=rid,
                    model_slug=rec.model_slug[:128],
                    name=rec.name[:120],
                    query_string=rec.query_string,
                    scope=rec.scope,
                    owner_id=rec.owner_id[:128],
                    owner_name=rec.owner_name[:128],
                    default_for_role=rec.default_for_role[:64] if rec.default_for_role else None,
                    created_at=now,
                )
            )
            sess.commit()
        with self._lock:
            self._model_cache.pop(rec.model_slug, None)
        return replace(rec, id=rid, created_at=now)

    def delete(self, view_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        conds: list[Any] = [self._table.c.id == view_id]
        if not is_superuser:
            conds.append(self._table.c.owner_id == actor_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.delete().where(*conds))
            sess.commit()
            deleted = bool((getattr(res, "rowcount", 0) or 0) > 0)
        if deleted:
            with self._lock:
                self._model_cache.clear()
        return deleted


@dataclass(slots=True)
class RecordNote:
    """Internal operational comment or pinned warning attached to one model record."""

    id: str
    model_slug: str
    record_pk: str
    author_id: str
    author_name: str
    body: str
    pinned: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class RecordNoteStore(Protocol):
    """Persistence contract for per-record operational notes."""

    def list_notes(
        self, model_slug: str, record_pk: str, *, limit: int = 100
    ) -> list[RecordNote]: ...

    def get(self, note_id: str) -> RecordNote | None: ...

    def add(self, note: RecordNote) -> RecordNote: ...

    def toggle_pin(
        self,
        note_id: str,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
    ) -> RecordNote | None: ...

    def delete(
        self, note_id: str, *, actor_id: str, is_superuser: bool = False
    ) -> bool: ...


class InMemoryRecordNoteStore:
    """Thread-safe in-memory per-record operational note store."""

    __slots__ = ("_lock", "_notes")

    def __init__(self) -> None:
        self._notes: dict[str, RecordNote] = {}
        self._lock = threading.Lock()

    def list_notes(
        self, model_slug: str, record_pk: str, *, limit: int = 100
    ) -> list[RecordNote]:
        with self._lock:
            items = [
                replace(n)
                for n in self._notes.values()
                if n.model_slug == model_slug and n.record_pk == record_pk
            ]
        items.sort(key=lambda n: (0 if n.pinned else 1, -n.created_at.timestamp()))
        return items[: max(1, int(limit))]

    def get(self, note_id: str) -> RecordNote | None:
        with self._lock:
            n = self._notes.get(note_id)
            return replace(n) if n is not None else None

    def add(self, note: RecordNote) -> RecordNote:
        nid = note.id or uuid.uuid4().hex[:16]
        stored = replace(note, id=nid)
        with self._lock:
            self._notes[nid] = stored
        return replace(stored)

    def toggle_pin(
        self,
        note_id: str,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
    ) -> RecordNote | None:
        with self._lock:
            n = self._notes.get(note_id)
            if n is None:
                return None
            if model_slug is not None and n.model_slug != model_slug:
                return None
            if record_pk is not None and n.record_pk != record_pk:
                return None
            n.pinned = not n.pinned
            return replace(n)

    def delete(self, note_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        with self._lock:
            n = self._notes.get(note_id)
            if n is None:
                return False
            if not is_superuser and n.author_id != actor_id:
                return False
            self._notes.pop(note_id, None)
            return True


class SQLAlchemyRecordNoteStore:
    """Persistent SQLAlchemy per-record operational note store (`deck_record_notes`)."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "deck_record_notes",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("model_slug", sa.String(128), nullable=False, index=True),
            sa.Column("record_pk", sa.String(256), nullable=False, index=True),
            sa.Column("author_id", sa.String(128), nullable=False),
            sa.Column("author_name", sa.String(128), nullable=False),
            sa.Column("body", sa.Text, nullable=False),
            sa.Column("pinned", sa.Boolean, nullable=False, default=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_note(row: Any) -> RecordNote:
        now = datetime.now(timezone.utc)
        return RecordNote(
            id=str(row.id),
            model_slug=str(row.model_slug),
            record_pk=str(row.record_pk),
            author_id=str(row.author_id),
            author_name=str(row.author_name),
            body=str(row.body),
            pinned=bool(row.pinned),
            created_at=_ensure_utc(row.created_at) or now,
        )

    def list_notes(
        self, model_slug: str, record_pk: str, *, limit: int = 100
    ) -> list[RecordNote]:
        stmt = (
            sa.select(self._table)
            .where(
                self._table.c.model_slug == model_slug,
                self._table.c.record_pk == record_pk,
            )
            .order_by(self._table.c.pinned.desc(), self._table.c.created_at.desc())
            .limit(max(1, int(limit)))
        )
        with Session(self._engine) as sess:
            return [self._row_to_note(r) for r in sess.execute(stmt)]

    def get(self, note_id: str) -> RecordNote | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == note_id)
            ).first()
            return self._row_to_note(row) if row is not None else None

    def add(self, note: RecordNote) -> RecordNote:
        now = note.created_at or datetime.now(timezone.utc)
        nid = note.id or uuid.uuid4().hex[:16]
        with Session(self._engine) as sess:
            sess.execute(
                self._table.insert().values(
                    id=nid,
                    model_slug=note.model_slug[:128],
                    record_pk=note.record_pk[:256],
                    author_id=note.author_id[:128],
                    author_name=note.author_name[:128],
                    body=note.body,
                    pinned=bool(note.pinned),
                    created_at=now,
                )
            )
            sess.commit()
        return replace(note, id=nid, created_at=now)

    def toggle_pin(
        self,
        note_id: str,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
    ) -> RecordNote | None:
        conds: list[Any] = [self._table.c.id == note_id]
        if model_slug is not None:
            conds.append(self._table.c.model_slug == model_slug)
        if record_pk is not None:
            conds.append(self._table.c.record_pk == record_pk)
        with Session(self._engine) as sess:
            row = sess.execute(sa.select(self._table).where(*conds)).first()
            if row is None:
                return None
            new_pinned = not bool(row.pinned)
            sess.execute(
                self._table.update().where(*conds).values(pinned=new_pinned)
            )
            sess.commit()
            updated = sess.execute(sa.select(self._table).where(*conds)).first()
            return self._row_to_note(updated) if updated is not None else None

    def delete(self, note_id: str, *, actor_id: str, is_superuser: bool = False) -> bool:
        conds: list[Any] = [self._table.c.id == note_id]
        if not is_superuser:
            conds.append(self._table.c.author_id == actor_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.delete().where(*conds))
            sess.commit()
            return bool((getattr(res, "rowcount", 0) or 0) > 0)
