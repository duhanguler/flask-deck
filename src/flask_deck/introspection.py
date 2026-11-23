from __future__ import annotations

import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

import sqlalchemy as sa
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapper, RelationshipProperty

from flask_deck.security import is_sensitive_field

FieldType = Literal[
    "string",
    "text",
    "integer",
    "float",
    "decimal",
    "boolean",
    "date",
    "datetime",
    "time",
    "enum",
    "json",
    "array",
    "uuid",
    "binary",
    "email",
    "url",
    "password",
]

RelationshipDirection = Literal["MANYTOONE", "ONETOMANY", "MANYTOMANY"]


@dataclass(frozen=True, slots=True)
class FieldMeta:
    """Immutable metadata describing one SQLAlchemy column."""

    name: str
    label: str
    field_type: FieldType
    python_type: type[Any] | None
    nullable: bool
    primary_key: bool
    unique: bool
    indexed: bool
    autoincrement: bool
    has_default: bool
    max_length: int | None
    choices: tuple[tuple[str, str], ...]
    enum_class: type[enum.Enum] | None
    is_sensitive: bool
    is_heavy: bool
    fk_column: str | None
    fk_target_table: str | None
    fk_target_model: type[Any] | None
    fk_relationship_name: str | None
    array_item_type: FieldType | None = None
    is_jsonb: bool = False
    is_computed: bool = False
    help_text: str = ""
    ondelete: str | None = None


@dataclass(frozen=True, slots=True)
class RelationshipMeta:
    """Immutable metadata describing one SQLAlchemy ORM relationship."""

    name: str
    label: str
    direction: RelationshipDirection
    target_model: type[Any]
    uselist: bool
    local_columns: tuple[str, ...]
    remote_columns: tuple[str, ...]
    back_populates: str | None
    cascade: str = ""


@dataclass(frozen=True, slots=True)
class ModelMeta:
    """Frozen, cached schema representation of a SQLAlchemy 2.0 model."""

    model: type[Any]
    name: str
    label: str
    plural_label: str
    slug: str
    table_name: str
    primary_keys: tuple[FieldMeta, ...]
    fields: tuple[FieldMeta, ...]
    fields_by_name: dict[str, FieldMeta]
    relationships: tuple[RelationshipMeta, ...]
    relationships_by_name: dict[str, RelationshipMeta]
    fk_column_to_rel: dict[str, RelationshipMeta]
    sensitive_fields: frozenset[str]
    heavy_fields: frozenset[str]
    indexed_fields: frozenset[str]
    schema: str | None = None


_CAMEL_RE_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_RE_2 = re.compile(r"([a-z0-9])([A-Z])")


def _to_snake(name: str) -> str:
    s1 = _CAMEL_RE_1.sub(r"\1_\2", name)
    return _CAMEL_RE_2.sub(r"\1_\2", s1).lower()


def humanize(name: str) -> str:
    """Convert snake_case or CamelCase identifier into Title Case."""
    snake = _to_snake(name)
    cleaned = snake.replace("_id", "") if snake.endswith("_id") and len(snake) > 3 else snake
    return " ".join(part.capitalize() for part in cleaned.split("_") if part)


def pluralize(word: str) -> str:
    """Minimal deterministic English pluralizer for model display labels."""
    if not word:
        return word
    lower = word.lower()
    if lower.endswith(("s", "x", "z", "ch", "sh")):
        return f"{word}es"
    if lower.endswith("y") and len(word) > 1 and lower[-2] not in "aeiou":
        return f"{word[:-1]}ies"
    return f"{word}s"


def slugify(name: str) -> str:
    """Build URL-safe kebab-case slug from model class name."""
    snake = _to_snake(name)
    return pluralize(snake).replace("_", "-")


def _unwrap_sa_type(col_type: Any) -> Any:
    """Unwrap SQLAlchemy TypeDecorator / Variant wrappers down to the underlying concrete TypeEngine."""
    seen: set[int] = set()
    cur = col_type
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, sa.TypeDecorator):
            impl = getattr(cur, "impl", None)
            if impl is not None:
                cur = impl() if isinstance(impl, type) else impl
                continue
        break
    return cur


def _classify_sa_type(
    raw_type: Any,
    name: str,
    is_sensitive: bool,
) -> tuple[FieldType, tuple[tuple[str, str], ...], type[enum.Enum] | None, int | None, bool]:
    col_type = _unwrap_sa_type(raw_type)
    choices: tuple[tuple[str, str], ...] = ()
    enum_cls: type[enum.Enum] | None = None
    max_length: int | None = getattr(col_type, "length", None)
    is_heavy = False

    if isinstance(col_type, sa.Enum):
        if col_type.enum_class is not None and issubclass(col_type.enum_class, enum.Enum):
            enum_cls = col_type.enum_class
            choices = tuple((str(m.value), humanize(m.name)) for m in enum_cls)
        else:
            choices = tuple((str(v), humanize(str(v))) for v in (col_type.enums or ()))
        return "enum", choices, enum_cls, max_length, False

    if isinstance(col_type, sa.Boolean):
        return "boolean", (), None, None, False
    if isinstance(col_type, sa.DateTime):
        return "datetime", (), None, None, False
    if isinstance(col_type, sa.Date):
        return "date", (), None, None, False
    if isinstance(col_type, sa.Time):
        return "time", (), None, None, False
    if isinstance(col_type, sa.Numeric) and not isinstance(col_type, sa.Float):
        return "decimal", (), None, None, False
    if isinstance(col_type, sa.Float):
        return "float", (), None, None, False
    if isinstance(col_type, sa.Integer):
        return "integer", (), None, None, False
    if isinstance(col_type, sa.ARRAY):
        return "array", (), None, None, False
    if isinstance(col_type, sa.JSON):
        return "json", (), None, None, True
    if isinstance(col_type, sa.Uuid):
        return "uuid", (), None, 36, False
    if isinstance(col_type, sa.LargeBinary):
        return "binary", (), None, None, True
    if isinstance(col_type, sa.Text):
        return "text", (), None, max_length, True

    # String-like column heuristics
    name_lower = name.lower()
    if is_sensitive:
        return "password", (), None, max_length, False
    if "email" in name_lower:
        return "email", (), None, max_length, False
    if name_lower in {"url", "website", "homepage", "avatar_url", "image_url"} or name_lower.endswith(
        "_url"
    ):
        return "url", (), None, max_length, False
    if max_length is not None and max_length >= 500:
        is_heavy = True

    return "string", (), None, max_length, is_heavy


def _classify_column(
    col: sa.Column[Any],
    is_sensitive: bool,
) -> tuple[FieldType, tuple[tuple[str, str], ...], type[enum.Enum] | None, int | None, bool]:
    return _classify_sa_type(col.type, col.name, is_sensitive)


def _collect_indexed_columns(table: sa.Table) -> frozenset[str]:
    indexed: set[str] = set()
    for col in table.columns:
        if col.primary_key or col.index or col.unique:
            indexed.add(col.name)
    for idx in table.indexes:
        cols = list(idx.columns)
        if cols:
            # Leading column of a composite index can serve equality/prefix lookups.
            indexed.add(cols[0].name)
    for constraint in table.constraints:
        if isinstance(constraint, sa.UniqueConstraint):
            cols = list(constraint.columns)
            if cols:
                indexed.add(cols[0].name)
    return frozenset(indexed)


def introspect_model(
    model: type[Any],
    *,
    extra_sensitive_patterns: Iterable[re.Pattern[str]] = (),
    slug_override: str | None = None,
) -> ModelMeta:
    """Inspect a SQLAlchemy 2.0 mapped model once (TypeDecorator, column/hybrid_property, joined inheritance)."""
    mapper: Mapper[Any] = sa.inspect(model)
    all_tables = [t for t in mapper.tables if isinstance(t, sa.Table)]
    local_table = mapper.local_table if isinstance(mapper.local_table, sa.Table) else None
    table = local_table if local_table is not None else (all_tables[0] if all_tables else None)
    if not isinstance(table, sa.Table):
        raise TypeError(f"Model {model.__name__} must be mapped to a concrete SQLAlchemy Table")
    inheritance_table_names = {t.name for t in all_tables}

    # Build table fullname -> model class lookup from registry for FK target resolution.
    table_to_model: dict[str, type[Any]] = {}
    for other_mapper in mapper.registry.mappers:
        other_table = other_mapper.local_table
        if isinstance(other_table, sa.Table):
            table_to_model[other_table.fullname] = other_mapper.class_
            table_to_model.setdefault(other_table.name, other_mapper.class_)

    # Map SQL column name -> ORM attribute key across all inheritance tables.
    col_name_to_attr: dict[str, str] = {}
    for attr in mapper.column_attrs:
        c0 = attr.columns[0]
        if isinstance(c0, sa.Column):
            col_name_to_attr[c0.name] = attr.key

    # Relationships first so FK columns can link directly to their MANYTOONE relationship.
    relationships: list[RelationshipMeta] = []
    fk_column_to_rel: dict[str, RelationshipMeta] = {}

    for rel in mapper.relationships:
        if not isinstance(rel, RelationshipProperty):
            continue
        direction_name = rel.direction.name
        if direction_name not in {"MANYTOONE", "ONETOMANY", "MANYTOMANY"}:
            continue
        direction: RelationshipDirection = direction_name  # type: ignore[assignment]
        local_cols = tuple(col_name_to_attr.get(c.name, c.name) for c in rel.local_columns)
        remote_cols = tuple(c.name for c in rel.remote_side)
        rel_meta = RelationshipMeta(
            name=rel.key,
            label=humanize(rel.key),
            direction=direction,
            target_model=rel.mapper.class_,
            uselist=bool(rel.uselist),
            local_columns=local_cols,
            remote_columns=remote_cols,
            back_populates=rel.back_populates,
            cascade=", ".join(sorted(str(c) for c in rel.cascade)) if rel.cascade else "",
        )
        relationships.append(rel_meta)
        if direction == "MANYTOONE" and len(local_cols) == 1:
            fk_column_to_rel[local_cols[0]] = rel_meta

    raw_indexed_cols: set[str] = set()
    for tbl in all_tables:
        raw_indexed_cols.update(_collect_indexed_columns(tbl))
    indexed_cols = frozenset(col_name_to_attr.get(c, c) for c in raw_indexed_cols)
    fields: list[FieldMeta] = []
    computed_fields: list[FieldMeta] = []
    primary_keys: list[FieldMeta] = []
    sensitive_set: set[str] = set()
    heavy_set: set[str] = set()
    seen_attr_keys: set[str] = set()

    for attr in mapper.column_attrs:
        col = attr.columns[0]
        col_name = attr.key
        if col_name in seen_attr_keys:
            continue
        seen_attr_keys.add(col_name)
        sensitive = is_sensitive_field(col_name, extra_sensitive_patterns)
        if not isinstance(col, sa.Column):
            # Computed column_property(...) attribute (read-only displayable)
            expr_type = getattr(col, "type", sa.String())
            field_type, choices, enum_cls, max_length, is_heavy = _classify_sa_type(
                expr_type, col_name, sensitive
            )
            if sensitive:
                sensitive_set.add(col_name)
            if is_heavy:
                heavy_set.add(col_name)
            try:
                comp_py: type[Any] | None = _unwrap_sa_type(expr_type).python_type
            except Exception:
                comp_py = None
            computed_fields.append(
                FieldMeta(
                    name=col_name,
                    label=humanize(col_name),
                    field_type=field_type,
                    python_type=comp_py,
                    nullable=True,
                    primary_key=False,
                    unique=False,
                    indexed=False,
                    autoincrement=False,
                    has_default=True,
                    max_length=max_length,
                    choices=choices,
                    enum_class=enum_cls,
                    is_sensitive=sensitive,
                    is_heavy=is_heavy,
                    fk_column=None,
                    fk_target_table=None,
                    fk_target_model=None,
                    fk_relationship_name=None,
                    is_computed=True,
                )
            )
            continue

        field_type, choices, enum_cls, max_length, is_heavy = _classify_column(col, sensitive)
        if sensitive:
            sensitive_set.add(col_name)
        if is_heavy:
            heavy_set.add(col_name)

        unwrapped_type = _unwrap_sa_type(col.type)
        try:
            py_type: type[Any] | None = unwrapped_type.python_type
        except NotImplementedError:
            py_type = None

        fk_target_table: str | None = None
        fk_target_model: type[Any] | None = None
        fk_col_str: str | None = None
        fk_rel_name: str | None = None
        fk_ondelete: str | None = None
        is_joined_pk_fk = False
        if col.foreign_keys:
            fk = next(iter(col.foreign_keys))
            if fk.ondelete:
                fk_ondelete = str(fk.ondelete).strip().upper()
            if col.primary_key and len(all_tables) > 1 and fk.column.table.name in inheritance_table_names:
                is_joined_pk_fk = True
            else:
                fk_target_table = fk.column.table.name
                fk_target_fullname = fk.column.table.fullname
                fk_col_str = f"{fk_target_table}.{fk.column.name}"
                fk_target_model = table_to_model.get(fk_target_fullname) or table_to_model.get(
                    fk_target_table
                )
                rel_match = fk_column_to_rel.get(col_name) or fk_column_to_rel.get(col.name)
                if rel_match is not None:
                    fk_rel_name = rel_match.name
                    fk_target_model = rel_match.target_model

        has_default = col.default is not None or col.server_default is not None
        raw_help = ""
        if isinstance(col.info, dict):
            raw_help = str(col.info.get("help_text") or "").strip()
        if not raw_help and getattr(col, "comment", None):
            raw_help = str(col.comment).strip()
        autoincrement = bool(
            col.primary_key
            and field_type == "integer"
            and (col.autoincrement in (True, "auto") or is_joined_pk_fk)
            and (not col.foreign_keys or is_joined_pk_fk)
        )

        array_item_type: FieldType | None = None
        if isinstance(unwrapped_type, sa.ARRAY):
            item_t = _unwrap_sa_type(unwrapped_type.item_type)
            if isinstance(item_t, sa.Integer):
                array_item_type = "integer"
            elif isinstance(item_t, sa.Float):
                array_item_type = "float"
            elif isinstance(item_t, sa.Boolean):
                array_item_type = "boolean"
            else:
                array_item_type = "string"
        is_jsonb = unwrapped_type.__class__.__name__.upper() == "JSONB"

        fmeta = FieldMeta(
            name=col_name,
            label=humanize(col_name),
            field_type=field_type,
            python_type=py_type,
            nullable=bool(col.nullable),
            primary_key=bool(col.primary_key),
            unique=bool(col.unique),
            indexed=col_name in indexed_cols,
            autoincrement=autoincrement,
            has_default=has_default,
            max_length=max_length,
            choices=choices,
            enum_class=enum_cls,
            is_sensitive=sensitive,
            is_heavy=is_heavy,
            fk_column=fk_col_str,
            fk_target_table=fk_target_table,
            fk_target_model=fk_target_model,
            fk_relationship_name=fk_rel_name,
            array_item_type=array_item_type,
            is_jsonb=is_jsonb,
            is_computed=False,
            help_text=raw_help,
            ondelete=fk_ondelete,
        )
        fields.append(fmeta)
        if fmeta.primary_key:
            primary_keys.append(fmeta)

    # Introspect hybrid_property descriptors on the mapped class/ancestors as computed fields.
    for attr_name, desc in mapper.all_orm_descriptors.items():
        if (
            isinstance(desc, hybrid_property)
            and not attr_name.startswith("_")
            and attr_name not in seen_attr_keys
        ):
            seen_attr_keys.add(attr_name)
            sensitive = is_sensitive_field(attr_name, extra_sensitive_patterns)
            if sensitive:
                sensitive_set.add(attr_name)
            computed_fields.append(
                FieldMeta(
                    name=attr_name,
                    label=humanize(attr_name),
                    field_type="string",
                    python_type=str,
                    nullable=True,
                    primary_key=False,
                    unique=False,
                    indexed=False,
                    autoincrement=False,
                    has_default=True,
                    max_length=None,
                    choices=(),
                    enum_class=None,
                    is_sensitive=sensitive,
                    is_heavy=False,
                    fk_column=None,
                    fk_target_table=None,
                    fk_target_model=None,
                    fk_relationship_name=None,
                    is_computed=True,
                )
            )
    fields.extend(computed_fields)

    if not primary_keys:
        raise ValueError(f"Model {model.__name__} must declare at least one primary key column")

    class_name = model.__name__
    label = humanize(class_name)
    return ModelMeta(
        model=model,
        name=class_name,
        label=label,
        plural_label=pluralize(label),
        slug=slug_override or slugify(class_name),
        table_name=table.name,
        primary_keys=tuple(primary_keys),
        fields=tuple(fields),
        fields_by_name={f.name: f for f in fields},
        relationships=tuple(relationships),
        relationships_by_name={r.name: r for r in relationships},
        fk_column_to_rel=fk_column_to_rel,
        sensitive_fields=frozenset(sensitive_set),
        heavy_fields=frozenset(heavy_set),
        indexed_fields=indexed_cols,
        schema=table.schema,
    )
