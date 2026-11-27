from __future__ import annotations

import contextlib
import enum
import hashlib
import inspect
import json
import math
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar, Literal

import sqlalchemy as sa
from markupsafe import Markup, escape
from sqlalchemy.orm import Session

from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk, extract_pk
from flask_deck.audit import compute_diff, serialize_audit_value
from flask_deck.auth import AuthProvider, DeckUser
from flask_deck.exceptions import InvalidPKError, PermissionDeniedError, ValidationError
from flask_deck.filters import resolve_custom_filters
from flask_deck.formatters import (
    BadgeFormatter,
    BooleanIconFormatter,
    CodeFormatter,
    FileFormatter,
    Formatter,
    ImageFormatter,
    RelativeTimeFormatter,
    normalize_tone,
)
from flask_deck.i18n import from_user_timezone
from flask_deck.introspection import FieldMeta, ModelMeta, humanize, introspect_model
from flask_deck.query import (
    CountMode,
    PaginationMode,
    QuickTab,
    parse_search_column_spec,
    soft_delete_predicate,
)
from flask_deck.security import check_json_depth, is_safe_display_url, is_sensitive_field
from flask_deck.storage import FileFieldConfig, store_validated_upload
from flask_deck.widgets import FormWidget


def is_safe_media_path(path: str) -> bool:
    """Allow strictly same-origin relative asset paths starting with ``/`` (blocks external/protocol-relative/traversal)."""
    if not isinstance(path, str):
        return False
    if "\\" in path or any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return False
    clean = path.strip()
    if not clean or not clean.startswith("/") or clean.startswith("//"):
        return False
    if any(ch.isspace() for ch in clean):
        return False
    base = clean.split("?", 1)[0].split("#", 1)[0]
    return ".." not in base.split("/")


def is_safe_template_name(name: str | None) -> bool:
    """Validate a Jinja template override path against path traversal and absolute paths."""
    if name is None:
        return True
    if not isinstance(name, str):
        return False
    clean = name.strip()
    if not clean or clean.startswith(("/", "\\")) or "\\" in clean or "\x00" in clean:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        return False
    return ".." not in clean.split("/")


@dataclass(frozen=True, slots=True)
class VirtualField:
    """Declarative non-model form field (coerced safely into ``virtual_data``; never ``setattr``'d onto ORM models)."""

    name: str
    field_type: Literal[
        "string",
        "text",
        "integer",
        "float",
        "decimal",
        "boolean",
        "date",
        "datetime",
        "time",
        "email",
        "url",
        "enum",
        "json",
    ] = "string"
    label: str = ""
    required: bool = False
    default: Any = None
    choices: tuple[tuple[str, str], ...] = ()
    help_text: str = ""
    placeholder: str = ""
    widget: str | FormWidget | None = None
    modes: tuple[Literal["create", "edit"], ...] = ("create", "edit")
    max_length: int | None = None

    @property
    def display_label(self) -> str:
        return self.label or humanize(self.name)

    def to_field_meta(self) -> FieldMeta:
        return FieldMeta(
            name=self.name,
            label=self.display_label,
            field_type=self.field_type,
            python_type=str,
            nullable=not self.required,
            primary_key=False,
            unique=False,
            indexed=False,
            autoincrement=False,
            has_default=self.default is not None,
            max_length=self.max_length,
            choices=self.choices,
            enum_class=None,
            is_sensitive=False,
            is_heavy=self.field_type in {"text", "json"},
            fk_column=None,
            fk_target_table=None,
            fk_target_model=None,
            fk_relationship_name=None,
            help_text=self.help_text,
        )


@dataclass(frozen=True, slots=True)
class ModelURL:
    """Custom sub-route mounted under ``/<slug>/<rule>`` inheriting Deck's Auth/CSRF/CSP security boundary."""

    rule: str
    endpoint: str
    handler: Callable[..., Any]
    methods: tuple[str, ...] = ("GET",)
    permission: str | None = None


@dataclass(frozen=True, slots=True)
class ViewMedia:
    """Per-view same-origin CSS/JS asset declarations injected under strict nonce CSP."""

    css: tuple[str, ...] = ()
    js: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DisplaySpec:
    """Metadata attached to a ModelView computed display method via ``@display``."""

    name: str
    label: str
    handler_name: str = ""
    ordering: str | Callable[[type[Any]], Any] | None = None
    boolean: bool = False
    tone: str | Mapping[str, str] | None = None
    description: str = ""
    empty_value: str | None = None


def display(
    *,
    label: str | None = None,
    ordering: str | Callable[[type[Any]], Any] | None = None,
    boolean: bool = False,
    tone: str | Mapping[str, str] | None = None,
    description: str = "",
    empty_value: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator marking a ModelView method as a computed display column / form preview."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        target_fn = func.__func__ if isinstance(func, staticmethod) else func
        spec = DisplaySpec(
            name=target_fn.__name__,
            label=label or humanize(target_fn.__name__),
            handler_name=target_fn.__name__,
            ordering=ordering,
            boolean=boolean,
            tone=tone,
            description=description,
            empty_value=empty_value,
        )
        target_fn._deck_display_spec = spec  # type: ignore[attr-defined]
        return func

    return decorator


FieldRow = str | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Fieldset:
    """Structured declarative form fieldset with optional horizontal rows & collapse."""

    title: str
    fields: tuple[FieldRow, ...]
    description: str = ""
    collapsible: bool = False
    collapsed: bool = False
    icon: str | None = None


@dataclass(frozen=True, slots=True)
class ActionField:
    """Declarative input parameter rendered inside an action confirmation modal."""

    name: str
    field_type: Literal["text", "textarea", "select", "number", "boolean"] = "text"
    label: str = ""
    choices: tuple[tuple[str, str], ...] = ()
    placeholder: str = ""
    required: bool = False
    default: str = ""

    @property
    def display_label(self) -> str:
        return self.label or humanize(self.name)


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """Metadata attached to a ModelView bulk/row action via ``@action``."""

    name: str
    label: str
    handler_name: str = ""
    icon: str = "zap"
    confirm: bool = False
    variant: str = "default"  # default | danger
    permission: str | None = None
    row_action: bool = False
    bulk_action: bool = True
    require_confirm_text: bool = False
    fields: tuple[ActionField, ...] = ()
    async_job: bool = False
    require_approval: bool = False


def action(
    name: str,
    *,
    label: str | None = None,
    icon: str = "zap",
    confirm: bool = False,
    variant: str = "default",
    permission: str | None = None,
    row_action: bool = False,
    bulk_action: bool = True,
    require_confirm_text: bool = False,
    fields: Sequence[ActionField] = (),
    async_job: bool = False,
    require_approval: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator registering a custom bulk or row action on a ModelView."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        spec = ActionSpec(
            name=name,
            label=label or humanize(name),
            handler_name=func.__name__,
            icon=icon,
            confirm=confirm or bool(fields),
            variant="danger" if variant == "danger" else "default",
            permission=permission,
            row_action=row_action,
            bulk_action=bulk_action,
            require_confirm_text=require_confirm_text,
            fields=tuple(fields),
            async_job=async_job,
            require_approval=require_approval,
        )
        func._deck_action_spec = spec  # type: ignore[attr-defined]
        return func

    return decorator


def pydantic_validator(
    schema_cls: type[Any],
) -> Callable[[Mapping[str, Any], Any | None, bool], dict[str, list[str]]]:
    """Bridge a Pydantic v2 BaseModel into ModelView.form_validator with zero hard dependency."""

    def _validate(
        data: Mapping[str, Any],
        obj: Any | None,
        is_created: bool,
    ) -> dict[str, list[str]]:
        _ = (obj, is_created)
        try:
            if hasattr(schema_cls, "model_validate"):
                schema_cls.model_validate(dict(data))
            else:
                schema_cls(**dict(data))
            return {}
        except Exception as exc:
            errs_fn = getattr(exc, "errors", None)
            if callable(errs_fn):
                out: dict[str, list[str]] = {}
                for err in errs_fn():
                    loc = err.get("loc", ())
                    field_key = str(loc[0]) if loc else "__all__"
                    sub_path = ".".join(str(p) for p in loc[1:]) if len(loc) > 1 else ""
                    msg = str(err.get("msg", "Invalid value."))
                    if sub_path:
                        msg = f"{sub_path}: {msg}"
                    out.setdefault(field_key, []).append(msg)
                return out
            return {"__all__": [str(exc)]}

    return _validate


class InlineModelView:
    """Declarative One-to-Many inline child editor embedded inside a parent ModelView form."""

    model: type[Any]
    fk_column: ClassVar[str | None] = None
    label: ClassVar[str | None] = None
    columns: ClassVar[Sequence[str]] = ()
    extra_fields: ClassVar[Sequence[str]] = ()
    order_by: ClassVar[str | None] = None
    searchable: ClassVar[bool] = False
    can_create: ClassVar[bool] = True
    can_edit: ClassVar[bool] = True
    can_delete: ClassVar[bool] = True
    max_rows: ClassVar[int] = 50
    # v0.5.0 Beyond-Django Inline upgrades
    layout: ClassVar[Literal["tabular", "stacked"]] = "tabular"
    min_num: ClassVar[int] = 0
    extra: ClassVar[int] = 0
    show_change_link: ClassVar[bool] = True
    field_help_texts: ClassVar[Mapping[str, str]] = {}
    # v0.6.0 Rich Inlines 2.0
    readonly_fields: ClassVar[Sequence[str]] = ()
    field_widgets: ClassVar[Mapping[str, str | FormWidget]] = {}
    file_fields: ClassVar[Mapping[str, FileFieldConfig]] = {}
    collapsible: ClassVar[bool] = False
    collapsed: ClassVar[bool] = False
    extra_on_edit: ClassVar[int | None] = None
    empty_value_display: ClassVar[str] = "—"

    def __init__(self, extra_sensitive_patterns: Sequence[Any] = ()) -> None:
        self.meta: ModelMeta = introspect_model(
            self.model,
            extra_sensitive_patterns=extra_sensitive_patterns,
        )
        self.display_label: str = self.label or self.meta.plural_label
        discovered_displays: dict[str, DisplaySpec] = {}
        for cls in reversed(self.__class__.__mro__):
            for attr_val in cls.__dict__.values():
                target_fn = attr_val.__func__ if isinstance(attr_val, staticmethod) else attr_val
                d_spec: DisplaySpec | None = getattr(target_fn, "_deck_display_spec", None)
                if d_spec is not None and d_spec.name not in self.meta.sensitive_fields:
                    discovered_displays[d_spec.name] = d_spec
        self.display_fields: dict[str, DisplaySpec] = discovered_displays
        self.resolved_readonly_fields: frozenset[str] = frozenset(self.readonly_fields) | frozenset(
            self.display_fields.keys()
        )

        if self.columns:
            raw_display_cols = [
                c
                for c in self.columns
                if c not in self.meta.sensitive_fields
                and (c in self.meta.fields_by_name or c in self.display_fields)
            ]
        else:
            raw_display_cols = [
                f.name
                for f in self.meta.fields
                if not f.primary_key
                and not f.is_computed
                and not f.is_sensitive
                and f.name != self.fk_column
            ]
        seen_disp = set(raw_display_cols)
        for ro in self.readonly_fields:
            if (
                ro not in seen_disp
                and ro not in self.meta.sensitive_fields
                and (ro in self.meta.fields_by_name or ro in self.display_fields)
            ):
                raw_display_cols.append(ro)
                seen_disp.add(ro)
        self.display_columns: tuple[str, ...] = tuple(raw_display_cols)
        self.editable_columns: tuple[str, ...] = tuple(
            c
            for c in self.display_columns
            if c in self.meta.fields_by_name
            and not self.meta.fields_by_name[c].is_computed
            and c not in self.meta.sensitive_fields
            and c not in self.resolved_readonly_fields
        )

    def get_column_label(self, col_name: str) -> str:
        if col_name in self.display_fields:
            return self.display_fields[col_name].label
        fmeta = self.meta.fields_by_name.get(col_name)
        return fmeta.label if fmeta is not None else humanize(col_name)

    def format_inline_cell(
        self,
        col_name: str,
        obj: Any | None,
        *,
        auth: AuthProvider | None = None,
        user: DeckUser | None = None,
        media_url_builder: Callable[[str, Any], str | None] | None = None,
    ) -> Markup | str:
        """Render a readonly scalar or ``@display`` cell for an inline child row safely."""
        if obj is None:
            return Markup(f'<span class="dk-null">{escape(self.empty_value_display)}</span>')
        d_spec = self.display_fields.get(col_name)
        raw_val = (
            getattr(self, d_spec.handler_name)(obj)
            if d_spec is not None
            else getattr(obj, col_name, None)
        )
        if auth is not None and col_name in auth.masked_fields_for(user, self.meta.slug):
            masked = auth.mask_field_value(user, self.meta.slug, col_name, raw_val)
            return Markup(
                f'<span class="dk-masked">{escape(str(masked or self.empty_value_display))}</span>'
            )
        empty_marker = (
            d_spec.empty_value
            if (d_spec is not None and d_spec.empty_value is not None)
            else self.empty_value_display
        )
        if col_name in self.file_fields and media_url_builder is not None:
            cfg = self.file_fields[col_name]
            fmt: ImageFormatter | FileFormatter = (
                ImageFormatter(field_name=col_name) if cfg.kind == "image" else FileFormatter()
            )
            return fmt.format_with_url(raw_val, media_url_builder(col_name, obj))
        if raw_val is None:
            return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')
        if d_spec is not None:
            if d_spec.boolean:
                return BooleanIconFormatter().format(raw_val, obj)
            if isinstance(d_spec.tone, Mapping):
                return BadgeFormatter(d_spec.tone).format(raw_val, obj)
            if isinstance(d_spec.tone, str) and d_spec.tone:
                tone_cls = normalize_tone(d_spec.tone)
                return Markup(
                    f'<span class="dk-badge dk-badge-{tone_cls}">'
                    f'<span class="dk-dot" aria-hidden="true"></span>'
                    f"{escape(str(raw_val))}</span>"
                )
            if isinstance(raw_val, Markup):
                return raw_val
        return str(raw_val)

    def scope_query(
        self,
        stmt: sa.Select[Any],
        user: DeckUser | None,
        parent_obj: Any | None = None,
    ) -> sa.Select[Any]:
        """Override to restrict which child rows are loaded and editable inside this inline."""
        _ = (user, parent_obj)
        return stmt

    def can_add_inline(self, parent_obj: Any | None, user: DeckUser | None) -> bool:
        _ = (parent_obj, user)
        return bool(self.can_create)

    def can_edit_inline(self, parent_obj: Any | None, user: DeckUser | None) -> bool:
        _ = (parent_obj, user)
        return bool(self.can_edit)

    def can_delete_inline(self, parent_obj: Any | None, user: DeckUser | None) -> bool:
        _ = (parent_obj, user)
        return bool(self.can_delete)

    def validate_rows(
        self,
        rows_data: Sequence[Mapping[str, Any]],
        *,
        parent_obj: Any | None = None,
        user: DeckUser | None = None,
    ) -> dict[str, list[str]]:
        """Optional cross-row inline validation hook returning ``{error_key: [messages]}``."""
        _ = (rows_data, parent_obj, user)
        return {}

    def resolve_fk_column(self, parent_meta: ModelMeta) -> str:
        if self.fk_column:
            if self.fk_column not in self.meta.fields_by_name:
                raise ValueError(
                    f"Configured fk_column {self.fk_column!r} does not exist on inline {self.meta.name}"
                )
            return self.fk_column
        for f in self.meta.fields:
            if f.fk_target_model is parent_meta.model or f.fk_target_table == parent_meta.table_name:
                return f.name
        raise ValueError(
            f"Cannot infer fk_column on inline {self.meta.name} pointing to {parent_meta.name}"
        )


def coerce_form_value(
    raw: Any,
    fmeta: FieldMeta,
    *,
    max_json_depth: int = 12,
    utc_passthrough: bool = False,
) -> Any:
    """Validate and coerce an incoming form/JSON field value into its SQLAlchemy Python type."""
    if fmeta.field_type == "boolean":
        if fmeta.nullable and (raw is None or (isinstance(raw, str) and raw.strip() == "")):
            return None
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    if raw is None or (isinstance(raw, str) and raw.strip() == ""):
        if fmeta.nullable or fmeta.has_default or fmeta.autoincrement:
            return None
        if utc_passthrough and isinstance(raw, str) and fmeta.field_type in {"string", "text"}:
            return ""
        raise ValueError("This field is required.")

    text = str(raw).strip() if not isinstance(raw, (dict, list)) else raw

    if fmeta.field_type == "enum":
        if fmeta.enum_class is not None:
            for member in fmeta.enum_class:
                if str(member.value) == str(text) or member.name == str(text):
                    return member
            valid_opts = ", ".join(str(m.value) for m in fmeta.enum_class)
            raise ValueError(f"Must be one of: {valid_opts}.")
        valid_values = {c[0] for c in fmeta.choices}
        if valid_values and str(text) not in valid_values:
            raise ValueError(f"Must be one of: {', '.join(sorted(valid_values))}.")
        return str(text)

    if fmeta.field_type == "integer":
        try:
            if isinstance(raw, bool):
                raise ValueError
            return int(str(text))
        except ValueError as exc:
            raise ValueError("Must be a valid integer.") from exc

    if fmeta.field_type == "float":
        try:
            fval = float(str(text))
        except ValueError as exc:
            raise ValueError("Must be a valid decimal number.") from exc
        if not math.isfinite(fval):
            raise ValueError("Must be a finite decimal number.")
        return fval

    if fmeta.field_type == "decimal":
        try:
            dval = Decimal(str(text))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("Must be a valid decimal value.") from exc
        if not dval.is_finite():
            raise ValueError("Must be a finite decimal value.")
        return dval

    if fmeta.field_type == "uuid":
        try:
            return raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(text))
        except ValueError as exc:
            raise ValueError("Must be a valid UUID.") from exc

    if fmeta.field_type == "date":
        try:
            return date.fromisoformat(str(text)[:10])
        except ValueError as exc:
            raise ValueError("Must be a valid ISO date (YYYY-MM-DD).") from exc

    if fmeta.field_type == "datetime":
        try:
            cleaned = str(text).replace(" ", "T").replace("Z", "+00:00")
            parsed_dt = datetime.fromisoformat(cleaned)
            if utc_passthrough:
                if parsed_dt.tzinfo is None:
                    return parsed_dt.replace(tzinfo=timezone.utc)
                return parsed_dt.astimezone(timezone.utc)
            return from_user_timezone(parsed_dt)
        except ValueError as exc:
            raise ValueError("Must be a valid ISO datetime.") from exc

    if fmeta.field_type == "time":
        try:
            return time.fromisoformat(str(text))
        except ValueError as exc:
            raise ValueError("Must be a valid time (HH:MM:SS).") from exc

    if fmeta.field_type == "array":
        raw_items: list[Any]
        if isinstance(raw, list):
            raw_items = list(raw)
        else:
            s_text = str(text).strip()
            if s_text.startswith("[") and s_text.endswith("]"):
                try:
                    loaded = json.loads(s_text)
                    if not isinstance(loaded, list):
                        raise ValueError("Must be a JSON array.")
                    raw_items = loaded
                except json.JSONDecodeError:
                    raw_items = [p.strip() for p in s_text.replace("\n", ",").split(",") if p.strip()]
            else:
                raw_items = [p.strip() for p in s_text.replace("\n", ",").split(",") if p.strip()]
        out_items: list[Any] = []
        for item in raw_items:
            if fmeta.array_item_type == "integer":
                try:
                    if isinstance(item, bool):
                        raise ValueError
                    out_items.append(int(str(item).strip()))
                except ValueError as exc:
                    raise ValueError(f"Invalid integer array element: {item!r}.") from exc
            elif fmeta.array_item_type == "float":
                try:
                    af = float(str(item).strip())
                    if not math.isfinite(af):
                        raise ValueError
                    out_items.append(af)
                except ValueError as exc:
                    raise ValueError(f"Invalid float array element: {item!r}.") from exc
            elif fmeta.array_item_type == "boolean":
                if isinstance(item, bool):
                    out_items.append(item)
                else:
                    lower_b = str(item).strip().lower()
                    if lower_b in {"1", "true", "yes", "on"}:
                        out_items.append(True)
                    elif lower_b in {"0", "false", "no", "off"}:
                        out_items.append(False)
                    else:
                        raise ValueError(f"Invalid boolean array element: {item!r}.")
            else:
                out_items.append(str(item).strip())
        return out_items

    if fmeta.field_type == "json":
        parsed: Any
        if isinstance(raw, (dict, list)):
            parsed = raw
        else:
            try:
                parsed = json.loads(str(text))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON: {exc.msg}.") from exc
        if not check_json_depth(parsed, max_json_depth):
            raise ValueError(f"JSON nesting exceeds maximum depth ({max_json_depth}).")
        return parsed

    result_str = str(raw)
    if fmeta.field_type == "url" and result_str.strip() and not is_safe_display_url(result_str):
        raise ValueError("URL must start with http://, https://, or /.")
    if fmeta.max_length is not None and len(result_str) > fmeta.max_length:
        raise ValueError(f"Must be at most {fmeta.max_length} characters.")
    return result_str


class ModelView:
    """Declarative configuration and controller logic for one registered SQLAlchemy model."""

    model: type[Any]
    slug: str | None = None
    name: str | None = None
    plural_name: str | None = None
    icon: str = "database"
    category: str = "Models"

    columns: ClassVar[Sequence[str]] = ()
    exclude_columns: ClassVar[Sequence[str]] = ()
    searchable_columns: ClassVar[Sequence[str]] = ()
    filterable_columns: ClassVar[Sequence[str]] = ()
    sortable_columns: ClassVar[Sequence[str]] = ()
    inline_editable_columns: ClassVar[Sequence[str]] = ()

    form_columns: ClassVar[Sequence[str]] = ()
    form_excluded_columns: ClassVar[Sequence[str]] = ()
    fieldsets: ClassVar[Sequence[Fieldset | tuple[str, Sequence[FieldRow]]]] = ()
    column_labels: ClassVar[Mapping[str, str]] = {}
    column_formatters: ClassVar[Mapping[str, Formatter | Callable[[Any, Any], Markup | str]]] = {}
    column_badges: ClassVar[Mapping[str, Mapping[str, str]]] = {}

    default_sort: ClassVar[tuple[str, str] | None] = None
    page_size: ClassVar[int | None] = None
    quick_tabs: ClassVar[Sequence[QuickTab]] = ()
    inlines: ClassVar[Sequence[type[InlineModelView]]] = ()
    export_columns: ClassVar[Sequence[str]] = ()
    import_columns: ClassVar[Sequence[str]] = ()
    import_key_columns: ClassVar[Sequence[str]] = ()
    display_column: ClassVar[str | None] = None
    kanban_column: ClassVar[str | None] = None
    kanban_card_fields: ClassVar[Sequence[str]] = ()
    column_aggregates: ClassVar[Mapping[str, str]] = {}
    form_layout: ClassVar[Literal["stacked", "tabs", "wizard"]] = "stacked"
    field_widgets: ClassVar[Mapping[str, str | FormWidget]] = {}
    saved_views: ClassVar[Sequence[tuple[str, str]]] = ()
    # v0.3.0 Enterprise ModelView capabilities
    pagination_mode: ClassVar[PaginationMode | None] = None
    count_mode: ClassVar[CountMode] = "exact"
    soft_delete_column: ClassVar[str | None] = None
    bind_key: ClassVar[str | None] = None
    file_fields: ClassVar[Mapping[str, FileFieldConfig]] = {}
    field_conditions: ClassVar[Mapping[str, tuple[str, str, Any]]] = {}
    dependent_fields: ClassVar[Mapping[str, tuple[str, str]]] = {}
    form_validator: ClassVar[
        Callable[[Mapping[str, Any], Any | None, bool], Mapping[str, list[str]]] | None
    ] = None
    # v0.4.0 Enterprise Governance capabilities
    approval_required: ClassVar[
        tuple[str, ...]
        | Callable[[DeckUser | None, str, Any, Mapping[str, Any]], bool]
    ] = ()
    version_column: ClassVar[str | None] = None
    # v0.4.0 Workspace 2.0 capabilities
    calendar_date_field: ClassVar[str | None] = None
    calendar_title_field: ClassVar[str | None] = None
    gallery_image_field: ClassVar[str | None] = None
    gallery_subtitle_field: ClassVar[str | None] = None
    tree_parent_field: ClassVar[str | None] = None
    tree_title_field: ClassVar[str | None] = None
    aggregate_scope: ClassVar[Literal["page", "all"]] = "page"
    # v0.5.0 Beyond-Django capabilities
    readonly_fields: ClassVar[Sequence[str]] = ()
    field_help_texts: ClassVar[Mapping[str, str]] = {}
    search_help_text: ClassVar[str] = ""
    empty_value_display: ClassVar[str] = "—"
    view_on_site: ClassVar[str | Callable[..., str | None] | None] = None
    prepopulated_fields: ClassVar[Mapping[str, Sequence[str]]] = {}
    save_as: ClassVar[bool] = False
    preserve_filters: ClassVar[bool] = True
    date_hierarchy: ClassVar[str | None] = None
    custom_filters: ClassVar[Sequence[Any]] = ()
    show_facets: ClassVar[Literal["auto", "always", "never"]] = "auto"
    page_size_options: ClassVar[tuple[int, ...]] = (25, 50, 100)
    list_max_show_all: ClassVar[int] = 200
    m2m_mode: ClassVar[Literal["auto", "pills", "dual", "async"]] = "auto"
    # v0.6.0 Django Parity & Authoring 2.0 capabilities
    extra_form_fields: ClassVar[Sequence[VirtualField]] = ()
    list_display_links: ClassVar[Sequence[str] | None] = None
    formfield_overrides: ClassVar[Mapping[str, str | FormWidget]] = {}
    radio_fields: ClassVar[Mapping[str, Literal["horizontal", "vertical"]]] = {}
    list_select_related: ClassVar[Sequence[str]] = ()
    show_full_result_count: ClassVar[bool] = False
    inline_edit_mode: ClassVar[Literal["instant", "batch"]] = "instant"
    save_as_continue: ClassVar[bool] = True
    save_on_top: ClassVar[bool] = False
    raw_id_fields: ClassVar[Sequence[str]] = ()
    disabled_actions: ClassVar[Sequence[str]] = ()
    is_primary_view: ClassVar[bool] = False
    nav_order: ClassVar[int] = 100
    list_template: ClassVar[str | None] = None
    form_template: ClassVar[str | None] = None
    detail_template: ClassVar[str | None] = None
    history_template: ClassVar[str | None] = None
    media: ClassVar[ViewMedia | None] = None
    extra_css: ClassVar[Sequence[str]] = ()
    extra_js: ClassVar[Sequence[str]] = ()

    can_view: bool = True
    can_create: bool = True
    can_edit: bool = True
    can_delete: bool = True
    can_export: bool = True
    can_import: bool = True

    def __init__(
        self,
        model: type[Any] | None = None,
        *,
        extra_sensitive_patterns: Sequence[Any] = (),
    ) -> None:
        if model is not None:
            self.model = model
        if not hasattr(self, "model") or self.model is None:
            raise ValueError(f"{self.__class__.__name__} must declare a SQLAlchemy model")

        self._deck: Any = None
        self._explicit_empty_value_display: bool = "empty_value_display" in self.__dict__ or any(
            "empty_value_display" in cls.__dict__
            for cls in self.__class__.__mro__
            if cls is not ModelView and issubclass(cls, ModelView)
        )
        self.meta: ModelMeta = introspect_model(
            self.model,
            extra_sensitive_patterns=extra_sensitive_patterns,
            slug_override=self.slug,
        )
        self.slug = self.meta.slug
        self.label: str = self.name or self.meta.label
        self.plural_label: str = self.plural_name or self.meta.plural_label
        self.virtual_fields_by_name: dict[str, VirtualField] = {
            vf.name: vf
            for vf in self.extra_form_fields
            if vf.name
            and vf.name not in self.meta.fields_by_name
            and vf.name not in self.meta.relationships_by_name
        }

        excluded = set(self.exclude_columns) | set(self.meta.sensitive_fields)

        # Discover @display methods and @action methods first so column/sortable checks can see them.
        discovered_displays: dict[str, DisplaySpec] = {}
        discovered_actions: dict[str, ActionSpec] = {}
        for cls in reversed(self.__class__.__mro__):
            for attr_val in cls.__dict__.values():
                target_fn = attr_val.__func__ if isinstance(attr_val, staticmethod) else attr_val
                d_spec: DisplaySpec | None = getattr(target_fn, "_deck_display_spec", None)
                if d_spec is not None and d_spec.name not in excluded:
                    discovered_displays[d_spec.name] = d_spec
                a_spec: ActionSpec | None = getattr(target_fn, "_deck_action_spec", None)
                if a_spec is not None:
                    discovered_actions[a_spec.name] = a_spec
        self.display_fields: dict[str, DisplaySpec] = discovered_displays
        self.actions: dict[str, ActionSpec] = discovered_actions

        def _is_model_attr(name: str) -> bool:
            if name.startswith("_") or name in excluded:
                return False
            attr = getattr(self.model, name, None)
            return attr is not None and not callable(attr)

        # Compute frozen column lists once at registration (zero per-request reflection).
        if self.columns:
            self.list_columns: tuple[str, ...] = tuple(
                c
                for c in self.columns
                if c not in excluded
                and (
                    c in self.meta.fields_by_name
                    or c in self.meta.relationships_by_name
                    or c in self.display_fields
                    or _is_model_attr(c)
                )
            )
        else:
            default_cols: list[str] = []
            for f in self.meta.fields:
                if f.name in excluded or f.is_heavy:
                    continue
                # Prefer relationship display over raw FK id if a MANYTOONE rel exists.
                rel = self.meta.fk_column_to_rel.get(f.name)
                if rel is not None and rel.name not in excluded:
                    default_cols.append(rel.name)
                else:
                    default_cols.append(f.name)
                if len(default_cols) >= 7:
                    break
            self.list_columns = tuple(default_cols)

        def _is_safe_search_spec(raw_spec: str) -> bool:
            path, _ = parse_search_column_spec(raw_spec)
            if not path:
                return False
            parts = path.split(".")
            if len(parts) > 3:
                return False
            if len(parts) == 1:
                return parts[0] not in self.meta.sensitive_fields
            return all(
                not is_sensitive_field(seg, extra_sensitive_patterns)
                for seg in parts
            ) and parts[0] not in self.meta.sensitive_fields

        if self.searchable_columns:
            self.resolved_searchable: tuple[str, ...] = tuple(
                c for c in self.searchable_columns if _is_safe_search_spec(c)
            )
        else:
            self.resolved_searchable = tuple(
                f.name
                for f in self.meta.fields
                if f.field_type in {"string", "email", "uuid"}
                and not f.is_sensitive
                and not f.is_heavy
            )[:4]

        def _is_valid_dotted_rel_col(spec_col: str) -> bool:
            if "." not in spec_col:
                return False
            rel_name, target_col = spec_col.split(".", 1)
            rel_m = self.meta.relationships_by_name.get(rel_name)
            return bool(
                rel_m is not None
                and rel_m.direction == "MANYTOONE"
                and rel_name not in self.meta.sensitive_fields
                and not is_sensitive_field(target_col, extra_sensitive_patterns)
            )

        if self.filterable_columns:
            resolved_filt: set[str] = set()
            for c in self.filterable_columns:
                if _is_valid_dotted_rel_col(c) or (
                    c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
                ):
                    resolved_filt.add(c)
            self.resolved_filterable: frozenset[str] = frozenset(resolved_filt)
        else:
            self.resolved_filterable = frozenset(
                f.name
                for f in self.meta.fields
                if f.field_type in {"enum", "boolean", "date", "datetime"}
                or f.fk_target_table is not None
            )

        def _is_sortable_display(col_name: str) -> bool:
            d_spec = self.display_fields.get(col_name)
            if d_spec is None or d_spec.ordering is None:
                return False
            if isinstance(d_spec.ordering, str):
                if "." in d_spec.ordering:
                    return _is_valid_dotted_rel_col(d_spec.ordering)
                return (
                    d_spec.ordering in self.meta.fields_by_name
                    and d_spec.ordering not in self.meta.sensitive_fields
                )
            return callable(d_spec.ordering)

        if self.sortable_columns:
            resolved_sort: set[str] = set()
            for c in self.sortable_columns:
                if (
                    (c in self.meta.fields_by_name and c not in self.meta.sensitive_fields)
                    or _is_valid_dotted_rel_col(c)
                    or _is_sortable_display(c)
                ):
                    resolved_sort.add(c)
            self.resolved_sortable: frozenset[str] = frozenset(resolved_sort)
        else:
            auto_sort = {
                f.name
                for f in self.meta.fields
                if not f.is_heavy and not f.is_sensitive and f.field_type not in {"binary", "array"}
            }
            for d_name in self.display_fields:
                if _is_sortable_display(d_name):
                    auto_sort.add(d_name)
            self.resolved_sortable = frozenset(auto_sort)

        self.resolved_inline_editable: frozenset[str] = frozenset(
            c
            for c in self.inline_editable_columns
            if c in self.meta.fields_by_name
            and not self.meta.fields_by_name[c].primary_key
            and not self.meta.fields_by_name[c].is_computed
            and c not in self.meta.sensitive_fields
            and (
                self.meta.fields_by_name[c].field_type
                in {"boolean", "enum", "string", "integer", "float", "decimal", "date"}
                or (
                    self.meta.fields_by_name[c].fk_target_model is not None
                    and self.meta.fields_by_name[c].field_type in {"integer", "string", "uuid"}
                )
            )
        )
        self.resolved_readonly_fields: frozenset[str] = frozenset(self.readonly_fields) | frozenset(
            self.display_fields.keys()
        )
        self.resolved_calendar_field: str | None = (
            self.calendar_date_field
            if self.calendar_date_field
            and self.calendar_date_field in self.meta.fields_by_name
            and self.meta.fields_by_name[self.calendar_date_field].field_type in {"date", "datetime"}
            else None
        )
        self.resolved_gallery_field: str | None = (
            self.gallery_image_field
            if self.gallery_image_field
            and (
                self.gallery_image_field in self.file_fields
                or self.gallery_image_field in self.meta.fields_by_name
            )
            and self.gallery_image_field not in self.meta.sensitive_fields
            else None
        )
        self.resolved_tree_field: str | None = (
            self.tree_parent_field
            if self.tree_parent_field and self.tree_parent_field in self.meta.fields_by_name
            else None
        )

        # Form columns (scalars + M2M relationships); auto-exclude soft_delete_column & version_column
        form_excluded = set(self.form_excluded_columns) | set(self.meta.sensitive_fields)
        if self.soft_delete_column:
            form_excluded.add(self.soft_delete_column)
        if self.version_column:
            form_excluded.add(self.version_column)
        if self.form_columns:
            self.resolved_form_fields: tuple[str, ...] = tuple(
                c
                for c in self.form_columns
                if c not in form_excluded
                and (
                    (c in self.meta.fields_by_name and not self.meta.fields_by_name[c].is_computed)
                    or c in self.meta.relationships_by_name
                    or c in self.display_fields
                    or c in self.virtual_fields_by_name
                )
            )
        else:
            auto_form: list[str] = []
            for f in self.meta.fields:
                if f.name in form_excluded or f.autoincrement or f.is_computed or f.field_type == "binary":
                    continue
                if f.primary_key and f.has_default:
                    continue
                auto_form.append(f.name)
            for rel in self.meta.relationships:
                if rel.direction == "MANYTOMANY" and rel.name not in form_excluded:
                    auto_form.append(rel.name)
            self.resolved_form_fields = tuple(auto_form)

        # Ensure declarative readonly_fields & @display previews declared in readonly/fieldsets appear in forms
        base_form_list = list(auto_form) if not self.form_columns else list(self.resolved_form_fields)
        # Re-read using actual resolved_form_fields before extending
        base_form_set = set(base_form_list)
        extra_ro_candidates: list[str] = list(self.readonly_fields)
        for fs in self.fieldsets:
            fs_rows = fs.fields if isinstance(fs, Fieldset) else fs[1]
            for row_item in fs_rows:
                cols_in_item = row_item if isinstance(row_item, (tuple, list)) else (row_item,)
                for col_candidate in cols_in_item:
                    if col_candidate in self.display_fields or col_candidate in self.readonly_fields:
                        extra_ro_candidates.append(col_candidate)
        for c in extra_ro_candidates:
            if (
                c not in base_form_set
                and c not in form_excluded
                and (
                    c in self.meta.fields_by_name
                    or c in self.meta.relationships_by_name
                    or c in self.display_fields
                )
            ):
                base_form_list.append(c)
                base_form_set.add(c)
        self.resolved_form_fields = tuple(base_form_list)

        # Formatters: merge user formatters + column_badges + sensible smart defaults.
        self._formatters: dict[str, Formatter | Callable[[Any, Any], Markup | str]] = {}
        for f in self.meta.fields:
            if f.field_type == "boolean":
                self._formatters[f.name] = BooleanIconFormatter()
            elif f.field_type == "enum":
                self._formatters[f.name] = BadgeFormatter()
            elif f.field_type == "datetime":
                self._formatters[f.name] = RelativeTimeFormatter()
            elif f.field_type == "uuid":
                self._formatters[f.name] = CodeFormatter(max_chars=18)
        for col_name, cfg in self.file_fields.items():
            if col_name not in self._formatters:
                self._formatters[col_name] = (
                    ImageFormatter(field_name=col_name) if cfg.kind == "image" else FileFormatter()
                )
        for col_name, badge_map in self.column_badges.items():
            self._formatters[col_name] = BadgeFormatter(badge_map)
        for col_name, fmt in self.column_formatters.items():
            self._formatters[col_name] = fmt

        # Inlines
        self.inline_views: tuple[InlineModelView, ...] = tuple(
            inline_cls(extra_sensitive_patterns=extra_sensitive_patterns)
            for inline_cls in self.inlines
        )
        self.resolved_custom_filters = resolve_custom_filters(self.custom_filters)

        # Export & import allowlists (never expose sensitive fields by default).
        if self.export_columns:
            self.resolved_export_columns: tuple[str, ...] = tuple(
                c
                for c in self.export_columns
                if c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
            )
        else:
            self.resolved_export_columns = tuple(
                f.name
                for f in self.meta.fields
                if not f.is_sensitive and f.field_type != "binary"
            )

        if self.import_columns:
            self.resolved_import_columns: tuple[str, ...] = tuple(
                c
                for c in self.import_columns
                if c in self.meta.fields_by_name
                and not self.meta.fields_by_name[c].is_computed
                and c not in self.meta.sensitive_fields
                and c != self.version_column
                and c != self.soft_delete_column
                and c not in self.readonly_fields
            )
        else:
            self.resolved_import_columns = tuple(
                f.name
                for f in self.meta.fields
                if not f.is_sensitive
                and not f.is_computed
                and not f.autoincrement
                and f.field_type != "binary"
                and f.name != self.soft_delete_column
                and f.name != self.version_column
                and f.name not in self.readonly_fields
            )

    def get_column_label(self, col_name: str) -> str:
        if col_name in self.column_labels:
            return self.column_labels[col_name]
        if col_name in self.virtual_fields_by_name:
            return self.virtual_fields_by_name[col_name].display_label
        if col_name in self.display_fields:
            return self.display_fields[col_name].label
        if col_name in self.meta.fields_by_name:
            return self.meta.fields_by_name[col_name].label
        if col_name in self.meta.relationships_by_name:
            return self.meta.relationships_by_name[col_name].label
        return humanize(col_name)

    def get_field_help_text(self, col_name: str) -> str:
        if col_name in self.field_help_texts:
            return self.field_help_texts[col_name]
        if col_name in self.virtual_fields_by_name and self.virtual_fields_by_name[col_name].help_text:
            return self.virtual_fields_by_name[col_name].help_text
        if col_name in self.display_fields and self.display_fields[col_name].description:
            return self.display_fields[col_name].description
        fmeta = self.meta.fields_by_name.get(col_name)
        return fmeta.help_text if fmeta is not None else ""

    def get_widget_for_field(self, field_name: str, field_type: str) -> str | FormWidget | None:
        """Resolve widget override from VirtualField, ``field_widgets``, or ``formfield_overrides``."""
        if field_name in self.virtual_fields_by_name:
            vw = self.virtual_fields_by_name[field_name].widget
            if vw is not None:
                return vw
        if field_name in self.field_widgets:
            return self.field_widgets[field_name]
        if field_type in self.formfield_overrides:
            return self.formfield_overrides[field_type]
        return None

    def collect_media(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return deduplicated, validated same-origin ``(css, js)`` assets for this view & its widgets."""
        css_out: list[str] = []
        js_out: list[str] = []

        def _add_css(items: Sequence[str]) -> None:
            for p in items:
                clean = p.strip()
                if is_safe_media_path(clean) and clean not in css_out:
                    css_out.append(clean)

        def _add_js(items: Sequence[str]) -> None:
            for p in items:
                clean = p.strip()
                if is_safe_media_path(clean) and clean not in js_out:
                    js_out.append(clean)

        if self.media is not None:
            _add_css(self.media.css)
            _add_js(self.media.js)
        _add_css(self.extra_css)
        _add_js(self.extra_js)

        widgets_to_scan: list[Any] = [
            *self.field_widgets.values(),
            *self.formfield_overrides.values(),
            *(vf.widget for vf in self.extra_form_fields if vf.widget is not None),
        ]
        for inline in self.inline_views:
            widgets_to_scan.extend(inline.field_widgets.values())
        for w in widgets_to_scan:
            if isinstance(w, FormWidget):
                _add_css(w.media_css)
                _add_js(w.media_js)
        return tuple(css_out), tuple(js_out)

    # ── Dynamic per-request / per-object hooks (v0.6.0) ─────────────────────

    def get_readonly_fields(
        self,
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> Sequence[str]:
        """Override to compute readonly fields dynamically per user or record state."""
        _ = (user, obj)
        return self.readonly_fields

    def effective_readonly_fields(
        self,
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> frozenset[str]:
        return frozenset(self.get_readonly_fields(user, obj)) | frozenset(self.display_fields.keys())

    def get_fieldsets(
        self,
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> Sequence[Fieldset | tuple[str, Sequence[FieldRow]]]:
        """Override to customize form fieldsets dynamically per user or object."""
        _ = (user, obj)
        return self.fieldsets

    def get_inlines(
        self,
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> Sequence[InlineModelView]:
        """Override to show/hide inline editors dynamically per user or object."""
        _ = (user, obj)
        return self.inline_views

    def get_list_display(self, user: DeckUser | None) -> Sequence[str]:
        """Override to customize list columns dynamically per user."""
        _ = user
        return self.list_columns

    def get_actions(self, user: DeckUser | None) -> dict[str, ActionSpec]:
        """Return available actions for ``user`` (merging site-wide + view actions minus disabled)."""
        _ = user
        deck = self._deck
        site_disabled: frozenset[str] = (
            frozenset(deck._disabled_site_actions)
            if deck is not None and hasattr(deck, "_disabled_site_actions")
            else frozenset()
        )
        view_disabled = set(self.disabled_actions)
        combined: dict[str, ActionSpec] = {}
        if deck is not None and hasattr(deck, "_site_actions"):
            for a_name, (a_spec, _fn) in deck._site_actions.items():
                if a_name not in view_disabled and a_name not in site_disabled:
                    combined[a_name] = a_spec
        for a_name, a_spec in self.actions.items():
            if a_name not in view_disabled and a_name not in site_disabled:
                combined[a_name] = a_spec
        return combined

    def can_view_record(self, obj: Any, user: DeckUser | None) -> bool:
        """Override for record-level view authorization (fail-closed 403 when False)."""
        _ = (obj, user)
        return True

    def can_edit_record(self, obj: Any, user: DeckUser | None) -> bool:
        """Override for record-level edit authorization (fail-closed 403 when False)."""
        _ = (obj, user)
        return True

    def can_delete_record(self, obj: Any, user: DeckUser | None) -> bool:
        """Override for record-level delete authorization (fail-closed 403 when False)."""
        _ = (obj, user)
        return True

    def get_search_results(
        self,
        stmt: sa.Select[Any],
        search_term: str,
        user: DeckUser | None,
    ) -> tuple[sa.Select[Any], bool]:
        """Override to customize SQL search filtering; returns ``(stmt, may_have_duplicates)``."""
        _ = (search_term, user)
        return stmt, False

    def has_custom_search_results(self) -> bool:
        return type(self).get_search_results is not ModelView.get_search_results

    def formfield_for_foreignkey(
        self,
        field_name: str,
        stmt: sa.Select[Any],
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> sa.Select[Any]:
        """Override to narrow FK dropdown/autocomplete choices for ``field_name``."""
        _ = (field_name, user, obj)
        return stmt

    def formfield_for_manytomany(
        self,
        field_name: str,
        stmt: sa.Select[Any],
        user: DeckUser | None,
        obj: Any | None = None,
    ) -> sa.Select[Any]:
        """Override to narrow M2M choices for ``field_name``."""
        _ = (field_name, user, obj)
        return stmt

    def get_changeform_initial_data(
        self,
        args: Mapping[str, str],
        user: DeckUser | None,
        *,
        auth: AuthProvider | None = None,
    ) -> dict[str, Any]:
        """Extract strictly allowlisted initial field values from create-form query parameters."""
        if not args:
            return {}
        if auth is not None:
            writable = set(self.allowed_form_fields(auth, user, mode="create", obj=None))
            hidden = auth.hidden_fields_for(user, self.meta.slug)
        else:
            ro = self.effective_readonly_fields(user, None)
            writable = {
                c
                for c in self.resolved_form_fields
                if c not in ro and c not in self.meta.sensitive_fields
            }
            hidden = frozenset()

        initial: dict[str, Any] = {}
        for key, raw_val in args.items():
            if not key or key.startswith("_") or key in hidden or key in self.meta.sensitive_fields:
                continue
            if key in self.file_fields:
                continue
            if key in self.virtual_fields_by_name:
                vf = self.virtual_fields_by_name[key]
                if "create" in vf.modes:
                    with contextlib.suppress(ValueError):
                        initial[key] = coerce_form_value(raw_val, vf.to_field_meta())
                continue
            if key not in writable:
                continue
            fmeta = self.meta.fields_by_name.get(key)
            if fmeta is None or fmeta.primary_key or fmeta.is_computed:
                continue
            with contextlib.suppress(ValueError):
                initial[key] = coerce_form_value(raw_val, fmeta)
        return initial

    def save_related(
        self,
        obj: Any,
        *,
        is_created: bool,
        user: DeckUser | None,
        inline_diffs: Sequence[Mapping[str, Any]],
    ) -> None:
        """Optional hook executed right after inline child rows flush, before commit."""
        _ = (obj, is_created, user, inline_diffs)

    def validate_batch(
        self,
        changes: Sequence[tuple[Any, Mapping[str, Any]]],
        user: DeckUser | None,
    ) -> dict[str, list[str]]:
        """Optional cross-row validation hook for ``inline_edit_mode = 'batch'`` saves."""
        _ = (changes, user)
        return {}

    def get_urls(self) -> Sequence[ModelURL]:
        """Override to register custom sub-routes mounted under ``/<slug>/<rule>``."""
        return ()

    def get_view_on_site_url(self, obj: Any) -> str | None:
        """Resolve and validate ``view_on_site`` for ``obj`` (rejects unsafe URL schemes)."""
        raw_spec: Any = None
        if "view_on_site" in self.__dict__:
            raw_spec = self.__dict__["view_on_site"]
        else:
            for cls in self.__class__.__mro__:
                if "view_on_site" in cls.__dict__:
                    raw_spec = cls.__dict__["view_on_site"]
                    break
        if raw_spec is None:
            return None
        candidate: str | None = None
        if isinstance(raw_spec, staticmethod):
            candidate = raw_spec.__func__(obj)
        elif callable(raw_spec):
            try:
                sig = inspect.signature(raw_spec)
                n_params = len(sig.parameters)
                first_name = next(iter(sig.parameters), "")
                if first_name == "self" or n_params >= 2:
                    candidate = raw_spec(self, obj)
                else:
                    candidate = raw_spec(obj)
            except (TypeError, ValueError):
                candidate = raw_spec(obj)
        elif isinstance(raw_spec, str):
            vals: dict[str, Any] = {
                f.name: getattr(obj, f.name, "") for f in self.meta.fields if not f.is_sensitive
            }
            if len(self.meta.primary_keys) == 1:
                vals.setdefault("pk", getattr(obj, self.meta.primary_keys[0].name, ""))
            with contextlib.suppress(KeyError, ValueError, TypeError):
                candidate = raw_spec.format_map(vals)
        if not candidate or not isinstance(candidate, str):
            return None
        clean = candidate.strip()
        return clean if is_safe_display_url(clean) else None

    def resolve_fieldsets(
        self,
        visible_fields: Sequence[str],
        errors: Mapping[str, Sequence[str]] | None = None,
        *,
        user: DeckUser | None = None,
        obj: Any | None = None,
    ) -> list[dict[str, Any]]:
        """Normalize legacy ``(title, cols)`` and ``Fieldset(...)`` into structured row groups."""
        vis_set = set(visible_fields)
        err_map = errors or {}
        out: list[dict[str, Any]] = []
        used: set[str] = set()
        active_fieldsets = self.get_fieldsets(user, obj)

        if active_fieldsets:
            for entry in active_fieldsets:
                raw_rows: Sequence[FieldRow]
                if isinstance(entry, Fieldset):
                    title = entry.title
                    raw_rows = entry.fields
                    desc = entry.description
                    collapsible = entry.collapsible
                    collapsed = entry.collapsed
                    icon = entry.icon
                else:
                    title, raw_rows = entry[0], entry[1]
                    desc = ""
                    collapsible = False
                    collapsed = False
                    icon = None
                rows: list[list[str]] = []
                flat: list[str] = []
                for item in raw_rows:
                    if isinstance(item, (tuple, list)):
                        row_cols = [c for c in item if c in vis_set and c not in used]
                    else:
                        row_cols = [item] if (item in vis_set and item not in used) else []
                    if row_cols:
                        rows.append(row_cols)
                        flat.extend(row_cols)
                        used.update(row_cols)
                if rows:
                    has_err = any(bool(err_map.get(c)) for c in flat)
                    out.append(
                        {
                            "title": title,
                            "description": desc,
                            "collapsible": collapsible,
                            "collapsed": bool(collapsed and not has_err),
                            "has_errors": has_err,
                            "icon": icon,
                            "rows": rows,
                            "flat_cols": flat,
                        }
                    )
            remaining = [c for c in visible_fields if c not in used]
            if remaining:
                has_rem_err = any(bool(err_map.get(c)) for c in remaining)
                out.append(
                    {
                        "title": "Additional Fields",
                        "description": "",
                        "collapsible": False,
                        "collapsed": False,
                        "has_errors": has_rem_err,
                        "icon": None,
                        "rows": [[c] for c in remaining],
                        "flat_cols": remaining,
                    }
                )
        else:
            vis_list = list(visible_fields)
            out.append(
                {
                    "title": f"{self.label} Details",
                    "description": "",
                    "collapsible": False,
                    "collapsed": False,
                    "has_errors": any(bool(err_map.get(c)) for c in vis_list),
                    "icon": None,
                    "rows": [[c] for c in vis_list],
                    "flat_cols": vis_list,
                }
            )
        return out

    def format_record_repr(
        self,
        obj: Any,
        *,
        auth: AuthProvider | None = None,
        user: DeckUser | None = None,
    ) -> str:
        """Human-friendly single-line label respecting RBAC hidden/masked field policies."""
        hidden = auth.hidden_fields_for(user, self.meta.slug) if auth is not None else frozenset()
        masked = auth.masked_fields_for(user, self.meta.slug) if auth is not None else frozenset()

        def _render_candidate(col_name: str) -> str | None:
            if col_name in hidden or col_name in self.meta.sensitive_fields:
                return None
            val = getattr(obj, col_name, None)
            if not val:
                return None
            if auth is not None and col_name in masked:
                return str(auth.mask_field_value(user, self.meta.slug, col_name, val))
            return str(val)

        if self.display_column and hasattr(obj, self.display_column):
            rendered = _render_candidate(self.display_column)
            if rendered is not None:
                return rendered
        for candidate in (
            "full_name",
            "name",
            "title",
            "order_number",
            "ticket_key",
            "code",
            "sku",
            "username",
            "slug",
            "email",
        ):
            if candidate in self.meta.fields_by_name:
                rendered = _render_candidate(candidate)
                if rendered is not None:
                    return rendered
        pk_str = ", ".join(str(getattr(obj, pk.name, "")) for pk in self.meta.primary_keys)
        return f"{self.label} #{pk_str}"

    def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
        """Override to enforce row-level multi-tenant filtering across all endpoints."""
        return stmt

    def visible_list_columns(self, auth: AuthProvider, user: DeckUser | None) -> tuple[str, ...]:
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        excluded = hidden | set(self.meta.sensitive_fields)
        raw_cols = self.get_list_display(user)
        out: list[str] = []
        seen: set[str] = set()
        for c in raw_cols:
            if c in excluded or c in seen or c.startswith("_"):
                continue
            if (
                c in self.meta.fields_by_name
                or c in self.meta.relationships_by_name
                or c in self.display_fields
                or (getattr(self.model, c, None) is not None and not callable(getattr(self.model, c, None)))
            ):
                out.append(c)
                seen.add(c)
        return tuple(out)

    def allowed_form_fields(
        self,
        auth: AuthProvider,
        user: DeckUser | None,
        *,
        mode: str = "edit",
        obj: Any | None = None,
    ) -> tuple[str, ...]:
        """Strict allowlist of writable ORM form fields (mass-assignment barrier)."""
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        rbac_readonly = auth.readonly_fields_for(user, self.meta.slug)
        dynamic_readonly = self.effective_readonly_fields(user, obj)
        allowed: list[str] = []
        for col in self.resolved_form_fields:
            if col in hidden or col in self.meta.sensitive_fields:
                continue
            if col in dynamic_readonly:
                continue
            if mode == "edit" and col in rbac_readonly:
                continue
            fmeta = self.meta.fields_by_name.get(col)
            if mode == "edit" and fmeta is not None and fmeta.primary_key:
                continue
            allowed.append(col)
        return tuple(allowed)

    def visible_form_fields(
        self,
        auth: AuthProvider,
        user: DeckUser | None,
        *,
        mode: str = "edit",
        obj: Any | None = None,
    ) -> tuple[str, ...]:
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        form_excluded = set(self.form_excluded_columns) | set(self.meta.sensitive_fields) | hidden
        if self.soft_delete_column:
            form_excluded.add(self.soft_delete_column)
        out = [c for c in self.resolved_form_fields if c not in form_excluded]
        seen = set(out)
        # Include dynamic readonly fields & @display methods referenced by dynamic hooks
        extra_candidates: list[str] = list(self.get_readonly_fields(user, obj))
        for fs in self.get_fieldsets(user, obj):
            fs_rows = fs.fields if isinstance(fs, Fieldset) else fs[1]
            for row_item in fs_rows:
                cols_in_item = row_item if isinstance(row_item, (tuple, list)) else (row_item,)
                for col_candidate in cols_in_item:
                    if col_candidate in self.display_fields or col_candidate in extra_candidates:
                        extra_candidates.append(col_candidate)
        for c in extra_candidates:
            if (
                c not in seen
                and c not in form_excluded
                and (
                    c in self.meta.fields_by_name
                    or c in self.meta.relationships_by_name
                    or c in self.display_fields
                )
            ):
                out.append(c)
                seen.add(c)
        # Include active VirtualFields for the requested mode
        for vf in self.extra_form_fields:
            if (
                vf.name in self.virtual_fields_by_name
                and mode in vf.modes
                and vf.name not in hidden
                and vf.name not in seen
            ):
                out.append(vf.name)
                seen.add(vf.name)
        return tuple(out)

    def format_cell(
        self,
        col_name: str,
        obj: Any,
        *,
        auth: AuthProvider,
        user: DeckUser | None,
        media_url_builder: Callable[[str, Any], str | None] | None = None,
        rel_repr: Callable[[type[Any], Any], str] | None = None,
        rel_url_builder: Callable[[type[Any], Any], str | None] | None = None,
    ) -> Markup | str:
        """Format one table/detail cell with @display support, RBAC field masking, and XSS-safe output."""
        d_spec = self.display_fields.get(col_name)
        raw_val = getattr(self, d_spec.handler_name)(obj) if d_spec is not None else getattr(obj, col_name, None)

        if col_name in auth.masked_fields_for(user, self.meta.slug):
            masked = auth.mask_field_value(user, self.meta.slug, col_name, raw_val)
            return Markup(f'<span class="dk-masked">{Markup.escape(str(masked or self.empty_value_display))}</span>')

        empty_marker = (
            d_spec.empty_value
            if (d_spec is not None and d_spec.empty_value is not None)
            else self.empty_value_display
        )

        formatter = self._formatters.get(col_name)
        if formatter is not None:
            if isinstance(formatter, (ImageFormatter, FileFormatter)) and media_url_builder is not None:
                return formatter.format_with_url(raw_val, media_url_builder(col_name, obj))
            if isinstance(formatter, Formatter):
                return formatter.format(raw_val, obj)
            return formatter(raw_val, obj)

        if d_spec is not None:
            if raw_val is None:
                return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')
            if d_spec.boolean:
                return BooleanIconFormatter().format(raw_val, obj)
            if isinstance(d_spec.tone, Mapping):
                return BadgeFormatter(d_spec.tone).format(raw_val, obj)
            if isinstance(d_spec.tone, str) and d_spec.tone:
                tone_cls = normalize_tone(d_spec.tone)
                return Markup(
                    f'<span class="dk-badge dk-badge-{tone_cls}">'
                    f'<span class="dk-dot" aria-hidden="true"></span>'
                    f"{escape(str(raw_val))}</span>"
                )
            if isinstance(raw_val, Markup):
                return raw_val
            return str(raw_val)

        rel_meta = self.meta.relationships_by_name.get(col_name)
        if rel_meta is not None:
            if raw_val is None:
                return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')

            def _fmt_rel_item(item: Any) -> str:
                if rel_repr is not None:
                    return rel_repr(rel_meta.target_model, item)
                return str(item)

            def _render_rel_badge(item: Any, *, chip: bool) -> str:
                label = Markup.escape(_fmt_rel_item(item))
                target_url = rel_url_builder(rel_meta.target_model, item) if rel_url_builder else None
                cls = "dk-chip dk-link" if chip else "dk-rel-val dk-link"
                if target_url:
                    return f'<a href="{Markup.escape(target_url)}" class="{cls}">{label}</a>'
                plain_cls = "dk-chip" if chip else "dk-rel-val"
                return f'<span class="{plain_cls}">{label}</span>'

            if rel_meta.uselist:
                items = list(raw_val)
                if not items:
                    return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')
                chips = "".join(_render_rel_badge(item, chip=True) for item in items[:3])
                extra = (
                    f'<span class="dk-muted dk-mono">+{len(items) - 3}</span>'
                    if len(items) > 3
                    else ""
                )
                return Markup(f'<span class="dk-chip-group">{chips}{extra}</span>')
            return Markup(_render_rel_badge(raw_val, chip=False))

        if raw_val is None:
            return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')
        fmeta = self.meta.fields_by_name.get(col_name)
        if fmeta is not None and fmeta.field_type == "array" and isinstance(raw_val, (list, tuple)):
            if not raw_val:
                return Markup(f'<span class="dk-null">{escape(empty_marker)}</span>')
            chips = "".join(f'<span class="dk-chip">{Markup.escape(str(it))}</span>' for it in raw_val[:4])
            extra = (
                f'<span class="dk-muted dk-mono">+{len(raw_val) - 4}</span>'
                if len(raw_val) > 4
                else ""
            )
            return Markup(f'<span class="dk-chip-group">{chips}{extra}</span>')
        if isinstance(raw_val, (dict, list)):
            compact = json.dumps(raw_val, separators=(",", ":"))
            if len(compact) > 48:
                compact = f"{compact[:47]}…"
            return Markup(f'<code class="dk-code">{Markup.escape(compact)}</code>')
        return str(raw_val)

    def validate(self, data: Mapping[str, Any], *, obj: Any | None = None) -> dict[str, list[str]]:
        """Optional custom validation hook returning {field_name: [error_messages]}."""
        return {}

    def on_model_change(self, obj: Any, *, is_created: bool, user: DeckUser | None) -> None:
        """Optional lifecycle hook called right before flush/commit."""

    def invoke_on_model_change(
        self,
        obj: Any,
        *,
        is_created: bool,
        user: DeckUser | None,
        virtual_data: Mapping[str, Any] | None = None,
    ) -> None:
        """Call ``on_model_change``, forwarding ``virtual_data`` if the subclass accepts it."""
        fn = self.on_model_change
        accepts_vd = False
        with contextlib.suppress(TypeError, ValueError):
            sig = inspect.signature(fn)
            accepts_vd = "virtual_data" in sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
        if accepts_vd:
            fn(obj, is_created=is_created, user=user, virtual_data=dict(virtual_data or {}))  # type: ignore[call-arg]
        else:
            fn(obj, is_created=is_created, user=user)

    def on_model_delete(self, obj: Any, *, user: DeckUser | None) -> None:
        """Optional lifecycle hook called right before deletion."""

    def extract_snapshot(self, obj: Any) -> dict[str, Any]:
        """Extract scalar field snapshot for audit diff computation."""
        return {f.name: getattr(obj, f.name, None) for f in self.meta.fields}

    def get_form_validator(
        self,
    ) -> Callable[[Mapping[str, Any], Any | None, bool], Mapping[str, list[str]]] | None:
        """Resolve class-level or instance-level form_validator without accidental method binding."""
        if "form_validator" in self.__dict__:
            raw_inst = self.__dict__["form_validator"]
            if callable(raw_inst):
                return raw_inst  # type: ignore[no-any-return]
            return None
        for cls in self.__class__.__mro__:
            if "form_validator" in cls.__dict__:
                raw_v = cls.__dict__["form_validator"]
                if isinstance(raw_v, staticmethod):
                    return raw_v.__func__
                if callable(raw_v):
                    return raw_v  # type: ignore[no-any-return]
                return None
        return None

    def requires_approval(
        self,
        user: DeckUser | None,
        operation: str,
        *,
        obj: Any | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> bool:
        """Return True when operation (create/edit/delete/action) requires Maker-Checker approval."""
        rule: Any = None
        if "approval_required" in self.__dict__:
            rule = self.__dict__["approval_required"]
        else:
            for cls in self.__class__.__mro__:
                if "approval_required" in cls.__dict__:
                    raw_r = cls.__dict__["approval_required"]
                    rule = raw_r.__func__ if isinstance(raw_r, staticmethod) else raw_r
                    break
        if rule is None:
            return False
        if isinstance(rule, bool):
            return rule
        if callable(rule):
            return bool(rule(user, operation, obj, dict(payload or {})))
        return operation in tuple(rule)

    def compute_version_token(
        self,
        obj: Any,
        *,
        auth: AuthProvider | None = None,
        user: DeckUser | None = None,
    ) -> str:
        """Compute deterministic optimistic concurrency token for ``obj``."""
        if self.version_column and hasattr(obj, self.version_column):
            return str(getattr(obj, self.version_column, ""))
        if auth is not None:
            cols = sorted(self.allowed_form_fields(auth, user, mode="edit", obj=obj))
        else:
            cols = sorted(f.name for f in self.meta.fields if not f.primary_key)
        snapshot = [
            (col, serialize_audit_value(getattr(obj, col, None))) for col in cols
        ]
        raw = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def _is_condition_satisfied(
        self,
        field_name: str,
        values: Mapping[str, Any],
        obj: Any | None,
    ) -> bool:
        cond = self.field_conditions.get(field_name)
        if cond is None:
            return True
        src_field, op, expected = cond
        raw_src = values.get(src_field, getattr(obj, src_field, None) if obj is not None else None)
        if isinstance(raw_src, enum.Enum):
            src_str = str(raw_src.value)
        elif isinstance(raw_src, bool):
            src_str = "true" if raw_src else "false"
        elif raw_src is None:
            src_str = ""
        else:
            src_str = str(raw_src)

        if op == "eq":
            exp_str = ("true" if expected else "false") if isinstance(expected, bool) else str(expected)
            return src_str == exp_str
        if op == "neq":
            exp_str = ("true" if expected else "false") if isinstance(expected, bool) else str(expected)
            return src_str != exp_str
        if op == "in":
            vals = [str(v) for v in expected] if isinstance(expected, (list, tuple, set, frozenset)) else [str(expected)]
            return src_str in vals
        if op == "truthy":
            return bool(src_str) and src_str.lower() not in {"false", "0"}
        if op == "falsy":
            return (not src_str) or src_str.lower() in {"false", "0"}
        return True

    def apply_form_data(
        self,
        session: Session,
        obj: Any,
        form_data: Mapping[str, Any],
        *,
        auth: AuthProvider,
        user: DeckUser | None,
        mode: str,
        max_json_depth: int = 12,
        m2m_getter: Callable[[str], list[str]] | None = None,
        m2m_scope: Callable[[type[Any], sa.Select[Any]], sa.Select[Any]] | None = None,
        partial: bool = False,
        utc_passthrough: bool = False,
    ) -> dict[str, Any]:
        """Validate & apply only strictly allowed ORM form fields and return coerced ``virtual_data``."""
        target_obj_ctx = obj if mode == "edit" else None
        writable = set(self.allowed_form_fields(auth, user, mode=mode, obj=target_obj_ctx))
        masked = auth.masked_fields_for(user, self.meta.slug)
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        ro_fields = set(self.get_readonly_fields(user, target_obj_ctx)) | set(
            auth.readonly_fields_for(user, self.meta.slug)
        )
        if mode == "edit":
            writable -= masked
        errors: dict[str, list[str]] = {}
        coerced_values: dict[str, Any] = {}
        virtual_data: dict[str, Any] = {}
        m2m_updates: dict[str, list[Any]] = {}

        # Process controlling fields first so field_conditions can evaluate against coerced values
        ordered_writable = sorted(
            writable,
            key=lambda fn: (1 if fn in self.field_conditions else 0, fn),
        )

        for field_name in ordered_writable:
            # Skip file upload columns here; they are processed via apply_file_uploads().
            if field_name in self.file_fields:
                continue
            if field_name in self.field_conditions and not self._is_condition_satisfied(
                field_name, coerced_values, target_obj_ctx
            ):
                continue
            fmeta = self.meta.fields_by_name.get(field_name)
            if fmeta is not None:
                if partial and field_name not in form_data:
                    continue
                if fmeta.field_type == "boolean":
                    if field_name in form_data:
                        raw_val: Any = form_data.get(field_name, "")
                    elif fmeta.nullable:
                        raw_val = None
                    else:
                        raw_val = ""
                elif field_name in form_data:
                    raw_val = form_data.get(field_name)
                elif mode == "edit":
                    continue
                else:
                    raw_val = None
                if (
                    fmeta.fk_target_model is not None
                    and isinstance(raw_val, str)
                    and raw_val.startswith("pk:")
                    and fmeta.field_type in {"string", "text"}
                ):
                    from urllib.parse import unquote

                    raw_val = unquote(raw_val[3:])
                try:
                    coerced_val = coerce_form_value(
                        raw_val,
                        fmeta,
                        max_json_depth=max_json_depth,
                        utc_passthrough=utc_passthrough,
                    )
                except ValueError as exc:
                    errors.setdefault(field_name, []).append(str(exc))
                    continue
                if (
                    fmeta.fk_target_model is not None
                    and coerced_val is not None
                    and not (mode == "edit" and getattr(obj, field_name, None) == coerced_val)
                ):
                    t_cls = fmeta.fk_target_model
                    t_view = (
                        self._deck._views_by_model.get(t_cls)
                        if self._deck is not None and hasattr(self._deck, "_views_by_model")
                        else None
                    )
                    t_meta = t_view.meta if t_view is not None else introspect_model(t_cls)
                    ref_col_name = fmeta.fk_target_column or (
                        t_meta.primary_keys[0].name if len(t_meta.primary_keys) == 1 else None
                    )
                    if ref_col_name and hasattr(t_cls, ref_col_name):
                        t_ref_col = getattr(t_cls, ref_col_name)
                        fk_stmt = sa.select(t_cls).where(t_ref_col == coerced_val)
                        if m2m_scope is not None:
                            fk_stmt = m2m_scope(t_cls, fk_stmt)
                        elif t_view is not None:
                            fk_stmt = t_view.scope_query(fk_stmt, user)
                        if t_view is not None and t_view.soft_delete_column:
                            t_sd = soft_delete_predicate(
                                t_view.meta, t_view.soft_delete_column, trashed=False
                            )
                            if t_sd is not None:
                                fk_stmt = fk_stmt.where(t_sd)
                        fk_stmt = self.formfield_for_foreignkey(
                            field_name, fk_stmt, user, obj=target_obj_ctx
                        )
                        fk_sess = (
                            self._deck.get_session(t_view.bind_key)
                            if (self._deck is not None and t_view is not None)
                            else session
                        )
                        if fk_sess.scalars(fk_stmt).first() is None:
                            errors.setdefault(field_name, []).append(
                                "Referenced record not found or outside your allowed scope."
                            )
                            continue
                coerced_values[field_name] = coerced_val
                continue

            rel_meta = self.meta.relationships_by_name.get(field_name)
            if rel_meta is not None and rel_meta.direction == "MANYTOMANY" and m2m_getter is not None:
                if partial and field_name not in form_data:
                    continue
                raw_ids = [v for v in m2m_getter(field_name) if v]
                t_cls = rel_meta.target_model
                t_view = (
                    self._deck._views_by_model.get(t_cls)
                    if self._deck is not None and hasattr(self._deck, "_views_by_model")
                    else None
                )
                target_meta = t_view.meta if t_view is not None else introspect_model(t_cls)
                decoded_pks: list[tuple[Any, ...]] = []
                for rid in raw_ids:
                    try:
                        decoded_pks.append(decode_pk(str(rid), target_meta))
                    except (InvalidPKError, ValueError):
                        errors.setdefault(field_name, []).append(f"Invalid reference ID: {rid}")
                if decoded_pks:
                    if len(target_meta.primary_keys) == 1:
                        pk_col = getattr(t_cls, target_meta.primary_keys[0].name)
                        t_stmt = sa.select(t_cls).where(pk_col.in_([p[0] for p in decoded_pks]))
                    else:
                        pk_cols = [getattr(t_cls, pk.name) for pk in target_meta.primary_keys]
                        t_stmt = sa.select(t_cls).where(sa.tuple_(*pk_cols).in_(decoded_pks))
                    if m2m_scope is not None:
                        t_stmt = m2m_scope(t_cls, t_stmt)
                    elif t_view is not None:
                        t_stmt = t_view.scope_query(t_stmt, user)
                    if t_view is not None and t_view.soft_delete_column:
                        t_sd = soft_delete_predicate(
                            t_view.meta, t_view.soft_delete_column, trashed=False
                        )
                        if t_sd is not None:
                            t_stmt = t_stmt.where(t_sd)
                    t_stmt = self.formfield_for_manytomany(
                        field_name, t_stmt, user, obj=target_obj_ctx
                    )
                    targets = list(session.scalars(t_stmt).all())
                    m2m_updates[field_name] = targets
                else:
                    m2m_updates[field_name] = []

        # Coerce declarative VirtualFields into virtual_data (NEVER setattr'd onto ORM obj!)
        for vf in self.extra_form_fields:
            if vf.name not in self.virtual_fields_by_name:
                continue
            if mode not in vf.modes or vf.name in hidden or vf.name in ro_fields:
                continue
            if mode == "edit" and vf.name in masked:
                continue
            if partial and vf.name not in form_data:
                continue
            if vf.name in self.field_conditions and not self._is_condition_satisfied(
                vf.name, coerced_values, target_obj_ctx
            ):
                continue
            vf_meta = vf.to_field_meta()
            if vf.field_type == "boolean":
                v_raw: Any = form_data.get(vf.name, "")
            elif vf.name in form_data:
                v_raw = form_data.get(vf.name)
            else:
                v_raw = vf.default
            try:
                v_coerced = coerce_form_value(
                    v_raw,
                    vf_meta,
                    max_json_depth=max_json_depth,
                    utc_passthrough=utc_passthrough,
                )
                if v_coerced is None and vf.default is not None and (v_raw is None or v_raw == ""):
                    v_coerced = vf.default
                virtual_data[vf.name] = v_coerced
            except ValueError as exc:
                errors.setdefault(vf.name, []).append(str(exc))

        if not errors:
            accepts_vd = False
            with contextlib.suppress(TypeError, ValueError):
                val_sig = inspect.signature(self.validate)
                accepts_vd = "virtual_data" in val_sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in val_sig.parameters.values()
                )
            if accepts_vd:
                custom_errors = self.validate(
                    coerced_values, obj=target_obj_ctx, virtual_data=dict(virtual_data)  # type: ignore[call-arg]
                )
            else:
                custom_errors = self.validate(coerced_values, obj=target_obj_ctx)
            for field_name, msgs in custom_errors.items():
                errors.setdefault(field_name, []).extend(msgs)

            validator_fn = self.get_form_validator()
            if validator_fn is not None:
                # Merge existing scalar fields on edit so Pydantic schemas don't fail on untouched readonly/file fields
                val_payload: dict[str, Any] = (
                    {**self.extract_snapshot(obj), **coerced_values}
                    if mode == "edit"
                    else dict(coerced_values)
                )
                ext_errors = validator_fn(
                    val_payload,
                    target_obj_ctx,
                    mode == "create",
                )
                visible_set = set(self.visible_form_fields(auth, user, mode=mode, obj=target_obj_ctx))
                for field_name, msgs in ext_errors.items():
                    target_key = field_name if (field_name in visible_set or field_name == "__all__") else "__all__"
                    if target_key == "__all__" and field_name != "__all__":
                        errors.setdefault("__all__", []).extend(f"{field_name}: {m}" for m in msgs)
                    else:
                        errors.setdefault(target_key, []).extend(msgs)

        if errors:
            raise ValidationError(errors)

        for field_name, val in coerced_values.items():
            setattr(obj, field_name, val)
        for rel_name, items in m2m_updates.items():
            setattr(obj, rel_name, items)
        return virtual_data

    def apply_file_uploads(
        self,
        obj: Any,
        files: Mapping[str, Any],
        form_data: Mapping[str, Any],
        *,
        auth: AuthProvider,
        user: DeckUser | None,
        mode: str,
        default_max_bytes: int,
    ) -> tuple[list[tuple[FileFieldConfig, str]], list[tuple[FileFieldConfig, str]]]:
        """Validate and persist multipart uploads for configured file_fields.

        Returns `(newly_stored, old_orphans_to_delete_after_commit)` for transactional safety.
        """
        if not self.file_fields:
            return [], []
        writable = set(
            self.allowed_form_fields(auth, user, mode=mode, obj=obj if mode == "edit" else None)
        )
        if mode == "edit":
            writable -= auth.masked_fields_for(user, self.meta.slug)
        newly_stored: list[tuple[FileFieldConfig, str]] = []
        orphans: list[tuple[FileFieldConfig, str]] = []
        errors: dict[str, list[str]] = {}

        try:
            for field_name, cfg in self.file_fields.items():
                if field_name not in writable:
                    continue
                existing_key = getattr(obj, field_name, None)
                clear_flag = str(form_data.get(f"_clear_{field_name}", "")).lower() in {"1", "true", "on"}
                upload = files.get(field_name)
                has_new = upload is not None and bool(getattr(upload, "filename", ""))

                if has_new and upload is not None:
                    try:
                        stored = store_validated_upload(
                            upload.stream,
                            filename=str(upload.filename),
                            config=cfg,
                            default_max_bytes=default_max_bytes,
                        )
                        setattr(obj, field_name, stored.key)
                        newly_stored.append((cfg, stored.key))
                        if existing_key and cfg.delete_orphan:
                            orphans.append((cfg, str(existing_key)))
                    except ValueError as exc:
                        errors.setdefault(field_name, []).append(str(exc))
                    finally:
                        with contextlib.suppress(Exception):
                            upload.stream.close()
                elif clear_flag and existing_key:
                    fmeta = self.meta.fields_by_name.get(field_name)
                    if fmeta is not None and not fmeta.nullable and not fmeta.has_default:
                        errors.setdefault(field_name, []).append("This file field is required.")
                    else:
                        setattr(obj, field_name, None)
                        if cfg.delete_orphan:
                            orphans.append((cfg, str(existing_key)))
                elif mode == "create" and not existing_key:
                    fmeta = self.meta.fields_by_name.get(field_name)
                    if fmeta is not None and not fmeta.nullable and not fmeta.has_default:
                        errors.setdefault(field_name, []).append("This file is required.")

            if errors:
                for cfg, key in newly_stored:
                    cfg.storage.delete(key)
                raise ValidationError(errors)
        except ValidationError:
            raise
        except BaseException:
            for cfg, key in newly_stored:
                with contextlib.suppress(Exception):
                    cfg.storage.delete(key)
            raise

        return newly_stored, orphans

    def apply_inline_forms(
        self,
        session: Session,
        parent_obj: Any,
        form_data: Mapping[str, Any],
        *,
        auth: AuthProvider,
        user: DeckUser | None,
        max_json_depth: int = 12,
        files: Mapping[str, Any] | None = None,
        default_max_bytes: int = 5 * 1024 * 1024,
        views_by_model: Mapping[type[Any], Any] | None = None,
        inlines: Sequence[InlineModelView] | None = None,
        newly_stored_files: list[tuple[FileFieldConfig, str]] | None = None,
        orphan_files: list[tuple[FileFieldConfig, str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Process embedded One-to-Many inline child rows with strict IDOR checks, file uploads, and audit diffs."""
        active_inlines = tuple(inlines) if inlines is not None else tuple(self.get_inlines(user, parent_obj))
        if not active_inlines:
            return []

        events: list[tuple[InlineModelView, str, Any, dict[str, Any], str | None]] = []
        local_newly_stored: list[tuple[FileFieldConfig, str]] = []
        local_orphans: list[tuple[FileFieldConfig, str]] = []
        file_map = files or {}

        try:
            extra_sens = (
                self._deck.config.extra_sensitive_patterns
                if self._deck is not None and hasattr(self._deck, "config")
                else ()
            )
            for inline in active_inlines:
                prefix = f"inline__{inline.meta.slug}__"
                fk_col_name = inline.resolve_fk_column(self.meta)
                fk_fmeta_inl = inline.meta.fields_by_name.get(fk_col_name)
                parent_match_col = (
                    getattr(fk_fmeta_inl, "fk_target_column", None)
                    or self.meta.primary_keys[0].name
                )
                parent_pk = getattr(parent_obj, parent_match_col)
                child_view = views_by_model.get(inline.model) if views_by_model is not None else None
                eff_child_slug = child_view.meta.slug if child_view is not None else inline.meta.slug
                child_hidden = auth.hidden_fields_for(user, eff_child_slug)
                child_rbac_ro = auth.readonly_fields_for(user, eff_child_slug)
                child_masked = auth.masked_fields_for(user, eff_child_slug)
                writable_inline_cols = tuple(
                    c
                    for c in inline.editable_columns
                    if c not in child_hidden and c not in inline.resolved_readonly_fields
                )

                # Discover submitted row indices across both form_data and multipart files
                row_indices: set[int] = set()
                for key in form_data:
                    if key.startswith(prefix):
                        rest = key[len(prefix) :]
                        idx_part = rest.split("__", 1)[0]
                        if idx_part.isdigit():
                            row_indices.add(int(idx_part))
                for key in file_map:
                    if key.startswith(prefix):
                        rest = key[len(prefix) :]
                        idx_part = rest.split("__", 1)[0]
                        if idx_part.isdigit():
                            row_indices.add(int(idx_part))

                # Preload existing children belonging ONLY to this parent + scoped + non-soft-deleted (IDOR barrier!)
                existing_by_key: dict[str, Any] = {}
                if parent_pk is not None:
                    fk_attr = getattr(inline.model, fk_col_name)
                    child_stmt = sa.select(inline.model).where(fk_attr == parent_pk)
                    if child_view is not None:
                        child_stmt = child_view.scope_query(child_stmt, user)
                        child_sd = soft_delete_predicate(
                            child_view.meta, child_view.soft_delete_column, trashed=False
                        )
                        if child_sd is not None:
                            child_stmt = child_stmt.where(child_sd)
                    child_stmt = inline.scope_query(child_stmt, user, parent_obj)
                    for row in session.scalars(child_stmt).all():
                        row_key = encode_pk(extract_pk(row, inline.meta))
                        existing_by_key[row_key] = row

                existing_surviving_keys = set(existing_by_key.keys())
                submitted_existing_keys: set[str] = set()
                created_count = 0
                errors: dict[str, list[str]] = {}
                surviving_rows_payload: list[dict[str, Any]] = []

                can_add = inline.can_add_inline(parent_obj, user)
                can_edit = inline.can_edit_inline(parent_obj, user)
                can_delete = inline.can_delete_inline(parent_obj, user)

                for idx in sorted(row_indices):
                    row_prefix = f"{prefix}{idx}__"
                    raw_pk = str(form_data.get(f"{row_prefix}_pk", "")).strip()
                    marked_delete = str(form_data.get(f"{row_prefix}_delete", "")).lower() in {
                        "1",
                        "true",
                        "on",
                    }

                    if raw_pk:
                        try:
                            decoded_pk = decode_pk(raw_pk, inline.meta)
                            canonical_key = encode_pk(decoded_pk)
                        except (InvalidPKError, ValueError):
                            errors.setdefault(inline.meta.slug, []).append(
                                f"Row {idx + 1}: invalid child ID."
                            )
                            continue
                        child_obj = existing_by_key.get(canonical_key)
                        if child_obj is None:
                            # Strict IDOR prevention: reject tampering with another parent's / out-of-scope child row!
                            raise PermissionDeniedError(
                                f"Inline record {raw_pk} does not belong to this {self.label}."
                            )
                        submitted_existing_keys.add(canonical_key)
                        before_snap = {
                            c: getattr(child_obj, c, None) for c in inline.editable_columns
                        }
                        if marked_delete:
                            if (
                                not can_delete
                                or not auth.has_permission(
                                    user, f"{eff_child_slug}:delete", model_slug=eff_child_slug, obj=child_obj
                                )
                                or (child_view is not None and not child_view.can_delete_record(child_obj, user))
                            ):
                                raise PermissionDeniedError("Not authorized to delete inline items.")
                            if child_view is not None and child_view.soft_delete_column:
                                sd_fmeta = child_view.meta.fields_by_name.get(child_view.soft_delete_column)
                                if sd_fmeta is not None:
                                    setattr(
                                        child_obj,
                                        child_view.soft_delete_column,
                                        True if sd_fmeta.field_type == "boolean" else datetime.now(timezone.utc),
                                    )
                                else:
                                    session.delete(child_obj)
                            else:
                                for f_col, f_cfg in inline.file_fields.items():
                                    old_k = getattr(child_obj, f_col, None)
                                    if old_k and f_cfg.delete_orphan:
                                        local_orphans.append((f_cfg, str(old_k)))
                                session.delete(child_obj)
                            existing_surviving_keys.discard(canonical_key)
                            events.append((inline, "delete", child_obj, before_snap, canonical_key))
                            continue
                        if (
                            not can_edit
                            or not auth.has_permission(
                                user, f"{eff_child_slug}:edit", model_slug=eff_child_slug, obj=child_obj
                            )
                            or (child_view is not None and not child_view.can_edit_record(child_obj, user))
                        ):
                            # Keep surviving unmodified row in validate_rows payload
                            surviving_rows_payload.append(
                                {
                                    **before_snap,
                                    "_pk": canonical_key,
                                    "_is_new": False,
                                    "_row_index": idx,
                                }
                            )
                            continue
                        target_obj = child_obj
                        op_kind = "edit"
                        recorded_key: str | None = canonical_key
                    else:
                        if marked_delete:
                            continue
                        # Skip completely blank newly-added rows (check both scalar fields and uploaded files)
                        has_any_val = any(
                            str(form_data.get(f"{row_prefix}{col}", "")).strip() != ""
                            for col in writable_inline_cols
                            if col not in inline.file_fields
                        ) or any(
                            file_map.get(f"{row_prefix}{col}") is not None
                            and bool(getattr(file_map.get(f"{row_prefix}{col}"), "filename", ""))
                            for col in writable_inline_cols
                            if col in inline.file_fields
                        )
                        if not has_any_val:
                            continue
                        if not can_add or not auth.has_permission(
                            user, f"{eff_child_slug}:create", model_slug=eff_child_slug
                        ):
                            raise PermissionDeniedError("Not authorized to create inline items.")
                        target_obj = inline.model()
                        setattr(target_obj, fk_col_name, parent_pk)
                        session.add(target_obj)
                        before_snap = {}
                        op_kind = "create"
                        recorded_key = None
                        created_count += 1

                    row_dict: dict[str, Any] = {
                        "_pk": recorded_key or "",
                        "_is_new": op_kind == "create",
                        "_row_index": idx,
                    }
                    for col in writable_inline_cols:
                        if op_kind == "edit" and (col in child_rbac_ro or col in child_masked):
                            row_dict[col] = getattr(target_obj, col, None)
                            continue
                        fmeta = inline.meta.fields_by_name[col]
                        if col in inline.file_fields:
                            cfg = inline.file_fields[col]
                            existing_key = getattr(target_obj, col, None)
                            clear_flag = str(form_data.get(f"{row_prefix}_clear_{col}", "")).lower() in {
                                "1",
                                "true",
                                "on",
                            }
                            upload = file_map.get(f"{row_prefix}{col}")
                            has_new = upload is not None and bool(getattr(upload, "filename", ""))
                            if has_new and upload is not None:
                                try:
                                    stored = store_validated_upload(
                                        upload.stream,
                                        filename=str(upload.filename),
                                        config=cfg,
                                        default_max_bytes=default_max_bytes,
                                    )
                                    setattr(target_obj, col, stored.key)
                                    local_newly_stored.append((cfg, stored.key))
                                    if existing_key and cfg.delete_orphan:
                                        local_orphans.append((cfg, str(existing_key)))
                                    row_dict[col] = stored.key
                                except ValueError as exc:
                                    errors.setdefault(f"{inline.meta.slug}[{idx}].{col}", []).append(str(exc))
                                finally:
                                    with contextlib.suppress(Exception):
                                        upload.stream.close()
                            elif clear_flag and existing_key:
                                if not fmeta.nullable and not fmeta.has_default:
                                    errors.setdefault(f"{inline.meta.slug}[{idx}].{col}", []).append(
                                        "This file field is required."
                                    )
                                else:
                                    setattr(target_obj, col, None)
                                    if cfg.delete_orphan:
                                        local_orphans.append((cfg, str(existing_key)))
                                    row_dict[col] = None
                            elif op_kind == "create" and not existing_key and not fmeta.nullable and not fmeta.has_default:
                                errors.setdefault(f"{inline.meta.slug}[{idx}].{col}", []).append(
                                    "This file is required."
                                )
                            else:
                                row_dict[col] = existing_key
                            continue

                        if fmeta.field_type == "boolean":
                            raw_val: Any = (
                                form_data.get(f"{row_prefix}{col}", None)
                                if fmeta.nullable
                                else form_data.get(f"{row_prefix}{col}", "false")
                            )
                        else:
                            raw_val = form_data.get(f"{row_prefix}{col}")
                        try:
                            val = coerce_form_value(raw_val, fmeta, max_json_depth=max_json_depth)
                            if (
                                fmeta.fk_target_model is not None
                                and val is not None
                                and not (op_kind == "edit" and getattr(target_obj, col, None) == val)
                            ):
                                fk_cls = fmeta.fk_target_model
                                fk_view = (
                                    views_by_model.get(fk_cls)
                                    if views_by_model is not None
                                    else None
                                )
                                fk_meta = fk_view.meta if fk_view is not None else introspect_model(fk_cls)
                                ref_col = fmeta.fk_target_column or (
                                    fk_meta.primary_keys[0].name
                                    if len(fk_meta.primary_keys) == 1
                                    else None
                                )
                                if ref_col and hasattr(fk_cls, ref_col):
                                    fk_q = sa.select(fk_cls).where(getattr(fk_cls, ref_col) == val)
                                    if fk_view is not None:
                                        fk_q = fk_view.scope_query(fk_q, user)
                                        fk_sd = soft_delete_predicate(
                                            fk_view.meta, fk_view.soft_delete_column, trashed=False
                                        )
                                        if fk_sd is not None:
                                            fk_q = fk_q.where(fk_sd)
                                    fk_sess = (
                                        self._deck.get_session(fk_view.bind_key)
                                        if (self._deck is not None and fk_view is not None)
                                        else session
                                    )
                                    if fk_sess.scalars(fk_q).first() is None:
                                        raise ValueError(
                                            "Referenced record not found or outside your allowed scope."
                                        )
                            setattr(target_obj, col, val)
                            row_dict[col] = val
                        except ValueError as exc:
                            errors.setdefault(f"{inline.meta.slug}[{idx}].{col}", []).append(str(exc))

                    surviving_rows_payload.append(row_dict)
                    if op_kind in {"create", "edit"}:
                        events.append((inline, op_kind, target_obj, before_snap, recorded_key))

                # Include unsubmitted surviving existing children so validate_rows & max_rows cannot be bypassed
                for rem_key, rem_obj in existing_by_key.items():
                    if rem_key in existing_surviving_keys and rem_key not in submitted_existing_keys:
                        surviving_rows_payload.append(
                            {
                                **{c: getattr(rem_obj, c, None) for c in inline.editable_columns},
                                "_pk": rem_key,
                                "_is_new": False,
                                "_row_index": -1,
                            }
                        )

                total_surviving = len(existing_surviving_keys) + created_count
                if total_surviving > inline.max_rows:
                    errors.setdefault(inline.meta.slug, []).append(
                        f"Maximum {inline.max_rows} inline rows allowed."
                    )

                if inline.min_num > 0 and total_surviving < inline.min_num:
                    errors.setdefault(inline.meta.slug, []).append(
                        f"At least {inline.min_num} {inline.display_label.lower()} row(s) required."
                    )

                if not errors:
                    row_val_errs = inline.validate_rows(
                        surviving_rows_payload, parent_obj=parent_obj, user=user
                    )
                    for err_k, err_msgs in row_val_errs.items():
                        norm_k = (
                            err_k
                            if err_k == inline.meta.slug
                            or err_k.startswith(f"{inline.meta.slug}[")
                            else inline.meta.slug
                        )
                        errors.setdefault(norm_k, []).extend(err_msgs)

                if errors:
                    raise ValidationError(errors)

            session.flush()
        except BaseException:
            for cfg, key in local_newly_stored:
                with contextlib.suppress(Exception):
                    cfg.storage.delete(key)
            raise

        if newly_stored_files is not None:
            newly_stored_files.extend(local_newly_stored)
        if orphan_files is not None:
            orphan_files.extend(local_orphans)

        out: list[dict[str, Any]] = []
        for inline, op_kind, target_obj, before_snap, recorded_key in events:
            pk_str = (
                recorded_key
                if recorded_key is not None
                else encode_pk(extract_pk(target_obj, inline.meta))
            )
            after_snap = (
                {}
                if op_kind == "delete"
                else {c: getattr(target_obj, c, None) for c in inline.editable_columns}
            )
            diff = compute_diff(
                before_snap,
                after_snap,
                sensitive_fields=inline.meta.sensitive_fields,
                extra_sensitive_patterns=extra_sens,
            )
            if diff:
                out.append(
                    {
                        "inline_slug": inline.meta.slug,
                        "inline_label": inline.display_label,
                        "op": op_kind,
                        "child_pk": pk_str,
                        "changes": diff,
                    }
                )
        return out
