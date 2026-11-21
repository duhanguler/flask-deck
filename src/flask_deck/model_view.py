from __future__ import annotations

import contextlib
import enum
import json
import math
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar, Literal

import sqlalchemy as sa
from markupsafe import Markup
from sqlalchemy.orm import Session

from flask_deck.auth import AuthProvider, DeckUser
from flask_deck.exceptions import PermissionDeniedError, ValidationError
from flask_deck.formatters import (
    BadgeFormatter,
    BooleanIconFormatter,
    CodeFormatter,
    FileFormatter,
    Formatter,
    ImageFormatter,
    RelativeTimeFormatter,
)
from flask_deck.i18n import from_user_timezone
from flask_deck.introspection import FieldMeta, ModelMeta, humanize, introspect_model
from flask_deck.query import CountMode, PaginationMode, QuickTab
from flask_deck.security import check_json_depth, is_safe_display_url
from flask_deck.storage import FileFieldConfig, store_validated_upload


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
    handler_name: str
    icon: str = "zap"
    confirm: bool = False
    variant: str = "default"  # default | danger
    permission: str | None = None
    row_action: bool = False
    bulk_action: bool = True
    require_confirm_text: bool = False
    fields: tuple[ActionField, ...] = ()
    async_job: bool = False


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
    can_create: ClassVar[bool] = True
    can_edit: ClassVar[bool] = True
    can_delete: ClassVar[bool] = True
    max_rows: ClassVar[int] = 50

    def __init__(self, extra_sensitive_patterns: Sequence[Any] = ()) -> None:
        self.meta: ModelMeta = introspect_model(
            self.model,
            extra_sensitive_patterns=extra_sensitive_patterns,
        )
        self.display_label: str = self.label or self.meta.plural_label
        if self.columns:
            self.editable_columns: tuple[str, ...] = tuple(
                c
                for c in self.columns
                if c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
            )
        else:
            self.editable_columns = tuple(
                f.name
                for f in self.meta.fields
                if not f.primary_key and not f.is_sensitive and f.name != self.fk_column
            )

    def resolve_fk_column(self, parent_meta: ModelMeta) -> str:
        if self.fk_column:
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
        if raw is None and fmeta.nullable:
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
    fieldsets: ClassVar[Sequence[tuple[str, Sequence[str]]]] = ()
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
    field_widgets: ClassVar[Mapping[str, str]] = {}
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

        self.meta: ModelMeta = introspect_model(
            self.model,
            extra_sensitive_patterns=extra_sensitive_patterns,
            slug_override=self.slug,
        )
        self.slug = self.meta.slug
        self.label: str = self.name or self.meta.label
        self.plural_label: str = self.plural_name or self.meta.plural_label

        excluded = set(self.exclude_columns) | set(self.meta.sensitive_fields)

        # Compute frozen column lists once at registration (zero per-request reflection).
        if self.columns:
            self.list_columns: tuple[str, ...] = tuple(
                c
                for c in self.columns
                if c not in excluded
                and (c in self.meta.fields_by_name or c in self.meta.relationships_by_name)
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

        if self.searchable_columns:
            self.resolved_searchable: tuple[str, ...] = tuple(
                c for c in self.searchable_columns if c not in self.meta.sensitive_fields
            )
        else:
            self.resolved_searchable = tuple(
                f.name
                for f in self.meta.fields
                if f.field_type in {"string", "email", "uuid"}
                and not f.is_sensitive
                and not f.is_heavy
            )[:4]

        if self.filterable_columns:
            self.resolved_filterable: frozenset[str] = frozenset(
                c
                for c in self.filterable_columns
                if c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
            )
        else:
            self.resolved_filterable = frozenset(
                f.name
                for f in self.meta.fields
                if f.field_type in {"enum", "boolean", "date", "datetime"}
                or f.fk_target_table is not None
            )

        if self.sortable_columns:
            self.resolved_sortable: frozenset[str] = frozenset(
                c
                for c in self.sortable_columns
                if c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
            )
        else:
            self.resolved_sortable = frozenset(
                f.name
                for f in self.meta.fields
                if not f.is_heavy and not f.is_sensitive and f.field_type != "binary"
            )

        self.resolved_inline_editable: frozenset[str] = frozenset(
            c
            for c in self.inline_editable_columns
            if c in self.meta.fields_by_name
            and self.meta.fields_by_name[c].field_type in {"boolean", "enum"}
            and c not in self.meta.sensitive_fields
        )

        # Form columns (scalars + M2M relationships); auto-exclude soft_delete_column to prevent bypass
        form_excluded = set(self.form_excluded_columns) | set(self.meta.sensitive_fields)
        if self.soft_delete_column:
            form_excluded.add(self.soft_delete_column)
        if self.form_columns:
            self.resolved_form_fields: tuple[str, ...] = tuple(
                c
                for c in self.form_columns
                if c not in form_excluded
                and (c in self.meta.fields_by_name or c in self.meta.relationships_by_name)
            )
        else:
            auto_form: list[str] = []
            for f in self.meta.fields:
                if f.name in form_excluded or f.autoincrement or f.field_type == "binary":
                    continue
                if f.primary_key and f.has_default:
                    continue
                auto_form.append(f.name)
            for rel in self.meta.relationships:
                if rel.direction == "MANYTOMANY" and rel.name not in form_excluded:
                    auto_form.append(rel.name)
            self.resolved_form_fields = tuple(auto_form)

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

        # Discover @action methods declared on this class or subclasses.
        discovered_actions: dict[str, ActionSpec] = {}
        for cls in reversed(self.__class__.__mro__):
            for attr_val in cls.__dict__.values():
                spec: ActionSpec | None = getattr(attr_val, "_deck_action_spec", None)
                if spec is not None:
                    discovered_actions[spec.name] = spec
        self.actions: dict[str, ActionSpec] = discovered_actions

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
                if c in self.meta.fields_by_name and c not in self.meta.sensitive_fields
            )
        else:
            self.resolved_import_columns = tuple(
                f.name
                for f in self.meta.fields
                if not f.is_sensitive
                and not f.autoincrement
                and f.field_type != "binary"
                and f.name != self.soft_delete_column
            )

    def get_column_label(self, col_name: str) -> str:
        if col_name in self.column_labels:
            return self.column_labels[col_name]
        if col_name in self.meta.fields_by_name:
            return self.meta.fields_by_name[col_name].label
        if col_name in self.meta.relationships_by_name:
            return self.meta.relationships_by_name[col_name].label
        return humanize(col_name)

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
        return tuple(c for c in self.list_columns if c not in hidden)

    def allowed_form_fields(
        self,
        auth: AuthProvider,
        user: DeckUser | None,
        *,
        mode: str = "edit",
    ) -> tuple[str, ...]:
        """Strict allowlist of writable form fields (mass-assignment barrier)."""
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        readonly = auth.readonly_fields_for(user, self.meta.slug)
        allowed: list[str] = []
        for col in self.resolved_form_fields:
            if col in hidden or col in self.meta.sensitive_fields:
                continue
            if mode == "edit" and col in readonly:
                continue
            fmeta = self.meta.fields_by_name.get(col)
            if mode == "edit" and fmeta is not None and fmeta.primary_key:
                continue
            allowed.append(col)
        return tuple(allowed)

    def visible_form_fields(self, auth: AuthProvider, user: DeckUser | None) -> tuple[str, ...]:
        hidden = auth.hidden_fields_for(user, self.meta.slug)
        return tuple(c for c in self.resolved_form_fields if c not in hidden)

    def format_cell(
        self,
        col_name: str,
        obj: Any,
        *,
        auth: AuthProvider,
        user: DeckUser | None,
        media_url_builder: Callable[[str, Any], str | None] | None = None,
        rel_repr: Callable[[type[Any], Any], str] | None = None,
    ) -> Markup | str:
        """Format one table/detail cell with RBAC field masking and XSS-safe output."""
        raw_val = getattr(obj, col_name, None)
        if col_name in auth.masked_fields_for(user, self.meta.slug):
            masked = auth.mask_field_value(user, self.meta.slug, col_name, raw_val)
            return Markup(f'<span class="dk-masked">{Markup.escape(str(masked or "—"))}</span>')

        formatter = self._formatters.get(col_name)
        if formatter is not None:
            if isinstance(formatter, (ImageFormatter, FileFormatter)) and media_url_builder is not None:
                return formatter.format_with_url(raw_val, media_url_builder(col_name, obj))
            if isinstance(formatter, Formatter):
                return formatter.format(raw_val, obj)
            return formatter(raw_val, obj)

        rel_meta = self.meta.relationships_by_name.get(col_name)
        if rel_meta is not None:
            if raw_val is None:
                return Markup('<span class="dk-null">—</span>')
            def _fmt_rel_item(item: Any) -> str:
                if rel_repr is not None:
                    return rel_repr(rel_meta.target_model, item)
                return str(item)
            if rel_meta.uselist:
                items = list(raw_val)
                if not items:
                    return Markup('<span class="dk-null">—</span>')
                chips = "".join(
                    f'<span class="dk-chip">{Markup.escape(_fmt_rel_item(item))}</span>'
                    for item in items[:3]
                )
                extra = (
                    f'<span class="dk-muted dk-mono">+{len(items) - 3}</span>'
                    if len(items) > 3
                    else ""
                )
                return Markup(f'<span class="dk-chip-group">{chips}{extra}</span>')
            return Markup(f'<span class="dk-rel-val">{Markup.escape(_fmt_rel_item(raw_val))}</span>')

        if raw_val is None:
            return Markup('<span class="dk-null">—</span>')
        fmeta = self.meta.fields_by_name.get(col_name)
        if fmeta is not None and fmeta.field_type == "array" and isinstance(raw_val, (list, tuple)):
            if not raw_val:
                return Markup('<span class="dk-null">—</span>')
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
            return bool(src_str) and src_str not in {"false", "0"}
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
    ) -> None:
        """Validate & apply only strictly allowed form fields (prevents mass assignment)."""
        writable = set(self.allowed_form_fields(auth, user, mode=mode))
        masked = auth.masked_fields_for(user, self.meta.slug)
        if mode == "edit":
            writable -= masked
        errors: dict[str, list[str]] = {}
        coerced_values: dict[str, Any] = {}
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
                field_name, coerced_values, obj if mode == "edit" else None
            ):
                continue
            fmeta = self.meta.fields_by_name.get(field_name)
            if fmeta is not None:
                if fmeta.field_type == "boolean":
                    raw_val: Any = form_data.get(field_name, "")
                elif field_name in form_data:
                    raw_val = form_data.get(field_name)
                elif mode == "edit":
                    continue
                else:
                    raw_val = None
                try:
                    coerced_values[field_name] = coerce_form_value(
                        raw_val, fmeta, max_json_depth=max_json_depth
                    )
                except ValueError as exc:
                    errors.setdefault(field_name, []).append(str(exc))
                continue

            rel_meta = self.meta.relationships_by_name.get(field_name)
            if rel_meta is not None and rel_meta.direction == "MANYTOMANY" and m2m_getter is not None:
                raw_ids = [v for v in m2m_getter(field_name) if v]
                target_meta = introspect_model(rel_meta.target_model)
                pk_field = target_meta.primary_keys[0]
                typed_ids: list[Any] = []
                for rid in raw_ids:
                    try:
                        typed_ids.append(coerce_form_value(rid, pk_field))
                    except ValueError:
                        errors.setdefault(field_name, []).append(f"Invalid reference ID: {rid}")
                if typed_ids:
                    pk_col = getattr(rel_meta.target_model, pk_field.name)
                    t_stmt = sa.select(rel_meta.target_model).where(pk_col.in_(typed_ids))
                    if m2m_scope is not None:
                        t_stmt = m2m_scope(rel_meta.target_model, t_stmt)
                    targets = list(session.scalars(t_stmt).all())
                    m2m_updates[field_name] = targets
                else:
                    m2m_updates[field_name] = []

        if not errors:
            custom_errors = self.validate(coerced_values, obj=obj if mode == "edit" else None)
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
                    obj if mode == "edit" else None,
                    mode == "create",
                )
                visible_set = set(self.visible_form_fields(auth, user))
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
        writable = set(self.allowed_form_fields(auth, user, mode=mode))
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
    ) -> None:
        """Process embedded One-to-Many inline child rows with strict parent-ownership IDOR checks."""
        if not self.inline_views:
            return

        parent_pk = getattr(parent_obj, self.meta.primary_keys[0].name)

        for inline in self.inline_views:
            prefix = f"inline__{inline.meta.slug}__"
            fk_col_name = inline.resolve_fk_column(self.meta)
            child_pk_field = inline.meta.primary_keys[0]

            # Discover submitted row indices: inline__order-items__0__quantity
            row_indices: set[int] = set()
            for key in form_data:
                if key.startswith(prefix):
                    rest = key[len(prefix) :]
                    idx_part = rest.split("__", 1)[0]
                    if idx_part.isdigit():
                        row_indices.add(int(idx_part))

            if len(row_indices) > inline.max_rows:
                raise ValidationError(
                    {inline.meta.slug: [f"Maximum {inline.max_rows} inline rows allowed."]}
                )

            # Preload existing children belonging ONLY to this parent (IDOR barrier!).
            existing_by_pk: dict[Any, Any] = {}
            if parent_pk is not None:
                fk_attr = getattr(inline.model, fk_col_name)
                existing_rows = list(
                    session.scalars(sa.select(inline.model).where(fk_attr == parent_pk)).all()
                )
                for row in existing_rows:
                    existing_by_pk[getattr(row, child_pk_field.name)] = row

            errors: dict[str, list[str]] = {}
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
                        typed_pk = coerce_form_value(raw_pk, child_pk_field)
                    except ValueError:
                        errors.setdefault(inline.meta.slug, []).append(
                            f"Row {idx + 1}: invalid child ID."
                        )
                        continue
                    child_obj = existing_by_pk.get(typed_pk)
                    if child_obj is None:
                        # Strict IDOR prevention: reject tampering with another parent's child row!
                        raise PermissionDeniedError(
                            f"Inline record {typed_pk} does not belong to this {self.label}."
                        )
                    if marked_delete:
                        if not inline.can_delete or not auth.has_permission(
                            user, f"{inline.meta.slug}:delete", model_slug=inline.meta.slug
                        ):
                            raise PermissionDeniedError("Not authorized to delete inline items.")
                        session.delete(child_obj)
                        continue
                    if not inline.can_edit or not auth.has_permission(
                        user, f"{inline.meta.slug}:edit", model_slug=inline.meta.slug
                    ):
                        continue
                    target_obj = child_obj
                else:
                    if marked_delete:
                        continue
                    # Skip completely blank newly-added rows
                    has_any_val = any(
                        str(form_data.get(f"{row_prefix}{col}", "")).strip() != ""
                        for col in inline.editable_columns
                    )
                    if not has_any_val:
                        continue
                    if not inline.can_create or not auth.has_permission(
                        user, f"{inline.meta.slug}:create", model_slug=inline.meta.slug
                    ):
                        raise PermissionDeniedError("Not authorized to create inline items.")
                    target_obj = inline.model()
                    setattr(target_obj, fk_col_name, parent_pk)
                    session.add(target_obj)

                for col in inline.editable_columns:
                    fmeta = inline.meta.fields_by_name[col]
                    raw_val = form_data.get(f"{row_prefix}{col}")
                    try:
                        val = coerce_form_value(raw_val, fmeta, max_json_depth=max_json_depth)
                        setattr(target_obj, col, val)
                    except ValueError as exc:
                        errors.setdefault(f"{inline.meta.slug}[{idx}].{col}", []).append(str(exc))

            if errors:
                raise ValidationError(errors)
