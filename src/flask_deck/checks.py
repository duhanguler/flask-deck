from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from flask_deck.introspection import introspect_model
from flask_deck.model_view import (
    Fieldset,
    ModelURL,
    ModelView,
    is_safe_media_path,
    is_safe_template_name,
)
from flask_deck.query import parse_search_column_spec
from flask_deck.security import is_sensitive_field
from flask_deck.widgets import FormWidget

if TYPE_CHECKING:
    from flask_deck.deck import Deck


@dataclass(frozen=True, slots=True)
class CheckFinding:
    """Declarative ModelView / Deck configuration validation finding (Django system-checks style)."""

    code: str
    severity: Literal["error", "warn", "info"]
    view_slug: str
    title: str
    message: str
    remediation: str = ""


def _validate_dotted_search_path(
    view: ModelView,
    raw_spec: str,
    extra_sensitive_patterns: tuple[Any, ...],
) -> tuple[bool, str]:
    path, _ = parse_search_column_spec(raw_spec)
    if not path:
        return False, f"Empty search column specifier {raw_spec!r}."
    parts = path.split(".")
    if len(parts) == 1:
        col = parts[0]
        if col in view.meta.sensitive_fields or is_sensitive_field(col, extra_sensitive_patterns):
            return False, f"Sensitive column {col!r} cannot be listed in searchable_columns."
        if col not in view.meta.fields_by_name:
            return False, f"Unknown searchable column {col!r} on {view.meta.name}."
        return True, ""
    if len(parts) > 3:
        return False, f"Search path {raw_spec!r} exceeds maximum depth of 2 relationship hops."
    cur_meta = view.meta
    for hop in parts[:-1]:
        if hop in cur_meta.sensitive_fields or is_sensitive_field(hop, extra_sensitive_patterns):
            return False, f"Sensitive relationship segment {hop!r} in search path {raw_spec!r}."
        rel = cur_meta.relationships_by_name.get(hop)
        if rel is None:
            return False, f"Unknown relationship {hop!r} on {cur_meta.name} in search path {raw_spec!r}."
        cur_meta = introspect_model(rel.target_model)
    leaf = parts[-1]
    if leaf in cur_meta.sensitive_fields or is_sensitive_field(leaf, extra_sensitive_patterns):
        return False, f"Sensitive target column {leaf!r} in search path {raw_spec!r}."
    if leaf not in cur_meta.fields_by_name:
        return False, f"Unknown target column {leaf!r} on {cur_meta.name} in search path {raw_spec!r}."
    return True, ""


def _is_valid_dotted_manytoone(view: ModelView, spec: str) -> bool:
    if "." not in spec:
        return False
    rel_name, target_col = spec.split(".", 1)
    rel = view.meta.relationships_by_name.get(rel_name)
    if rel is None or rel.direction != "MANYTOONE":
        return False
    t_meta = introspect_model(rel.target_model)
    return target_col in t_meta.fields_by_name


def check_model_view(
    view: ModelView,
    *,
    extra_sensitive_patterns: tuple[Any, ...] = (),
) -> list[CheckFinding]:
    """Run static configuration checks against a single registered ``ModelView``."""
    findings: list[CheckFinding] = []
    slug = view.meta.slug
    fields = view.meta.fields_by_name
    rels = view.meta.relationships_by_name
    displays = view.display_fields
    virtuals = view.virtual_fields_by_name
    sensitive = view.meta.sensitive_fields

    def _is_model_attr(name: str) -> bool:
        if name.startswith("_"):
            return False
        attr = getattr(view.model, name, None)
        return attr is not None and not callable(attr)

    def _check_sensitive(col: str, attr_name: str) -> bool:
        if col in sensitive or is_sensitive_field(col, extra_sensitive_patterns):
            findings.append(
                CheckFinding(
                    code="DECK-E009",
                    severity="error",
                    view_slug=slug,
                    title=f"Sensitive column in {attr_name}",
                    message=f"{view.__class__.__name__}.{attr_name} references sensitive column {col!r}.",
                    remediation=f"Remove {col!r} from {attr_name} so credentials/secrets are never exposed.",
                )
            )
            return True
        return False

    # DECK-E001 / DECK-E009: columns, filterable, sortable, inline_editable, export, import, readonly, raw_id, radio
    for col in view.columns:
        if _check_sensitive(col, "columns"):
            continue
        if (
            col not in fields
            and col not in rels
            and col not in displays
            and not _is_model_attr(col)
        ):
            findings.append(
                CheckFinding(
                    code="DECK-E001",
                    severity="error",
                    view_slug=slug,
                    title="Unknown column in columns",
                    message=f"{view.__class__.__name__}.columns references unknown attribute {col!r}.",
                    remediation="Ensure every entry is a model column, relationship, @display method, or property.",
                )
            )

    for col in view.form_columns:
        if _check_sensitive(col, "form_columns"):
            continue
        if col not in fields and col not in rels and col not in displays and col not in virtuals:
            findings.append(
                CheckFinding(
                    code="DECK-E001",
                    severity="error",
                    view_slug=slug,
                    title="Unknown column in form_columns",
                    message=f"{view.__class__.__name__}.form_columns references unknown field {col!r}.",
                    remediation="Remove or correct the field name in form_columns.",
                )
            )

    for col in view.filterable_columns:
        if "." in col:
            if not _is_valid_dotted_manytoone(view, col):
                findings.append(
                    CheckFinding(
                        code="DECK-E001",
                        severity="error",
                        view_slug=slug,
                        title="Unknown dotted column in filterable_columns",
                        message=f"{view.__class__.__name__}.filterable_columns has invalid relation path {col!r}.",
                        remediation="Use 'manytoone_rel.column' pointing to a valid column on the related model.",
                    )
                )
            else:
                rel_name, target_col = col.split(".", 1)
                if is_sensitive_field(target_col, extra_sensitive_patterns) or rel_name in sensitive:
                    findings.append(
                        CheckFinding(
                            code="DECK-E009",
                            severity="error",
                            view_slug=slug,
                            title="Sensitive column exposed in filterable_columns",
                            message=f"{view.__class__.__name__}.filterable_columns references sensitive field {col!r}.",
                            remediation="Remove sensitive credential/secret columns from view configuration.",
                        )
                    )
        else:
            if _check_sensitive(col, "filterable_columns"):
                continue
            if col not in fields:
                findings.append(
                    CheckFinding(
                        code="DECK-E001",
                        severity="error",
                        view_slug=slug,
                        title="Unknown column in filterable_columns",
                        message=f"{view.__class__.__name__}.filterable_columns references unknown column {col!r}.",
                        remediation="Remove or correct the column name in filterable_columns.",
                    )
                )

    for col in view.sortable_columns:
        if "." in col:
            if not _is_valid_dotted_manytoone(view, col):
                findings.append(
                    CheckFinding(
                        code="DECK-E001",
                        severity="error",
                        view_slug=slug,
                        title="Unknown dotted column in sortable_columns",
                        message=f"{view.__class__.__name__}.sortable_columns has invalid relation path {col!r}.",
                        remediation="Use 'manytoone_rel.column' pointing to a valid related column.",
                    )
                )
            else:
                rel_name, target_col = col.split(".", 1)
                if is_sensitive_field(target_col, extra_sensitive_patterns) or rel_name in sensitive:
                    findings.append(
                        CheckFinding(
                            code="DECK-E009",
                            severity="error",
                            view_slug=slug,
                            title="Sensitive column exposed in sortable_columns",
                            message=f"{view.__class__.__name__}.sortable_columns references sensitive field {col!r}.",
                            remediation="Remove sensitive credential/secret columns from view configuration.",
                        )
                    )
        else:
            if _check_sensitive(col, "sortable_columns"):
                continue
            if col not in fields and col not in displays:
                findings.append(
                    CheckFinding(
                        code="DECK-E001",
                        severity="error",
                        view_slug=slug,
                        title="Unknown column in sortable_columns",
                        message=f"{view.__class__.__name__}.sortable_columns references unknown column {col!r}.",
                        remediation="Use a model column or a @display method with ordering=.",
                    )
                )

    for col in view.inline_editable_columns:
        if _check_sensitive(col, "inline_editable_columns"):
            continue
        if col not in fields:
            findings.append(
                CheckFinding(
                    code="DECK-E001",
                    severity="error",
                    view_slug=slug,
                    title="Unknown column in inline_editable_columns",
                    message=f"{view.__class__.__name__}.inline_editable_columns references unknown column {col!r}.",
                    remediation="Ensure inline_editable_columns only lists editable model columns.",
                )
            )

    for attr_label, seq in (
        ("export_columns", view.export_columns),
        ("import_columns", view.import_columns),
        ("raw_id_fields", view.raw_id_fields),
        ("radio_fields", tuple(view.radio_fields.keys())),
    ):
        for col in seq:
            if attr_label in {"export_columns", "import_columns"} and _check_sensitive(col, attr_label):
                continue
            if (
                col not in fields
                and not (attr_label == "raw_id_fields" and col in rels)
                and not (attr_label == "radio_fields" and col in virtuals)
            ):
                findings.append(
                    CheckFinding(
                        code="DECK-E001",
                        severity="error",
                        view_slug=slug,
                        title=f"Unknown column in {attr_label}",
                        message=f"{view.__class__.__name__}.{attr_label} references unknown column {col!r}.",
                        remediation=f"Remove or correct {col!r} in {attr_label}.",
                    )
                )

    for col in view.readonly_fields:
        if _check_sensitive(col, "readonly_fields"):
            continue
        if col not in fields and col not in rels and col not in displays and col not in virtuals:
            findings.append(
                CheckFinding(
                    code="DECK-E001",
                    severity="error",
                    view_slug=slug,
                    title="Unknown field in readonly_fields",
                    message=f"{view.__class__.__name__}.readonly_fields references unknown field {col!r}.",
                    remediation="Ensure readonly_fields lists valid model columns, relationships, or @display methods.",
                )
            )

    # DECK-E002: searchable_columns
    for raw_s in view.searchable_columns:
        ok, err_msg = _validate_dotted_search_path(view, raw_s, extra_sensitive_patterns)
        if not ok:
            code = "DECK-E009" if err_msg.startswith("Sensitive") else "DECK-E002"
            findings.append(
                CheckFinding(
                    code=code,
                    severity="error",
                    view_slug=slug,
                    title="Invalid searchable_columns entry",
                    message=f"{view.__class__.__name__}: {err_msg}",
                    remediation="Check prefix (^, =, @) and ensure every column/relationship segment exists and is non-sensitive.",
                )
            )

    # DECK-E003: fieldsets unknown, sensitive, or duplicate fields
    seen_fs_fields: set[str] = set()
    for entry in view.fieldsets:
        fs_rows = entry.fields if isinstance(entry, Fieldset) else entry[1]
        for row_item in fs_rows:
            row_cols = row_item if isinstance(row_item, (tuple, list)) else (row_item,)
            for col in row_cols:
                if _check_sensitive(col, "fieldsets"):
                    continue
                if col not in fields and col not in rels and col not in displays and col not in virtuals:
                    findings.append(
                        CheckFinding(
                            code="DECK-E003",
                            severity="error",
                            view_slug=slug,
                            title="Unknown field in fieldsets",
                            message=f"{view.__class__.__name__}.fieldsets references unknown field {col!r}.",
                            remediation="Remove or rename the invalid field inside fieldsets.",
                        )
                    )
                elif col in seen_fs_fields:
                    findings.append(
                        CheckFinding(
                            code="DECK-E003",
                            severity="error",
                            view_slug=slug,
                            title="Duplicate field in fieldsets",
                            message=f"{view.__class__.__name__}.fieldsets lists field {col!r} more than once.",
                            remediation="Each field should appear in at most one fieldset.",
                        )
                    )
                else:
                    seen_fs_fields.add(col)

    # DECK-E004: date_hierarchy / calendar_date_field
    for attr_label, col_opt in (
        ("date_hierarchy", view.date_hierarchy),
        ("calendar_date_field", view.calendar_date_field),
    ):
        if col_opt:
            fm = fields.get(col_opt)
            if fm is None or fm.field_type not in {"date", "datetime"}:
                findings.append(
                    CheckFinding(
                        code="DECK-E004",
                        severity="error",
                        view_slug=slug,
                        title=f"Invalid {attr_label} column",
                        message=f"{view.__class__.__name__}.{attr_label} = {col_opt!r} must reference a Date or DateTime column.",
                        remediation=f"Point {attr_label} to an indexed date/datetime column on {view.meta.name}.",
                    )
                )

    # DECK-E005: prepopulated_fields
    for target_col, src_cols in view.prepopulated_fields.items():
        tfm = fields.get(target_col)
        if tfm is None or tfm.is_sensitive or is_sensitive_field(target_col, extra_sensitive_patterns):
            findings.append(
                CheckFinding(
                    code="DECK-E005",
                    severity="error",
                    view_slug=slug,
                    title="Invalid prepopulated_fields target",
                    message=f"{view.__class__.__name__}.prepopulated_fields target {target_col!r} is missing or sensitive.",
                    remediation="Target a writable string/slug column on the model.",
                )
            )
        for sc in src_cols:
            if _check_sensitive(sc, "prepopulated_fields"):
                continue
            if sc not in fields:
                findings.append(
                    CheckFinding(
                        code="DECK-E005",
                        severity="error",
                        view_slug=slug,
                        title="Invalid prepopulated_fields source",
                        message=f"{view.__class__.__name__}.prepopulated_fields source {sc!r} for {target_col!r} does not exist.",
                        remediation="Reference valid model columns as prepopulated_fields sources.",
                    )
                )

    # DECK-E006: list_display_links (skip static check when get_list_display() is dynamically overridden)
    has_dynamic_list_display = type(view).get_list_display is not ModelView.get_list_display
    if view.list_display_links is not None and not has_dynamic_list_display:
        list_set = set(view.list_columns)
        for link_col in view.list_display_links:
            if link_col not in list_set:
                findings.append(
                    CheckFinding(
                        code="DECK-E006",
                        severity="error",
                        view_slug=slug,
                        title="list_display_links column not in columns",
                        message=f"{view.__class__.__name__}.list_display_links contains {link_col!r}, which is not in list_columns.",
                        remediation="Add the column to columns or remove it from list_display_links.",
                    )
                )

    # DECK-E007: kanban_column
    if view.kanban_column:
        kfm = fields.get(view.kanban_column)
        if kfm is None or not kfm.choices:
            findings.append(
                CheckFinding(
                    code="DECK-E007",
                    severity="error",
                    view_slug=slug,
                    title="Invalid kanban_column",
                    message=f"{view.__class__.__name__}.kanban_column = {view.kanban_column!r} must reference an Enum/choices column.",
                    remediation="Point kanban_column to an Enum column.",
                )
            )

    # DECK-E008: inlines
    for inline in view.inline_views:
        try:
            inline.resolve_fk_column(view.meta)
        except ValueError as exc:
            findings.append(
                CheckFinding(
                    code="DECK-E008",
                    severity="error",
                    view_slug=slug,
                    title="Inline FK column cannot be resolved",
                    message=str(exc),
                    remediation="Set explicit fk_column on the InlineModelView subclass.",
                )
            )
        for icol in inline.columns:
            if icol in inline.meta.sensitive_fields or is_sensitive_field(icol, extra_sensitive_patterns):
                findings.append(
                    CheckFinding(
                        code="DECK-E009",
                        severity="error",
                        view_slug=slug,
                        title="Sensitive column exposed on InlineModelView",
                        message=f"{inline.__class__.__name__}.columns references sensitive field {icol!r}.",
                        remediation="Remove sensitive fields from InlineModelView.columns.",
                    )
                )
                continue
            if icol not in inline.meta.fields_by_name and icol not in inline.display_fields:
                findings.append(
                    CheckFinding(
                        code="DECK-E008",
                        severity="error",
                        view_slug=slug,
                        title="Unknown column on InlineModelView",
                        message=f"{inline.__class__.__name__}.columns references unknown field {icol!r}.",
                        remediation="Ensure inline columns match child model columns or @display methods.",
                    )
                )
        for ro_col in inline.readonly_fields:
            if ro_col in inline.meta.sensitive_fields or is_sensitive_field(ro_col, extra_sensitive_patterns):
                findings.append(
                    CheckFinding(
                        code="DECK-E009",
                        severity="error",
                        view_slug=slug,
                        title="Sensitive readonly_fields on InlineModelView",
                        message=f"{inline.__class__.__name__}.readonly_fields references sensitive field {ro_col!r}.",
                        remediation="Remove sensitive fields from InlineModelView.readonly_fields.",
                    )
                )
                continue
            if ro_col not in inline.meta.fields_by_name and ro_col not in inline.display_fields:
                findings.append(
                    CheckFinding(
                        code="DECK-E008",
                        severity="error",
                        view_slug=slug,
                        title="Unknown readonly_fields on InlineModelView",
                        message=f"{inline.__class__.__name__}.readonly_fields references unknown field {ro_col!r}.",
                        remediation="Remove or correct invalid readonly_fields on the inline.",
                    )
                )

    # DECK-E010: template override paths
    for t_attr in ("list_template", "form_template", "detail_template", "history_template"):
        t_val = getattr(view, t_attr, None)
        if t_val is not None and not is_safe_template_name(t_val):
            findings.append(
                CheckFinding(
                    code="DECK-E010",
                    severity="error",
                    view_slug=slug,
                    title=f"Unsafe template path in {t_attr}",
                    message=f"{view.__class__.__name__}.{t_attr} = {t_val!r} fails template path safety validation.",
                    remediation="Use a relative Jinja template path without leading '/', backslashes, or '..'.",
                )
            )

    # DECK-E011: Media asset paths (view.media, extra_css, extra_js, widget media)
    media_paths: list[tuple[str, str]] = []
    if view.media is not None:
        media_paths.extend(("media.css", p) for p in view.media.css)
        media_paths.extend(("media.js", p) for p in view.media.js)
    media_paths.extend(("extra_css", p) for p in view.extra_css)
    media_paths.extend(("extra_js", p) for p in view.extra_js)
    for w in (
        *view.field_widgets.values(),
        *view.formfield_overrides.values(),
        *(vf.widget for vf in view.extra_form_fields if vf.widget is not None),
        *(iw for inl in view.inline_views for iw in inl.field_widgets.values()),
    ):
        if isinstance(w, FormWidget):
            media_paths.extend((f"{w.__class__.__name__}.media_css", p) for p in w.media_css)
            media_paths.extend((f"{w.__class__.__name__}.media_js", p) for p in w.media_js)
    for src_label, asset_path in media_paths:
        if not is_safe_media_path(asset_path):
            findings.append(
                CheckFinding(
                    code="DECK-E011",
                    severity="error",
                    view_slug=slug,
                    title=f"Unsafe external or invalid Media path ({src_label})",
                    message=f"{view.__class__.__name__} declares non-same-origin or invalid asset path {asset_path!r}.",
                    remediation="Only same-origin relative paths starting with '/' (e.g. '/static/admin/custom.js') are allowed.",
                )
            )

    # DECK-E012: get_urls() custom sub-routes
    for u in view.get_urls():
        if not isinstance(u, ModelURL):
            findings.append(
                CheckFinding(
                    code="DECK-E012",
                    severity="error",
                    view_slug=slug,
                    title="Invalid entry returned by get_urls()",
                    message=f"{view.__class__.__name__}.get_urls() returned non-ModelURL object {u!r}.",
                    remediation="Return ModelURL(rule=..., endpoint=..., handler=...) instances.",
                )
            )
            continue
        clean_rule = u.rule.strip().lstrip("/")
        if not clean_rule or ".." in clean_rule.split("/") or "\\" in clean_rule or "\x00" in clean_rule:
            findings.append(
                CheckFinding(
                    code="DECK-E012",
                    severity="error",
                    view_slug=slug,
                    title="Invalid custom ModelURL rule",
                    message=f"{view.__class__.__name__}.get_urls() contains unsafe rule {u.rule!r}.",
                    remediation="Use a relative Flask route pattern such as 'export-pdf' or '<raw_pk>/invoice'.",
                )
            )
        if not u.endpoint or not u.endpoint.replace("_", "").isalnum() or not callable(u.handler):
            findings.append(
                CheckFinding(
                    code="DECK-E012",
                    severity="error",
                    view_slug=slug,
                    title="Invalid custom ModelURL endpoint or handler",
                    message=f"{view.__class__.__name__}.get_urls() has invalid endpoint {u.endpoint!r} or non-callable handler.",
                    remediation="Provide an alphanumeric/underscore endpoint name and a callable view function.",
                )
            )

    # DECK-W001: list_select_related path check
    for rel_chain in view.list_select_related:
        parts = [p.strip() for p in rel_chain.split(".") if p.strip()]
        if not parts or len(parts) > 3:
            findings.append(
                CheckFinding(
                    code="DECK-W001",
                    severity="warn",
                    view_slug=slug,
                    title="Invalid list_select_related path",
                    message=f"{view.__class__.__name__}.list_select_related contains invalid chain {rel_chain!r}.",
                    remediation="Use dotted relationship names up to 3 hops (e.g. 'order.customer').",
                )
            )
            continue
        cur_m = view.meta
        for hop in parts:
            rm = cur_m.relationships_by_name.get(hop)
            if rm is None:
                findings.append(
                    CheckFinding(
                        code="DECK-W001",
                        severity="warn",
                        view_slug=slug,
                        title="Unknown relationship in list_select_related",
                        message=f"{view.__class__.__name__}.list_select_related hop {hop!r} not found on {cur_m.name}.",
                        remediation="Use exact SQLAlchemy relationship attribute names.",
                    )
                )
                break
            cur_m = introspect_model(rm.target_model)

    return findings


def run_model_view_checks(deck: Deck) -> list[CheckFinding]:
    """Run startup & diagnostic configuration checks across all registered views on ``deck``."""
    findings: list[CheckFinding] = []
    extra_pats = tuple(deck.config.extra_sensitive_patterns)
    for view in deck.views.values():
        findings.extend(check_model_view(view, extra_sensitive_patterns=extra_pats))

    # DECK-W002: Password strength policy advisory in production
    if (
        deck.config.environment == "production"
        and hasattr(deck.auth, "strict_password_policy")
        and not bool(getattr(deck.auth, "strict_password_policy", False))
        and not bool(getattr(deck.auth, "_has_custom_password_validators", False))
    ):
            findings.append(
                CheckFinding(
                    code="DECK-W002",
                    severity="warn",
                    view_slug="_security",
                    title="Strict password policy not enabled in production",
                    message="SQLAlchemyAuthProvider is running in production with strict_password_policy=False.",
                    remediation="Set strict_password_policy=True or pass custom password_validators on SQLAlchemyAuthProvider.",
                )
            )
    return findings
