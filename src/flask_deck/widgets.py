from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from markupsafe import Markup, escape


class FormWidget(ABC):
    """Base declarative widget renderer for ModelView ``field_widgets`` overrides."""

    full_width: bool = False

    @abstractmethod
    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        """Render strict-CSP HTML input markup without inline styles or event handlers."""


class CodeWidget(FormWidget):
    """Monospace code editor textarea with language tag."""

    full_width: bool = True

    def __init__(self, *, language: str = "plain", rows: int = 8) -> None:
        self.language = language.strip().lower() or "plain"
        self.rows = max(2, int(rows))

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        ro = " readonly" if readonly else ""
        req = " required" if required else ""
        val_str = "" if value is None else str(value)
        return Markup(
            f'<div class="dk-code-widget" data-lang="{escape(self.language)}">'
            f'<div class="dk-kv-ed-bar"><span class="dk-badge dk-badge-neutral dk-mono">{escape(self.language.upper())}</span></div>'
            f'<textarea id="{escape(field_id)}" name="{escape(name)}" rows="{self.rows}" '
            f'class="dk-textarea dk-mono" aria-label="{escape(label or name)}"{ro}{req}>{escape(val_str)}</textarea>'
            f"</div>"
        )


class MarkdownFormWidget(FormWidget):
    """Write/Preview Markdown editor wired into deck-form.js XSS-safe previewer."""

    full_width: bool = True

    def __init__(self, *, rows: int = 8) -> None:
        self.rows = max(3, int(rows))

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        ro = " readonly" if readonly else ""
        req = " required" if required else ""
        val_str = "" if value is None else str(value)
        return Markup(
            '<div class="dk-md-editor" data-deck-md>'
            '<div class="dk-kv-ed-bar">'
            '<div class="dk-seg">'
            '<button type="button" class="dk-seg-btn is-active" data-md-mode="write">Write</button>'
            '<button type="button" class="dk-seg-btn" data-md-mode="preview">Preview</button>'
            "</div>"
            '<span class="dk-subtle dk-mono">XSS-safe DOM preview</span>'
            "</div>"
            f'<textarea id="{escape(field_id)}" name="{escape(name)}" rows="{self.rows}" '
            f'class="dk-textarea dk-mono" data-md-input aria-label="{escape(label or name)}"{ro}{req}>{escape(val_str)}</textarea>'
            '<div class="dk-md-preview" data-md-preview hidden="hidden"></div>'
            "</div>"
        )


class ColorWidget(FormWidget):
    """Hex color picker widget."""

    full_width: bool = False

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        dis = " disabled" if readonly else ""
        req = " required" if required else ""
        val_str = str(value).strip() if value else "#18181b"
        if not val_str.startswith("#") or len(val_str) not in {4, 7}:
            val_str = "#18181b"
        return Markup(
            '<div class="dk-color-widget">'
            f'<input type="color" id="{escape(field_id)}" name="{escape(name)}" '
            f'value="{escape(val_str)}" class="dk-color-input" aria-label="{escape(label or name)}"{dis}{req}>'
            f'<span class="dk-mono dk-subtle">{escape(val_str)}</span>'
            "</div>"
        )


class TagInputWidget(FormWidget):
    """Interactive tag-chip array editor wired into deck-form.js."""

    full_width: bool = True

    def __init__(self, *, placeholder: str = "Type tag and press Enter…") -> None:
        self.placeholder = placeholder

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        if isinstance(value, (list, tuple)):
            json_val = json.dumps(list(value))
        elif isinstance(value, str):
            json_val = value or "[]"
        else:
            json_val = "[]"
        dis = " disabled" if readonly else ""
        req = " required" if required else ""
        entry_input = (
            ""
            if readonly
            else f'<input type="text" class="dk-input dk-tag-input" data-tag-entry placeholder="{escape(self.placeholder)}">'
        )
        return Markup(
            '<div class="dk-tag-editor" data-deck-tags>'
            '<div class="dk-tag-chips" data-tag-chips></div>'
            f"{entry_input}"
            f'<input type="hidden" id="{escape(field_id)}" name="{escape(name)}" '
            f'value="{escape(json_val)}" data-tag-hidden aria-label="{escape(label or name)}"{dis}{req}>'
            "</div>"
        )


class SliderWidget(FormWidget):
    """Numeric range slider widget wired into deck-form.js."""

    full_width: bool = False

    def __init__(
        self,
        *,
        min_value: float = 0,
        max_value: float = 100,
        step: float = 1,
        unit: str = "%",
    ) -> None:
        self.min_value = min_value
        self.max_value = max_value
        self.step = step
        self.unit = unit

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        dis = " disabled" if readonly else ""
        val = self.min_value if value in (None, "") else value
        return Markup(
            '<div class="dk-slider-row" data-deck-slider>'
            f'<input type="range" min="{self.min_value}" max="{self.max_value}" step="{self.step}" '
            f'id="{escape(field_id)}" name="{escape(name)}" value="{escape(str(val))}" '
            f'class="dk-slider" data-slider-input aria-label="{escape(label or name)}"{dis}>'
            f'<span class="dk-badge dk-badge-neutral dk-mono dk-tabular" data-slider-val>{escape(str(val))}{escape(self.unit)}</span>'
            "</div>"
        )


class JSONSchemaWidget(FormWidget):
    """Schema-guided JSON editor displaying allowed properties and types."""

    full_width: bool = True

    def __init__(
        self,
        *,
        schema: Mapping[str, Any] | None = None,
        rows: int = 8,
    ) -> None:
        self.schema = dict(schema or {})
        self.rows = max(4, int(rows))

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        ro = " readonly" if readonly else ""
        req = " required" if required else ""
        if isinstance(value, (dict, list)):
            val_str = json.dumps(value, indent=2)
        elif value is None:
            val_str = "{}"
        else:
            val_str = str(value)
        props = self.schema.get("properties") if isinstance(self.schema, Mapping) else None
        hints_html = ""
        if isinstance(props, Mapping) and props:
            chips = "".join(
                f'<span class="dk-chip dk-mono">{escape(str(k))}: {escape(str(v.get("type", "any") if isinstance(v, Mapping) else "any"))}</span>'
                for k, v in list(props.items())[:10]
            )
            hints_html = f'<div class="dk-chip-group">{chips}</div>'
        schema_json = json.dumps(self.schema, separators=(",", ":"))
        return Markup(
            f'<div class="dk-json-schema-widget" data-json-schema="{escape(schema_json)}">'
            f"{hints_html}"
            f'<textarea id="{escape(field_id)}" name="{escape(name)}" rows="{self.rows}" '
            f'class="dk-textarea dk-mono" aria-label="{escape(label or name)}"{ro}{req}>{escape(val_str)}</textarea>'
            "</div>"
        )


MarkdownWidget = MarkdownFormWidget
