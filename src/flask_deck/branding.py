from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from markupsafe import Markup, escape

from flask_deck.security import is_safe_display_url

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Precision anti-AI-slop accent presets: preset_name -> (dark_accent, light_accent)
ACCENT_PRESETS: dict[str, tuple[str, str]] = {
    "monochrome": ("#fafafa", "#18181b"),
    "cobalt": ("#3b82f6", "#2563eb"),
    "emerald": ("#10b981", "#059669"),
    "amber": ("#f59e0b", "#d97706"),
    "crimson": ("#ef4444", "#dc2626"),
    "slate": ("#94a3b8", "#334155"),
}

VALID_TEMPLATE_SLOTS: frozenset[str] = frozenset(
    {
        "head_extra",
        "topbar_right",
        "rail_top",
        "rail_bottom",
        "dashboard_top",
        "list_above_table",
        "form_above",
        "form_below",
        "detail_above",
        "detail_below",
        "login_footer",
    }
)


def _validate_hex(value: str, *, field_name: str) -> str:
    clean = value.strip()
    if not _HEX_COLOR_RE.fullmatch(clean):
        raise ValueError(
            f"BrandConfig.{field_name} must be a valid 6-digit hex color (#RRGGBB), got {value!r}"
        )
    return clean.lower()


def _validate_relative_asset(path: str, *, field_name: str) -> str:
    if (
        not isinstance(path, str)
        or "\\" in path
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
    ):
        raise ValueError(
            f"BrandConfig.{field_name} entries must be relative same-origin paths starting with '/': {path!r}"
        )
    clean = path.strip()
    if not clean or not clean.startswith("/") or clean.startswith("//"):
        raise ValueError(
            f"BrandConfig.{field_name} entries must be relative same-origin paths starting with '/': {path!r}"
        )
    return clean


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    return (
        int(hex_color[1:3], 16),
        int(hex_color[3:5], 16),
        int(hex_color[5:7], 16),
    )


def _relative_luminance(hex_color: str) -> float:
    r, g, b = _hex_to_rgb(hex_color)
    channels = []
    for c in (r, g, b):
        s = c / 255.0
        channels.append(s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast_fg(hex_color: str) -> str:
    """Choose WCAG high-contrast foreground (#09090b or #fafafa) for a button background."""
    return "#09090b" if _relative_luminance(hex_color) > 0.42 else "#fafafa"


def _shift_hex(hex_color: str, factor: float) -> str:
    """Darken (factor < 1) or lighten (factor > 1) a hex color cleanly."""
    r, g, b = _hex_to_rgb(hex_color)
    if factor < 1.0:
        nr, ng, nb = int(r * factor), int(g * factor), int(b * factor)
    else:
        delta = factor - 1.0
        nr = int(r + (255 - r) * delta)
        ng = int(g + (255 - g) * delta)
        nb = int(b + (255 - b) * delta)
    return f"#{max(0, min(255, nr)):02x}{max(0, min(255, ng)):02x}{max(0, min(255, nb)):02x}"


SlotRenderer = str | Callable[[Mapping[str, Any]], Markup | str]


@dataclass(frozen=True, slots=True)
class BrandConfig:
    """Strict-CSP white-label branding & safe template slot configuration."""

    accent: str = "monochrome"
    accent_light: str | None = None
    logo_url: str | None = None
    logo_dark_url: str | None = None
    logo_mark: str | None = None
    favicon_url: str | None = None
    login_title: str | None = None
    login_subtitle: str | None = None
    login_notice: str | None = None
    footer_note: str | None = None
    extra_css: tuple[str, ...] = ()
    extra_js: tuple[str, ...] = ()
    template_slots: Mapping[str, SlotRenderer] = field(default_factory=dict)

    def __post_init__(self) -> None:
        acc_lower = self.accent.strip().lower()
        if acc_lower not in ACCENT_PRESETS:
            _validate_hex(self.accent, field_name="accent")
        if self.accent_light is not None:
            _validate_hex(self.accent_light, field_name="accent_light")
        for attr in ("logo_url", "logo_dark_url", "favicon_url"):
            val = getattr(self, attr)
            if val is not None:
                if not is_safe_display_url(val):
                    raise ValueError(f"BrandConfig.{attr} must be a safe relative or http(s) URL")
                object.__setattr__(self, attr, val.strip())
        clean_css = tuple(
            _validate_relative_asset(css_path, field_name="extra_css")
            for css_path in self.extra_css
        )
        clean_js = tuple(
            _validate_relative_asset(js_path, field_name="extra_js")
            for js_path in self.extra_js
        )
        object.__setattr__(self, "extra_css", clean_css)
        object.__setattr__(self, "extra_js", clean_js)
        unknown_slots = set(self.template_slots.keys()) - VALID_TEMPLATE_SLOTS
        if unknown_slots:
            raise ValueError(
                f"Unknown BrandConfig.template_slots: {sorted(unknown_slots)}. "
                f"Allowed: {sorted(VALID_TEMPLATE_SLOTS)}"
            )

    @property
    def has_custom_theme(self) -> bool:
        return self.accent.strip().lower() != "monochrome" or self.accent_light is not None

    def resolved_accents(self) -> tuple[str, str]:
        """Return (dark_hex, light_hex) accent colors."""
        key = self.accent.strip().lower()
        if key in ACCENT_PRESETS:
            dark_hex, light_hex = ACCENT_PRESETS[key]
        else:
            dark_hex = _validate_hex(self.accent, field_name="accent")
            light_hex = dark_hex
        if self.accent_light is not None:
            light_hex = _validate_hex(self.accent_light, field_name="accent_light")
        return dark_hex, light_hex


def render_brand_css(brand: BrandConfig) -> tuple[bytes, str]:
    """Generate strict-CSP external /_theme.css bytes and SHA-256 cache-busting hash."""
    if not brand.has_custom_theme:
        empty = b"/* flask-deck default monochrome tokens */\n"
        return empty, hashlib.sha256(empty).hexdigest()[:10]

    dark_hex, light_hex = brand.resolved_accents()
    dark_fg = _contrast_fg(dark_hex)
    light_fg = _contrast_fg(light_hex)
    dark_hover = _shift_hex(dark_hex, 0.88 if _relative_luminance(dark_hex) > 0.35 else 1.15)
    light_hover = _shift_hex(light_hex, 0.86)
    dr, dg, db = _hex_to_rgb(dark_hex)
    lr, lg, lb = _hex_to_rgb(light_hex)

    css = (
        ":root,[data-theme=\"dark\"]{"
        f"--btn-bg:{dark_hex};"
        f"--btn-fg:{dark_fg};"
        f"--btn-hover:{dark_hover};"
        f"--chart-stroke:{dark_hex};"
        f"--chart-fill:rgba({dr},{dg},{db},0.10);"
        f"--accent-soft:rgba({dr},{dg},{db},0.14);"
        "}\n"
        "[data-theme=\"light\"]{"
        f"--btn-bg:{light_hex};"
        f"--btn-fg:{light_fg};"
        f"--btn-hover:{light_hover};"
        f"--chart-stroke:{light_hex};"
        f"--chart-fill:rgba({lr},{lg},{lb},0.09);"
        f"--accent-soft:rgba({lr},{lg},{lb},0.12);"
        "}\n"
    ).encode()
    return css, hashlib.sha256(css).hexdigest()[:10]


def render_safe_slot(
    brand: BrandConfig,
    slot_name: str,
    context: Mapping[str, Any],
    *,
    template_renderer: Callable[..., str],
) -> Markup:
    """Safely render a configured brand template slot without unescaped string injection."""
    if slot_name not in VALID_TEMPLATE_SLOTS:
        return Markup("")
    handler = brand.template_slots.get(slot_name)
    if handler is None:
        return Markup("")
    if isinstance(handler, str):
        return Markup(template_renderer(handler, **context))
    out = handler(context)
    return out if isinstance(out, Markup) else Markup(escape(str(out)))
