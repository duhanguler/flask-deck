from __future__ import annotations

import enum
import math
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import date, datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, ClassVar

from markupsafe import Markup, escape

from flask_deck.i18n import format_locale_decimal, to_user_timezone
from flask_deck.security import is_safe_display_url

VALID_TONES = frozenset({"neutral", "ok", "warn", "danger", "info"})
_TONE_ALIASES: dict[str, str] = {
    "emerald": "ok",
    "green": "ok",
    "success": "ok",
    "amber": "warn",
    "yellow": "warn",
    "warning": "warn",
    "rose": "danger",
    "red": "danger",
    "error": "danger",
    "indigo": "info",
    "blue": "info",
    "zinc": "neutral",
    "gray": "neutral",
    "muted": "neutral",
}


def normalize_tone(tone: str) -> str:
    lower = tone.strip().lower()
    mapped = _TONE_ALIASES.get(lower, lower)
    return mapped if mapped in VALID_TONES else "neutral"


class Formatter(ABC):
    """Base cell formatter producing strictly CSP-safe and XSS-safe Markup."""

    @abstractmethod
    def format(self, value: Any, obj: Any | None = None) -> Markup | str:
        """Render a cell value safely."""


class BadgeFormatter(Formatter):
    """Render status/enum strings as crisp semantic badges with indicator dots."""

    def __init__(
        self,
        tones: Mapping[str, str] | None = None,
        *,
        default_tone: str = "neutral",
        labels: Mapping[str, str] | None = None,
    ) -> None:
        self._tones = {str(k).lower(): normalize_tone(v) for k, v in (tones or {}).items()}
        self._default_tone = normalize_tone(default_tone)
        self._labels = {str(k).lower(): str(v) for k, v in (labels or {}).items()}

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        raw = value.value if isinstance(value, enum.Enum) else str(value)
        key = str(raw).lower()
        tone = self._tones.get(key, self._default_tone)
        display = self._labels.get(key, str(raw).replace("_", " "))
        return Markup(
            f'<span class="dk-badge dk-badge-{tone}">'
            f'<span class="dk-dot" aria-hidden="true"></span>'
            f"{escape(display)}</span>"
        )


class CurrencyFormatter(Formatter):
    """Format numeric or minor-unit currency values with tabular monospace alignment."""

    _SYMBOLS: ClassVar[dict[str, str]] = {
        "USD": "$",
        "EUR": "€",
        "GBP": "£",
        "TRY": "₺",
        "JPY": "¥",
    }

    def __init__(
        self,
        *,
        currency: str = "USD",
        divisor: int | float = 1,
        decimals: int = 2,
    ) -> None:
        self._symbol = self._SYMBOLS.get(currency.upper(), f"{currency.upper()} ")
        self._divisor = Decimal(str(divisor))
        self._decimals = decimals

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        try:
            amount = Decimal(str(value)) / self._divisor
            if not amount.is_finite():
                return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')
            quant = Decimal(10) ** -max(0, self._decimals)
            rounded = amount.quantize(quant, rounding=ROUND_HALF_UP)
        except Exception:
            return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')
        sign = "-" if rounded < 0 else ""
        formatted_num = format_locale_decimal(abs(rounded), decimals=self._decimals)
        formatted = f"{sign}{self._symbol}{formatted_num}"
        return Markup(f'<span class="dk-mono dk-tabular">{escape(formatted)}</span>')


class RelativeTimeFormatter(Formatter):
    """Render UTC/naive datetimes as crisp relative time with user-timezone tooltip."""

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        if isinstance(value, datetime):
            dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = now - dt
            secs = int(delta.total_seconds())
            local_dt = to_user_timezone(dt)
            if secs < 0:
                fut = abs(secs)
                if fut < 60:
                    rel = f"in {fut}s"
                elif fut < 3600:
                    rel = f"in {fut // 60}m"
                elif fut < 86400:
                    rel = f"in {fut // 3600}h"
                elif fut < 86400 * 30:
                    rel = f"in {fut // 86400}d"
                else:
                    rel = local_dt.strftime("%Y-%m-%d")
            elif secs < 60:
                rel = f"{secs}s ago"
            elif secs < 3600:
                rel = f"{secs // 60}m ago"
            elif secs < 86400:
                rel = f"{secs // 3600}h ago"
            elif secs < 86400 * 30:
                rel = f"{secs // 86400}d ago"
            else:
                rel = local_dt.strftime("%Y-%m-%d")
            tz_abbr = local_dt.tzname() or "UTC"
            iso = f"{local_dt.strftime('%Y-%m-%d %H:%M')} {tz_abbr}"
            return Markup(
                f'<time class="dk-mono dk-tabular dk-muted" title="{escape(iso)}">{escape(rel)}</time>'
            )
        if isinstance(value, date):
            iso = value.isoformat()
            return Markup(f'<time class="dk-mono dk-tabular dk-muted">{escape(iso)}</time>')
        return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')


class DateTimeFormatter(Formatter):
    """Render datetimes explicitly converted to the user's active ZoneInfo timezone."""

    def __init__(self, *, fmt: str = "%Y-%m-%d %H:%M") -> None:
        self._fmt = fmt

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        if isinstance(value, datetime):
            local_dt = to_user_timezone(value)
            tz_abbr = local_dt.tzname() or "UTC"
            display = f"{local_dt.strftime(self._fmt)} {tz_abbr}"
            return Markup(
                f'<time class="dk-mono dk-tabular dk-muted" title="{escape(local_dt.isoformat())}">'
                f"{escape(display)}</time>"
            )
        if isinstance(value, date):
            return Markup(f'<time class="dk-mono dk-tabular dk-muted">{escape(value.isoformat())}</time>')
        return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')


class BooleanIconFormatter(Formatter):
    """Render booleans as crisp high-contrast semantic pills."""

    def __init__(self, *, true_label: str = "Active", false_label: str = "Inactive") -> None:
        self._true_label = true_label
        self._false_label = false_label

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        if bool(value):
            return Markup(
                f'<span class="dk-badge dk-badge-ok">'
                f'<span class="dk-dot" aria-hidden="true"></span>'
                f"{escape(self._true_label)}</span>"
            )
        return Markup(
            f'<span class="dk-badge dk-badge-neutral">'
            f'<span class="dk-dot" aria-hidden="true"></span>'
            f"{escape(self._false_label)}</span>"
        )


class CodeFormatter(Formatter):
    """Render identifiers, slugs, or keys in compact monospace chips (optionally copyable)."""

    def __init__(self, *, max_chars: int = 36, copyable: bool = False) -> None:
        self._max_chars = max_chars
        self._copyable = copyable

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        text = str(value)
        display = text if len(text) <= self._max_chars else f"{text[: self._max_chars - 1]}…"
        if self._copyable:
            return Markup(
                '<span class="dk-copy-wrap">'
                f'<code class="dk-code" title="{escape(text)}">{escape(display)}</code>'
                f'<button type="button" class="dk-copy-btn" data-deck-copy="{escape(text)}" '
                'title="Copy to clipboard" aria-label="Copy to clipboard">'
                '<svg class="dk-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" '
                'stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" '
                'aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>'
                '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'
                "</button></span>"
            )
        return Markup(f'<code class="dk-code" title="{escape(text)}">{escape(display)}</code>')


class AvatarFormatter(Formatter):
    """Render initials badge + name cleanly without relying on external image hosts."""

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        text = str(value).strip()
        parts = [p for p in text.split() if p]
        initials = (
            (parts[0][0] + parts[-1][0]).upper()
            if len(parts) >= 2
            else (text[:2].upper() if text else "?")
        )
        return Markup(
            '<span class="dk-avatar-cell">'
            f'<span class="dk-avatar" aria-hidden="true">{escape(initials)}</span>'
            f'<span class="dk-avatar-name">{escape(text)}</span>'
            "</span>"
        )


class ProgressBarFormatter(Formatter):
    """Strict CSP-compliant progress bar using pure SVG (zero inline style attributes)."""

    def __init__(
        self,
        *,
        max_value: float = 100.0,
        warn_below: float | None = None,
        danger_below: float | None = None,
        suffix: str = "%",
    ) -> None:
        self._max_value = max(0.0001, float(max_value))
        self._warn_below = warn_below
        self._danger_below = danger_below
        self._suffix = suffix

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None:
            return Markup('<span class="dk-null">—</span>')
        try:
            num = float(value)
        except (TypeError, ValueError):
            return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')
        if not math.isfinite(num):
            return Markup(f'<span class="dk-mono">{escape(str(value))}</span>')
        pct = max(0.0, min(100.0, (num / self._max_value) * 100.0))
        bar_cls = "dk-prog-fill-ok"
        if self._danger_below is not None and num <= self._danger_below:
            bar_cls = "dk-prog-fill-danger"
        elif self._warn_below is not None and num <= self._warn_below:
            bar_cls = "dk-prog-fill-warn"
        label = f"{int(num) if num.is_integer() else f'{num:.1f}'}{self._suffix}"
        return Markup(
            '<span class="dk-progress-cell">'
            '<svg class="dk-progress-svg" viewBox="0 0 100 6" width="68" height="6" aria-hidden="true">'
            '<rect class="dk-prog-track" x="0" y="0" width="100" height="6" rx="2"></rect>'
            f'<rect class="{bar_cls}" x="0" y="0" width="{pct:.1f}" height="6" rx="2"></rect>'
            "</svg>"
            f'<span class="dk-mono dk-tabular dk-muted">{escape(label)}</span>'
            "</span>"
        )


class LinkFormatter(Formatter):
    """Render external/internal URLs safely, blocking javascript: and data: schemes."""

    def __init__(self, *, label: str | None = None, new_tab: bool = True) -> None:
        self._label = label
        self._new_tab = new_tab

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        if value is None or not str(value).strip():
            return Markup('<span class="dk-null">—</span>')
        url = str(value).strip()
        if not is_safe_display_url(url):
            return Markup(f'<span class="dk-mono dk-muted">{escape(url)}</span>')
        display = self._label or url.removeprefix("https://").removeprefix("http://")
        if len(display) > 36:
            display = f"{display[:35]}…"
        target = ' target="_blank" rel="noopener noreferrer"' if self._new_tab else ""
        return Markup(f'<a class="dk-link" href="{escape(url)}"{target}>{escape(display)}</a>')


class ImageFormatter(Formatter):
    """Render stored image thumbnails opening a strict-CSP Lightbox modal on click."""

    def __init__(
        self,
        *,
        media_url_builder: Callable[[Any], str | None] | None = None,
        field_name: str | None = None,
        alt_prefix: str = "Image",
    ) -> None:
        self._media_url_builder = media_url_builder
        self._field_name = field_name
        self._alt_prefix = alt_prefix

    def format_with_url(self, value: Any, media_url: str | None) -> Markup:
        if value is None or not str(value).strip():
            return Markup('<span class="dk-null">—</span>')
        key = str(value).strip()
        filename = key.rsplit("/", 1)[-1]
        url = media_url if media_url and is_safe_display_url(media_url) else (
            key if is_safe_display_url(key) else None
        )
        if not url:
            return Markup(f'<code class="dk-code">{escape(filename)}</code>')
        return Markup(
            f'<button type="button" class="dk-thumb-btn" data-deck-lightbox="{escape(url)}" '
            f'data-lightbox-title="{escape(filename)}" title="Preview {escape(filename)}" '
            f'aria-label="Preview {escape(filename)}">'
            f'<img class="dk-thumb" src="{escape(url)}" alt="{escape(self._alt_prefix)}: {escape(filename)}" loading="lazy">'
            "</button>"
        )

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        url = self._media_url_builder(obj) if (self._media_url_builder and obj is not None) else None
        return self.format_with_url(value, url)


class FileFormatter(Formatter):
    """Render stored file attachments as crisp downloadable monospace chips."""

    def __init__(
        self,
        *,
        media_url_builder: Callable[[Any], str | None] | None = None,
    ) -> None:
        self._media_url_builder = media_url_builder

    def format_with_url(self, value: Any, media_url: str | None) -> Markup:
        if value is None or not str(value).strip():
            return Markup('<span class="dk-null">—</span>')
        key = str(value).strip()
        filename = key.rsplit("/", 1)[-1]
        short = filename if len(filename) <= 28 else f"{filename[:27]}…"
        url = media_url if media_url and is_safe_display_url(media_url) else (
            key if is_safe_display_url(key) else None
        )
        if not url:
            return Markup(f'<code class="dk-code">{escape(short)}</code>')
        return Markup(
            f'<a class="dk-file-chip dk-mono" href="{escape(url)}" title="{escape(filename)}">'
            '<svg class="dk-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" '
            'stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" '
            'aria-hidden="true"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19'
            'a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>'
            f"<span>{escape(short)}</span></a>"
        )

    def format(self, value: Any, obj: Any | None = None) -> Markup:
        url = self._media_url_builder(obj) if (self._media_url_builder and obj is not None) else None
        return self.format_with_url(value, url)
