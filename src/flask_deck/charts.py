from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import date
from typing import Any

from markupsafe import Markup, escape

_SERIES_CLASSES: tuple[str, ...] = ("primary", "ok", "info", "warn", "danger")


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        num = float(val)
    except (TypeError, ValueError):
        return default
    return num if math.isfinite(num) else default


def _fmt_num(val: float) -> str:
    if not math.isfinite(val):
        return "0"
    if abs(val) >= 1_000_000:
        return f"{val / 1_000_000:.1f}M"
    if abs(val) >= 1_000:
        return f"{val / 1_000:.1f}k"
    return f"{int(val)}" if float(val).is_integer() else f"{val:.1f}"


def render_sparkline(values: Sequence[float], *, tone: str = "primary") -> Markup:
    """Render a minimal flat sparkline SVG for KPI cards (strict CSP-compliant)."""
    if len(values) < 2:
        return Markup("")
    nums = [_safe_float(v) for v in values]
    lo = min(nums)
    hi = max(nums)
    span = (hi - lo) or 1.0
    w, h = 88.0, 26.0
    pad_y = 3.0
    step = w / (len(nums) - 1)
    pts: list[tuple[float, float]] = []
    for i, val in enumerate(nums):
        x = i * step
        y = h - pad_y - ((val - lo) / span) * (h - 2 * pad_y)
        pts.append((x, y))

    line_d = " ".join(
        f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(pts)
    )
    area_d = f"{line_d} L{w:.1f},{h:.1f} L0,{h:.1f} Z"
    cls = tone if tone in _SERIES_CLASSES else "primary"
    return Markup(
        f'<svg class="dk-sparkline dk-spark-{cls}" viewBox="0 0 {int(w)} {int(h)}" '
        f'width="{int(w)}" height="{int(h)}" aria-hidden="true">'
        f'<path class="dk-spark-area" d="{area_d}"/>'
        f'<path class="dk-spark-line" d="{line_d}"/>'
        "</svg>"
    )


def render_area_chart(
    labels: Sequence[str],
    series: Sequence[dict[str, Any]],
    *,
    height: int = 210,
) -> Markup:
    """Render a crisp anti-slop SVG area/line chart with hairline grid and hover hooks."""
    if not labels or not series:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    w = 640.0
    h = float(height)
    pad_l, pad_r, pad_t, pad_b = 44.0, 14.0, 14.0, 28.0
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b

    all_vals: list[float] = []
    clean_series: list[tuple[str, list[float], str]] = []
    for idx, item in enumerate(series):
        name = str(item.get("name", f"Series {idx + 1}"))
        raw_data = [_safe_float(v) for v in item.get("data", [])][: len(labels)]
        if not raw_data:
            continue
        all_vals.extend(raw_data)
        tone = str(item.get("tone", _SERIES_CLASSES[idx % len(_SERIES_CLASSES)]))
        if tone not in _SERIES_CLASSES:
            tone = _SERIES_CLASSES[idx % len(_SERIES_CLASSES)]
        clean_series.append((name, raw_data, tone))

    if not all_vals:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    max_v = max(all_vals)
    min_v = min(0.0, min(all_vals))
    span = (max_v - min_v) or 1.0
    # Slight headroom so the highest point sits cleanly below the top rule.
    top_v = min_v + span * 1.12
    eff_span = top_v - min_v

    parts: list[str] = [
        '<div class="dk-chart-wrap" data-deck-chart="area">',
        f'<svg class="dk-chart-svg" viewBox="0 0 {int(w)} {int(h)}" role="img" aria-label="Area chart">',
    ]

    # 4 crisp horizontal hairline gridlines + monospace Y axis labels.
    ticks = 4
    for t in range(ticks + 1):
        frac = t / ticks
        y = pad_t + plot_h * (1.0 - frac)
        val = min_v + eff_span * frac
        parts.append(
            f'<line class="dk-chart-grid" x1="{pad_l:.1f}" y1="{y:.1f}" x2="{w - pad_r:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="dk-chart-axis" x="{pad_l - 8:.1f}" y="{y + 3:.1f}" text-anchor="end">'
            f"{escape(_fmt_num(val))}</text>"
        )

    n = len(labels)
    step_x = plot_w / max(1, n - 1)

    # X axis labels (evenly spaced without crowding the final tick)
    label_stride = max(1, math.ceil(n / 7))
    for i, lbl in enumerate(labels):
        is_last = i == n - 1
        if not is_last and (i % label_stride != 0 or (n - 1 - i) < label_stride):
            continue
        x = pad_l + i * step_x
        parts.append(
            f'<text class="dk-chart-axis" x="{x:.1f}" y="{h - 6:.1f}" text-anchor="middle">'
            f"{escape(str(lbl))}</text>"
        )

    # Crosshair placeholder controlled by deck.js
    parts.append(
        f'<line class="dk-chart-crosshair" x1="{pad_l:.1f}" y1="{pad_t:.1f}" '
        f'x2="{pad_l:.1f}" y2="{pad_t + plot_h:.1f}" hidden="hidden"/>'
    )

    # Paths and interactive data points
    for name, data, tone in clean_series:
        pts: list[tuple[float, float]] = []
        for i, val in enumerate(data):
            x = pad_l + i * step_x
            y = pad_t + plot_h * (1.0 - (val - min_v) / eff_span)
            pts.append((x, y))

        line_d = " ".join(
            f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(pts)
        )
        base_y = pad_t + plot_h
        area_d = f"{line_d} L{pts[-1][0]:.1f},{base_y:.1f} L{pts[0][0]:.1f},{base_y:.1f} Z"
        parts.append(f'<path class="dk-area-fill dk-tone-{tone}" d="{area_d}"/>')
        parts.append(f'<path class="dk-area-line dk-tone-{tone}" d="{line_d}"/>')

        for i, (x, y) in enumerate(pts):
            parts.append(
                f'<circle class="dk-chart-pt dk-tone-{tone}" cx="{x:.1f}" cy="{y:.1f}" r="3.5" '
                f'data-label="{escape(str(labels[i]))}" '
                f'data-series="{escape(name)}" '
                f'data-value="{escape(_fmt_num(data[i]))}" '
                f'data-raw="{data[i]:.2f}" '
                f'data-x="{x:.1f}"/>'
            )

    parts.append("</svg>")
    parts.append('<div class="dk-chart-tooltip" hidden="hidden"></div>')
    if len(clean_series) > 1:
        legend_items = "".join(
            f'<span class="dk-legend-item"><span class="dk-legend-swatch dk-tone-{tone}"></span>'
            f"{escape(name)}</span>"
            for name, _, tone in clean_series
        )
        parts.append(f'<div class="dk-chart-legend">{legend_items}</div>')
    parts.append("</div>")
    return Markup("".join(parts))


def render_bar_chart(
    labels: Sequence[str],
    series: Sequence[dict[str, Any]],
    *,
    height: int = 210,
) -> Markup:
    """Render a crisp geometric bar chart in pure SVG."""
    if not labels or not series:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    w = 640.0
    h = float(height)
    pad_l, pad_r, pad_t, pad_b = 44.0, 14.0, 14.0, 28.0
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b

    first = series[0]
    name = str(first.get("name", "Count"))
    data = [_safe_float(v) for v in first.get("data", [])][: len(labels)]
    tone = str(first.get("tone", "primary"))
    if tone not in _SERIES_CLASSES:
        tone = "primary"
    if not data:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    max_v = max(0.0, max(data)) or 1.0
    top_v = max_v * 1.12

    parts: list[str] = [
        '<div class="dk-chart-wrap" data-deck-chart="bar">',
        f'<svg class="dk-chart-svg" viewBox="0 0 {int(w)} {int(h)}" role="img" aria-label="Bar chart">',
    ]

    for t in range(5):
        frac = t / 4
        y = pad_t + plot_h * (1.0 - frac)
        parts.append(
            f'<line class="dk-chart-grid" x1="{pad_l:.1f}" y1="{y:.1f}" x2="{w - pad_r:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="dk-chart-axis" x="{pad_l - 8:.1f}" y="{y + 3:.1f}" text-anchor="end">'
            f"{escape(_fmt_num(top_v * frac))}</text>"
        )

    n = len(data)
    slot_w = plot_w / max(1, n)
    bar_w = max(8.0, min(34.0, slot_w * 0.58))

    for i, val in enumerate(data):
        bar_h = max(1.0, (max(0.0, val) / top_v) * plot_h)
        cx = pad_l + i * slot_w + slot_w / 2.0
        bx = cx - bar_w / 2.0
        by = pad_t + plot_h - bar_h
        parts.append(
            f'<rect class="dk-bar-rect dk-tone-{tone}" x="{bx:.1f}" y="{by:.1f}" '
            f'width="{bar_w:.1f}" height="{bar_h:.1f}" rx="2" '
            f'data-label="{escape(str(labels[i]))}" '
            f'data-series="{escape(name)}" '
            f'data-value="{escape(_fmt_num(val))}" '
            f'data-x="{cx:.1f}"/>'
        )
        parts.append(
            f'<text class="dk-chart-axis" x="{cx:.1f}" y="{h - 6:.1f}" text-anchor="middle">'
            f"{escape(str(labels[i])[:10])}</text>"
        )

    parts.append("</svg>")
    parts.append('<div class="dk-chart-tooltip" hidden="hidden"></div>')
    parts.append("</div>")
    return Markup("".join(parts))


def render_donut_chart(
    labels: Sequence[str],
    series: Sequence[dict[str, Any]],
    *,
    center_label: str = "Total",
) -> Markup:
    """Render a minimal high-contrast donut ring chart with aligned tabular breakdown."""
    if not labels or not series:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    data = [max(0.0, _safe_float(v)) for v in series[0].get("data", [])][: len(labels)]
    total = sum(data)
    if total <= 0:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    tones = series[0].get("tones") or []
    cx, cy, r = 80.0, 80.0, 58.0
    circ = 2.0 * math.pi * r
    offset = 0.0

    segments: list[str] = []
    legend_rows: list[str] = []
    for i, val in enumerate(data):
        frac = val / total
        seg_len = frac * circ
        tone = str(tones[i]) if i < len(tones) else _SERIES_CLASSES[i % len(_SERIES_CLASSES)]
        if tone not in _SERIES_CLASSES:
            tone = _SERIES_CLASSES[i % len(_SERIES_CLASSES)]
        segments.append(
            f'<circle class="dk-donut-seg dk-tone-{tone}" cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" '
            f'stroke-dasharray="{max(0.0, seg_len - 1.5):.2f} {circ:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'data-label="{escape(str(labels[i]))}" '
            f'data-value="{escape(_fmt_num(val))} ({frac * 100:.0f}%)"/>'
        )
        offset += seg_len
        legend_rows.append(
            '<div class="dk-donut-row">'
            f'<span class="dk-donut-key"><span class="dk-legend-swatch dk-tone-{tone}"></span>'
            f"{escape(str(labels[i]))}</span>"
            f'<span class="dk-mono dk-tabular dk-muted">{escape(_fmt_num(val))} · {frac * 100:.0f}%</span>'
            "</div>"
        )

    svg = (
        '<div class="dk-donut-layout" data-deck-chart="donut">'
        '<div class="dk-donut-ring-wrap">'
        '<svg class="dk-donut-svg" viewBox="0 0 160 160" width="152" height="152" role="img" aria-label="Donut chart">'
        f'<circle class="dk-donut-track" cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}"/>'
        f'{"".join(segments)}'
        f'<text class="dk-donut-total" x="{cx:.1f}" y="{cy + 2:.1f}" text-anchor="middle">{escape(_fmt_num(total))}</text>'
        f'<text class="dk-donut-sub" x="{cx:.1f}" y="{cy + 18:.1f}" text-anchor="middle">{escape(center_label)}</text>'
        "</svg>"
        '<div class="dk-chart-tooltip" hidden="hidden"></div>'
        "</div>"
        f'<div class="dk-donut-legend">{"".join(legend_rows)}</div>'
        "</div>"
    )
    return Markup(svg)


def render_grouped_bar_chart(
    labels: Sequence[str],
    series: Sequence[dict[str, Any]],
    *,
    height: int = 210,
) -> Markup:
    """Render a multi-series grouped bar chart in pure SVG with hairline grid and tooltips."""
    if not labels or not series:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    w = 640.0
    h = float(height)
    pad_l, pad_r, pad_t, pad_b = 44.0, 14.0, 14.0, 28.0
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b

    clean: list[tuple[str, list[float], str]] = []
    all_vals: list[float] = []
    for idx, item in enumerate(series[:3]):
        name = str(item.get("name", f"Series {idx + 1}"))
        vals = [max(0.0, _safe_float(v)) for v in item.get("data", [])][: len(labels)]
        if not vals:
            continue
        tone = str(item.get("tone", _SERIES_CLASSES[idx % len(_SERIES_CLASSES)]))
        if tone not in _SERIES_CLASSES:
            tone = _SERIES_CLASSES[idx % len(_SERIES_CLASSES)]
        all_vals.extend(vals)
        clean.append((name, vals, tone))

    if not all_vals:
        return Markup('<div class="dk-chart-empty">No chart data available</div>')

    top_v = (max(all_vals) or 1.0) * 1.15
    parts: list[str] = [
        '<div class="dk-chart-wrap" data-deck-chart="grouped_bar">',
        f'<svg class="dk-chart-svg" viewBox="0 0 {int(w)} {int(h)}" role="img" aria-label="Grouped bar chart">',
    ]
    for t in range(5):
        frac = t / 4
        y = pad_t + plot_h * (1.0 - frac)
        parts.append(
            f'<line class="dk-chart-grid" x1="{pad_l:.1f}" y1="{y:.1f}" x2="{w - pad_r:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="dk-chart-axis" x="{pad_l - 8:.1f}" y="{y + 3:.1f}" text-anchor="end">'
            f"{escape(_fmt_num(top_v * frac))}</text>"
        )

    n = len(labels)
    k = len(clean)
    slot_w = plot_w / max(1, n)
    group_w = min(46.0, slot_w * 0.72)
    bar_w = max(5.0, (group_w - (k - 1) * 3.0) / k)

    for i, lbl in enumerate(labels):
        gx = pad_l + i * slot_w + (slot_w - group_w) / 2.0
        for s_idx, (name, vals, tone) in enumerate(clean):
            val = vals[i] if i < len(vals) else 0.0
            bh = max(1.0, (val / top_v) * plot_h)
            bx = gx + s_idx * (bar_w + 3.0)
            by = pad_t + plot_h - bh
            parts.append(
                f'<rect class="dk-bar-rect dk-tone-{tone}" x="{bx:.1f}" y="{by:.1f}" '
                f'width="{bar_w:.1f}" height="{bh:.1f}" rx="2" '
                f'data-label="{escape(str(lbl))}" '
                f'data-series="{escape(name)}" '
                f'data-value="{escape(_fmt_num(val))}" '
                f'data-x="{bx + bar_w / 2.0:.1f}"/>'
            )
        cx = pad_l + i * slot_w + slot_w / 2.0
        parts.append(
            f'<text class="dk-chart-axis" x="{cx:.1f}" y="{h - 6:.1f}" text-anchor="middle">'
            f"{escape(str(lbl)[:10])}</text>"
        )

    parts.append("</svg>")
    parts.append('<div class="dk-chart-tooltip" hidden="hidden"></div>')
    legend_items = "".join(
        f'<span class="dk-legend-item"><span class="dk-legend-swatch dk-tone-{tone}"></span>'
        f"{escape(name)}</span>"
        for name, _, tone in clean
    )
    parts.append(f'<div class="dk-chart-legend">{legend_items}</div></div>')
    return Markup("".join(parts))


def render_heatmap_chart(cells: Sequence[tuple[str, Any]], *, unit: str = "events") -> Markup:
    """Render a crisp 7x13 (91-day) GitHub-style activity heatmap in pure SVG."""
    if not cells:
        return Markup('<div class="dk-chart-empty">No activity data available</div>')

    data = list(cells)[-91:]
    parsed: list[tuple[str, int, int | None]] = []
    for date_str, count in data:
        safe_count = max(0, int(_safe_float(count)))
        dow_val: int | None = None
        if isinstance(date_str, str) and len(date_str) >= 10:
            try:
                dow_val = date.fromisoformat(date_str[:10]).weekday()
            except ValueError:
                dow_val = None
        parsed.append((str(date_str), safe_count, dow_val))

    max_val = max((c for _, c, _ in parsed), default=1) or 1
    first_dow = parsed[0][2] if parsed[0][2] is not None else 0
    cell_sz = 13.0
    gap = 4.0
    step = cell_sz + gap
    pad_l, pad_t = 28.0, 10.0
    weeks = max(1, math.ceil((len(parsed) + first_dow) / 7))
    w = pad_l + weeks * step + 6.0
    h = pad_t + 7 * step + 8.0

    day_labels = ("Mon", "", "Wed", "", "Fri", "", "Sun")
    parts: list[str] = [
        '<div class="dk-chart-wrap" data-deck-chart="heatmap">',
        f'<svg class="dk-chart-svg dk-heatmap-svg" viewBox="0 0 {int(w)} {int(h)}" role="img" aria-label="Activity heatmap">',
    ]
    for d_idx, dlbl in enumerate(day_labels):
        if dlbl:
            parts.append(
                f'<text class="dk-chart-axis" x="0" y="{pad_t + d_idx * step + 10:.1f}">{dlbl}</text>'
            )

    for idx, (date_str, safe_count, real_dow) in enumerate(parsed):
        slot = idx + first_dow
        wk = slot // 7
        dow = real_dow if real_dow is not None else (slot % 7)
        x = pad_l + wk * step
        y = pad_t + dow * step
        if safe_count <= 0:
            lvl = 0
        else:
            ratio = safe_count / max_val
            lvl = 1 if ratio <= 0.25 else (2 if ratio <= 0.5 else (3 if ratio <= 0.75 else 4))
        parts.append(
            f'<rect class="dk-hm-cell dk-hm-{lvl}" x="{x:.1f}" y="{y:.1f}" '
            f'width="{cell_sz:.1f}" height="{cell_sz:.1f}" rx="2" '
            f'data-label="{escape(date_str)}" data-value="{safe_count} {escape(unit)}"/>'
        )

    parts.append("</svg>")
    parts.append('<div class="dk-chart-tooltip" hidden="hidden"></div>')
    parts.append(
        '<div class="dk-hm-legend dk-mono dk-subtle">'
        "<span>Less</span>"
        '<span class="dk-hm-swatch dk-hm-0"></span>'
        '<span class="dk-hm-swatch dk-hm-1"></span>'
        '<span class="dk-hm-swatch dk-hm-2"></span>'
        '<span class="dk-hm-swatch dk-hm-3"></span>'
        '<span class="dk-hm-swatch dk-hm-4"></span>'
        "<span>More</span>"
        "</div></div>"
    )
    return Markup("".join(parts))


def render_stat_bars(items: Sequence[dict[str, Any]]) -> Markup:
    """Render horizontal precision utilization bars using pure SVG tracks (zero inline styles)."""
    if not items:
        return Markup('<div class="dk-chart-empty">No breakdown data</div>')

    rows: list[str] = ['<div class="dk-statbars">']
    for item in items:
        label = str(item.get("label", ""))
        val = _safe_float(item.get("value", 0))
        max_v = max(0.0001, _safe_float(item.get("max", 100), 100.0))
        pct = max(0.0, min(100.0, (val / max_v) * 100.0))
        meta = str(item.get("meta", f"{pct:.0f}%"))
        tone = str(item.get("tone", "primary"))
        if tone not in _SERIES_CLASSES:
            tone = "primary"
        rows.append(
            '<div class="dk-statbar-row">'
            '<div class="dk-statbar-top">'
            f'<span class="dk-statbar-lbl">{escape(label)}</span>'
            f'<span class="dk-mono dk-tabular dk-muted">{escape(meta)}</span>'
            "</div>"
            '<svg class="dk-statbar-svg" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true">'
            '<rect class="dk-prog-track" x="0" y="0" width="100" height="5" rx="1.5"/>'
            f'<rect class="dk-bar-rect dk-tone-{tone}" x="0" y="0" width="{pct:.1f}" height="5" rx="1.5"/>'
            "</svg>"
            "</div>"
        )
    rows.append("</div>")
    return Markup("".join(rows))


def render_gauge_chart(
    value: float,
    *,
    max_value: float = 100.0,
    label: str = "Health",
    suffix: str = "%",
    tone: str = "ok",
) -> Markup:
    """Render a minimal precision semi-circular SVG gauge dial."""
    safe_val = _safe_float(value)
    safe_max = max(0.0001, _safe_float(max_value, 100.0))
    pct = max(0.0, min(1.0, safe_val / safe_max))
    r = 56.0
    semi_circ = math.pi * r
    dash = pct * semi_circ
    cls = tone if tone in _SERIES_CLASSES else "ok"
    display = f"{int(safe_val) if safe_val.is_integer() else f'{safe_val:.1f}'}{suffix}"
    return Markup(
        '<div class="dk-gauge-wrap">'
        '<svg class="dk-gauge-svg" viewBox="0 0 160 98" width="160" height="98" role="img" aria-label="Gauge">'
        '<path class="dk-gauge-track" d="M 24 80 A 56 56 0 0 1 136 80"/>'
        f'<path class="dk-gauge-fill dk-tone-{cls}" d="M 24 80 A 56 56 0 0 1 136 80" '
        f'stroke-dasharray="{dash:.2f} {semi_circ:.2f}"/>'
        f'<text class="dk-donut-total" x="80" y="72" text-anchor="middle">{escape(display)}</text>'
        f'<text class="dk-donut-sub" x="80" y="90" text-anchor="middle">{escape(label)}</text>'
        "</svg></div>"
    )
