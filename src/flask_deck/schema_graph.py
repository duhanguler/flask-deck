from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from markupsafe import Markup, escape

from flask_deck.introspection import ModelMeta


def render_schema_erd_svg(
    metas: Sequence[ModelMeta],
    row_counts: Mapping[str, int],
    *,
    model_urls: Mapping[str, str] | None = None,
) -> Markup:
    """Render a crisp, strict-CSP pure SVG Entity-Relationship Diagram from frozen ModelMeta."""
    if not metas:
        return Markup('<div class="dk-chart-empty">No models registered</div>')

    cols_per_row = min(3, max(1, len(metas)))
    card_w = 240.0
    header_h = 30.0
    row_h = 19.0
    pad_x = 56.0
    pad_y = 44.0
    margin = 24.0
    max_fields_shown = 7

    # Precompute node geometry
    positions: dict[type, tuple[float, float, float, float]] = {}
    node_data: list[tuple[ModelMeta, float, float, float, float]] = []

    row_heights: dict[int, float] = {}
    for idx, meta in enumerate(metas):
        r = idx // cols_per_row
        shown = min(max_fields_shown, len(meta.fields)) + (1 if len(meta.fields) > max_fields_shown else 0)
        h = header_h + shown * row_h + 10.0
        row_heights[r] = max(row_heights.get(r, 0.0), h)

    total_rows = math.ceil(len(metas) / cols_per_row)
    row_y: dict[int, float] = {}
    cur_y = margin
    for r in range(total_rows):
        row_y[r] = cur_y
        cur_y += row_heights[r] + pad_y

    svg_w = margin * 2 + cols_per_row * card_w + max(0, cols_per_row - 1) * pad_x
    svg_h = max(180.0, cur_y - pad_y + margin)

    for idx, meta in enumerate(metas):
        r = idx // cols_per_row
        c = idx % cols_per_row
        x = margin + c * (card_w + pad_x)
        y = row_y[r]
        shown = min(max_fields_shown, len(meta.fields)) + (1 if len(meta.fields) > max_fields_shown else 0)
        h = header_h + shown * row_h + 10.0
        positions[meta.model] = (x, y, card_w, h)
        node_data.append((meta, x, y, card_w, h))

    parts: list[str] = [
        '<div class="dk-erd-wrap">',
        f'<svg class="dk-erd-svg" data-erd-svg data-base-vb="0 0 {int(svg_w)} {int(svg_h)}" viewBox="0 0 {int(svg_w)} {int(svg_h)}" role="img" aria-label="SQLAlchemy schema relationship diagram">',
        '<defs>'
        '<marker id="dk-erd-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M 1 1 L 9 5 L 1 9 z" class="dk-erd-arrow-head"/>'
        '</marker>'
        '</defs>',
    ]

    # Draw FK relationship connectors underneath model nodes (including overflow fields beyond max_fields_shown)
    for meta, x, y, w, _h in node_data:
        for f_idx, field in enumerate(meta.fields):
            if field.fk_target_model is None or field.fk_target_model not in positions:
                continue
            if field.fk_target_model is meta.model:
                continue
            tx, ty, tw, _th = positions[field.fk_target_model]
            anchor_idx = min(f_idx, max_fields_shown)
            fy = y + header_h + anchor_idx * row_h + row_h * 0.55
            target_y = ty + header_h * 0.5

            if tx >= x + w:
                sx, ex = x + w, tx
                mid_x = (sx + ex) / 2.0
                d = f"M{sx:.1f},{fy:.1f} C{mid_x:.1f},{fy:.1f} {mid_x:.1f},{target_y:.1f} {ex:.1f},{target_y:.1f}"
            elif x >= tx + tw:
                sx, ex = x, tx + tw
                mid_x = (sx + ex) / 2.0
                d = f"M{sx:.1f},{fy:.1f} C{mid_x:.1f},{fy:.1f} {mid_x:.1f},{target_y:.1f} {ex:.1f},{target_y:.1f}"
            else:
                sx = x + w
                ex = tx + tw
                bend = min(svg_w - 4.0, max(sx, ex) + 20.0)
                d = f"M{sx:.1f},{fy:.1f} C{bend:.1f},{fy:.1f} {bend:.1f},{target_y:.1f} {ex:.1f},{target_y:.1f}"

            parts.append(
                f'<path class="dk-erd-edge" d="{d}" marker-end="url(#dk-erd-arrow)">'
                f"<title>{escape(meta.name)}.{escape(field.name)} → {escape(field.fk_target_table or '')}</title>"
                "</path>"
            )

    # Draw model table nodes
    for meta, x, y, w, h in node_data:
        count = row_counts.get(meta.slug, 0)
        target_url = model_urls.get(meta.slug) if model_urls else None
        title_text = f'<text class="dk-erd-title" x="{x + 10:.1f}" y="{y + 19:.1f}">{escape(meta.name)}</text>'
        if target_url:
            title_node = f'<a href="{escape(target_url)}" class="dk-erd-link">{title_text}</a>'
        else:
            title_node = title_text
        parts.append(
            f'<g class="dk-erd-node">'
            f'<rect class="dk-erd-card" x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="5"/>'
            f'<rect class="dk-erd-head" x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{header_h:.1f}" rx="5"/>'
            f'<line class="dk-erd-div" x1="{x:.1f}" y1="{y + header_h:.1f}" x2="{x + w:.1f}" y2="{y + header_h:.1f}"/>'
            f"{title_node}"
            f'<text class="dk-erd-count" x="{x + w - 10:.1f}" y="{y + 19:.1f}" text-anchor="end">{count:,} rows</text>'
        )
        for f_idx, f in enumerate(meta.fields[:max_fields_shown]):
            fy = y + header_h + (f_idx + 1) * row_h - 3.0
            tag = "PK" if f.primary_key else ("FK" if f.fk_target_table else ("SEC" if f.is_sensitive else ""))
            tag_cls = (
                "dk-erd-tag-pk"
                if f.primary_key
                else ("dk-erd-tag-fk" if f.fk_target_table else "dk-erd-tag-sec")
            )
            name_x = x + (34.0 if tag else 10.0)
            if tag:
                parts.append(f'<text class="{tag_cls}" x="{x + 10:.1f}" y="{fy:.1f}">{tag}</text>')
            short_name = f.name if len(f.name) <= 18 else f"{f.name[:17]}…"
            parts.append(
                f'<text class="dk-erd-col" x="{name_x:.1f}" y="{fy:.1f}">{escape(short_name)}</text>'
                f'<text class="dk-erd-type" x="{x + w - 10:.1f}" y="{fy:.1f}" text-anchor="end">{escape(f.field_type)}</text>'
            )
        if len(meta.fields) > max_fields_shown:
            extra = len(meta.fields) - max_fields_shown
            ey = y + header_h + (max_fields_shown + 1) * row_h - 3.0
            parts.append(
                f'<text class="dk-erd-type" x="{x + 10:.1f}" y="{ey:.1f}">+{extra} more column(s)</text>'
            )
        parts.append("</g>")

    parts.append("</svg></div>")
    return Markup("".join(parts))
