from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

import sqlalchemy as sa
from markupsafe import Markup
from sqlalchemy.orm import Session

from flask_deck.audit import AuditEntry
from flask_deck.auth import DeckUser
from flask_deck.charts import (
    render_area_chart,
    render_bar_chart,
    render_donut_chart,
    render_gauge_chart,
    render_grouped_bar_chart,
    render_heatmap_chart,
    render_sparkline,
    render_stat_bars,
)
from flask_deck.formatters import normalize_tone
from flask_deck.query import soft_delete_predicate
from flask_deck.security import is_safe_display_url

if TYPE_CHECKING:
    from flask_deck.deck import Deck


@dataclass(frozen=True, slots=True)
class Widget:
    """Base dashboard widget."""

    title: str
    col_span: int = 12
    subtitle: str = ""

    @property
    def span_class(self) -> str:
        allowed = {3, 4, 6, 8, 9, 12}
        span = self.col_span if self.col_span in allowed else 12
        return f"dk-span-{span}"


@dataclass(frozen=True, slots=True)
class KPIWidget(Widget):
    """Single operational metric tile with tabular numerals and optional sparkline."""

    value: str = "0"
    delta: str = ""
    trend: Literal["up", "down", "flat"] = "flat"
    icon: str = "activity"
    href: str | None = None
    sparkline: Sequence[float] = field(default_factory=tuple)
    col_span: int = 3

    @property
    def kind(self) -> str:
        return "kpi"

    @property
    def safe_href(self) -> str | None:
        return self.href if is_safe_display_url(self.href) else None

    @property
    def sparkline_svg(self) -> Markup:
        tone = "ok" if self.trend == "up" else ("danger" if self.trend == "down" else "primary")
        return render_sparkline(self.sparkline, tone=tone)


@dataclass(frozen=True, slots=True)
class ChartWidget(Widget):
    """Pure SVG chart widget (area, bar, grouped_bar, or donut)."""

    chart_type: Literal["area", "bar", "grouped_bar", "donut"] = "area"
    labels: Sequence[str] = field(default_factory=tuple)
    series: Sequence[dict[str, Any]] = field(default_factory=tuple)
    center_label: str = "Total"
    col_span: int = 8

    @property
    def kind(self) -> str:
        return "chart"

    @property
    def chart_svg(self) -> Markup:
        if self.chart_type == "bar":
            return render_bar_chart(self.labels, self.series)
        if self.chart_type == "grouped_bar":
            return render_grouped_bar_chart(self.labels, self.series)
        if self.chart_type == "donut":
            return render_donut_chart(self.labels, self.series, center_label=self.center_label)
        return render_area_chart(self.labels, self.series)


@dataclass(frozen=True, slots=True)
class HeatmapWidget(Widget):
    """91-day GitHub-style pure SVG activity heatmap."""

    cells: Sequence[tuple[str, int]] = field(default_factory=tuple)
    unit: str = "events"
    col_span: int = 8

    @property
    def kind(self) -> str:
        return "heatmap"

    @property
    def heatmap_svg(self) -> Markup:
        return render_heatmap_chart(self.cells, unit=self.unit)


@dataclass(frozen=True, slots=True)
class StatBarWidget(Widget):
    """Horizontal utilization / quota progress bars widget."""

    items: Sequence[dict[str, Any]] = field(default_factory=tuple)
    col_span: int = 4

    @property
    def kind(self) -> str:
        return "statbars"

    @property
    def bars_svg(self) -> Markup:
        return render_stat_bars(self.items)


@dataclass(frozen=True, slots=True)
class GaugeWidget(Widget):
    """Precision semi-circular SVG gauge dial with key metrics."""

    value: float = 0.0
    max_value: float = 100.0
    gauge_label: str = "Score"
    suffix: str = "%"
    tone: str = "ok"
    details: Sequence[tuple[str, str]] = field(default_factory=tuple)
    col_span: int = 4

    @property
    def kind(self) -> str:
        return "gauge"

    @property
    def gauge_svg(self) -> Markup:
        return render_gauge_chart(
            self.value,
            max_value=self.max_value,
            label=self.gauge_label,
            suffix=self.suffix,
            tone=self.tone,
        )


@dataclass(frozen=True, slots=True)
class TimelineWidget(Widget):
    """Structured operational event timeline with semantic status rail."""

    events: Sequence[dict[str, Any]] = field(default_factory=tuple)
    col_span: int = 6

    @property
    def kind(self) -> str:
        return "timeline"

    @property
    def safe_events(self) -> tuple[dict[str, Any], ...]:
        out: list[dict[str, Any]] = []
        for ev in self.events:
            href = ev.get("href")
            safe_href = href if (isinstance(href, str) and is_safe_display_url(href)) else None
            if safe_href != href:
                cleaned = dict(ev)
                cleaned["href"] = safe_href
                out.append(cleaned)
            else:
                out.append(ev)
        return tuple(out)


@dataclass(frozen=True, slots=True)
class CalloutWidget(Widget):
    """High-signal operational alert banner with optional direct CTA."""

    message: str = ""
    tone: str = "warn"
    action_label: str = ""
    action_href: str | None = None
    col_span: int = 12

    @property
    def kind(self) -> str:
        return "callout"

    @property
    def safe_action_href(self) -> str | None:
        return self.action_href if is_safe_display_url(self.action_href) else None

    @property
    def normalized_tone(self) -> str:
        return normalize_tone(self.tone)


@dataclass(frozen=True, slots=True)
class TableWidget(Widget):
    """Compact summary table widget for recent/critical records."""

    headers: Sequence[str] = field(default_factory=tuple)
    rows: Sequence[Sequence[Any]] = field(default_factory=tuple)
    href: str | None = None
    href_label: str = "View all"
    col_span: int = 6

    @property
    def kind(self) -> str:
        return "table"

    @property
    def safe_href(self) -> str | None:
        return self.href if is_safe_display_url(self.href) else None


@dataclass(frozen=True, slots=True)
class ActivityWidget(Widget):
    """Recent Audit Log activity feed widget."""

    limit: int = 8
    entries: Sequence[AuditEntry] = field(default_factory=tuple)
    col_span: int = 6

    @property
    def kind(self) -> str:
        return "activity"


@dataclass(frozen=True, slots=True)
class MarkdownWidget(Widget):
    """Plain operational notes / runbook checklist block."""

    lines: Sequence[str] = field(default_factory=tuple)
    col_span: int = 6

    @property
    def kind(self) -> str:
        return "notes"


class DashboardContext:
    """Context passed to custom ``@deck.dashboard`` callbacks."""

    __slots__ = ("_deck", "range_days", "session", "user")

    def __init__(
        self,
        deck: Deck,
        session: Session,
        user: DeckUser | None,
        *,
        range_days: int = 14,
    ) -> None:
        self._deck = deck
        self.session = session
        self.user = user
        self.range_days = range_days if range_days in {7, 14, 30, 90} else 14

    def url_for_model(self, model_or_slug: type[Any] | str) -> str | None:
        return self._deck.url_for_model(model_or_slug)

    def recent_audit_entries(self, limit: int = 8) -> list[AuditEntry]:
        if self._deck.audit_store is None:
            return []
        if not self._deck.auth.has_permission(self.user, "audit:view"):
            return []
        entries, _ = self._deck.audit_store.list_entries(limit=limit)
        return entries

    def last_n_days(self, n: int = 14) -> list[str]:
        today = datetime.now(timezone.utc).date()
        return [(today - timedelta(days=n - 1 - i)).strftime("%b %d") for i in range(n)]


DashboardBuilder = Callable[[DashboardContext], Sequence[Widget]]


def build_default_dashboard(deck: Deck, ctx: DashboardContext) -> list[Widget]:
    """Generate an automatic operational dashboard from registered models and audit store."""
    widgets: list[Widget] = []
    views = [
        v
        for v in deck.views.values()
        if v.can_view
        and deck.auth.has_permission(ctx.user, f"{v.meta.slug}:view", model_slug=v.meta.slug)
    ]

    model_counts: list[tuple[str, int]] = []
    trend_labels = ctx.last_n_days(14)
    trend_series: list[dict[str, Any]] = []
    today = datetime.now(timezone.utc).date()
    window_start = datetime(
        (today - timedelta(days=13)).year,
        (today - timedelta(days=13)).month,
        (today - timedelta(days=13)).day,
        tzinfo=timezone.utc,
    )

    for view in views[:4]:
        view_sess = deck.get_session(view.bind_key)
        base = view.scope_query(sa.select(view.model), ctx.user)
        sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
        if sd_pred is not None:
            base = base.where(sd_pred)
        count_stmt = sa.select(sa.func.count()).select_from(base.subquery())
        total = int(view_sess.execute(count_stmt).scalar_one() or 0)
        model_counts.append((view.plural_label, total))

        # Check if model has a creation timestamp to build real 7d/14d series.
        ts_field = next(
            (
                f
                for f in view.meta.fields
                if f.field_type == "datetime"
                and f.name in {"created_at", "created", "inserted_at", "timestamp", "updated_at"}
            ),
            None,
        )
        spark: list[float] = []
        delta = ""
        trend: Literal["up", "down", "flat"] = "flat"
        if ts_field is not None:
            ts_col = getattr(view.model, ts_field.name)
            ts_stmt = (
                sa.select(ts_col)
                .where(ts_col >= window_start)
                .where(*base._where_criteria)
            )
            dates = list(view_sess.scalars(ts_stmt).all())
            buckets = [0] * 14
            for dt in dates:
                if isinstance(dt, datetime):
                    dt_utc = dt.astimezone(timezone.utc) if dt.tzinfo is not None else dt
                    d = dt_utc.date()
                    diff_days = (d - (today - timedelta(days=13))).days
                    if 0 <= diff_days < 14:
                        buckets[diff_days] += 1
            spark = [float(b) for b in buckets[-7:]]
            prev_7 = sum(buckets[:7])
            curr_7 = sum(buckets[7:])
            if prev_7 > 0:
                pct = ((curr_7 - prev_7) / prev_7) * 100.0
                delta = f"{pct:+.1f}% 7d"
                trend = "up" if pct > 0 else ("down" if pct < 0 else "flat")
            elif curr_7 > 0:
                delta = f"+{curr_7} new (7d)"
                trend = "up"
            if len(trend_series) < 2:
                trend_series.append(
                    {
                        "name": view.plural_label,
                        "data": [float(b) for b in buckets],
                        "tone": "primary" if not trend_series else "ok",
                    }
                )

        widgets.append(
            KPIWidget(
                title=view.plural_label,
                value=f"{total:,}",
                delta=delta or "total rows",
                trend=trend,
                icon=view.icon,
                href=ctx.url_for_model(view.meta.slug),
                sparkline=spark,
                col_span=3,
            )
        )

    if trend_series:
        widgets.append(
            ChartWidget(
                title="14-Day Record Activity",
                subtitle="New records indexed per day across primary tables",
                chart_type="area",
                labels=trend_labels,
                series=trend_series,
                col_span=8,
            )
        )

    if model_counts:
        widgets.append(
            ChartWidget(
                title="Schema Distribution",
                subtitle="Row share across registered models",
                chart_type="donut",
                labels=[name for name, _ in model_counts],
                series=[{"data": [count for _, count in model_counts]}],
                center_label="Rows",
                col_span=4 if trend_series else 6,
            )
        )

    if deck.auth.has_permission(ctx.user, "audit:view"):
        entries = ctx.recent_audit_entries(limit=8)
        widgets.append(
            ActivityWidget(
                title="Recent Audit Trail",
                subtitle="Latest mutations captured by Flask-Deck",
                entries=entries,
                limit=8,
                col_span=12 if trend_series else 6,
            )
        )
    return widgets
