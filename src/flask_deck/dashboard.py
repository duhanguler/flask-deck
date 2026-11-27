from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
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
from flask_deck.query import apply_base_stmt_extras, soft_delete_predicate
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
        excluded = self._deck._excluded_audit_models(self.user)
        entries, _ = self._deck.audit_store.list_entries(
            limit=limit,
            excluded_models=excluded,
        )
        return [self._deck._sanitize_audit_entry(e, self.user) for e in entries]

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

    days = max(2, min(int(ctx.range_days), 90))
    model_counts: list[tuple[str, int]] = []
    trend_labels = ctx.last_n_days(days)
    trend_series: list[dict[str, Any]] = []
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=days - 1)
    window_start = datetime(start_date.year, start_date.month, start_date.day)

    for view in views[:4]:
        view_sess = deck.get_session(view.bind_key)
        base = view.scope_query(sa.select(view.model), ctx.user)
        sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
        if sd_pred is not None:
            base = base.where(sd_pred)
        count_stmt = sa.select(sa.func.count()).select_from(base.subquery())
        total = int(view_sess.execute(count_stmt).scalar_one() or 0)
        model_counts.append((view.plural_label, total))

        # Check if model has a creation timestamp to build SQL GROUP BY trends across range_days.
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
            bind_eng = view_sess.get_bind()
            d_name = bind_eng.dialect.name if bind_eng is not None else "sqlite"
            date_bucket: Any = (
                sa.func.date(ts_col) if d_name == "sqlite" else sa.cast(ts_col, sa.Date)
            )
            grp_stmt = apply_base_stmt_extras(
                sa.select(date_bucket.label("d_key"), sa.func.count().label("cnt")).select_from(
                    view.model
                ),
                base,
            )
            base_where = getattr(base, "_where_criteria", ())
            if base_where:
                grp_stmt = grp_stmt.where(*base_where)
            grp_stmt = (
                grp_stmt.where(ts_col >= window_start)
                .group_by(date_bucket)
                .order_by(date_bucket)
            )
            buckets = [0] * days
            for raw_d, cnt in view_sess.execute(grp_stmt).all():
                if raw_d is None:
                    continue
                d_obj: date | None = None
                if isinstance(raw_d, date) and not isinstance(raw_d, datetime):
                    d_obj = raw_d
                elif isinstance(raw_d, datetime):
                    d_obj = raw_d.date()
                else:
                    try:
                        d_obj = date.fromisoformat(str(raw_d)[:10])
                    except ValueError:
                        d_obj = None
                if d_obj is not None:
                    diff_days = (d_obj - start_date).days
                    if 0 <= diff_days < days:
                        buckets[diff_days] += int(cnt or 0)
            spark = [float(b) for b in buckets[-7:]]
            half = max(1, days // 2)
            prev_half = sum(buckets[:half])
            curr_half = sum(buckets[-half:])
            if prev_half > 0:
                pct = ((curr_half - prev_half) / prev_half) * 100.0
                delta = f"{pct:+.1f}% {half}d"
                trend = "up" if pct > 0 else ("down" if pct < 0 else "flat")
            elif curr_half > 0:
                delta = f"+{curr_half} new ({half}d)"
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
                title=f"{days}-Day Record Activity",
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

    if (
        deck.saved_query_store is not None
        and deck.config.enable_sql_console
        and deck.auth.has_permission(ctx.user, "sql:query")
        and deck.adapter is not None
    ):
        from flask_deck.sql_console import execute_readonly_sql, extract_sql_chart_data

        pinned_queries = deck.saved_query_store.list_queries(pinned_only=True, limit=6)
        engines = deck.adapter.get_engines()
        for sq in pinned_queries:
            target_eng = engines.get(sq.bind_key) if sq.bind_key else deck.adapter.get_engine()
            if target_eng is None:
                continue
            q_res = execute_readonly_sql(
                target_eng,
                sq.sql,
                max_rows=min(25, deck.config.sql_console_max_rows),
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            )
            if q_res.error:
                continue
            chart_pair = extract_sql_chart_data(q_res) if sq.chart_type in {"bar", "line"} else None
            if chart_pair is not None:
                c_labels, c_series = chart_pair
                widgets.append(
                    ChartWidget(
                        title=sq.name,
                        subtitle=f"Pinned BI ({sq.bind_key or 'default'})",
                        chart_type="area" if sq.chart_type == "line" else "bar",
                        labels=c_labels,
                        series=c_series,
                        col_span=6,
                    )
                )
            else:
                widgets.append(
                    TableWidget(
                        title=sq.name,
                        subtitle=f"Pinned SQL ({sq.bind_key or 'default'})",
                        headers=list(q_res.columns),
                        rows=[list(r) for r in q_res.rows[:10]],
                        col_span=6,
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
