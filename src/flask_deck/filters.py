from __future__ import annotations

import calendar
import contextlib
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, ClassVar

import sqlalchemy as sa
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from flask_deck.auth import DeckUser
    from flask_deck.introspection import ModelMeta

_DH_RE = re.compile(r"^(?:(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?)?$")


class ListFilter(ABC):
    """Declarative custom filter with optional single-query conditional facet counting."""

    parameter_name: ClassVar[str] = ""
    title: ClassVar[str] = ""

    @abstractmethod
    def lookups(
        self,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> Sequence[tuple[str, str]]:
        """Return ``[(query_value, display_label), ...]`` choices."""

    @abstractmethod
    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> sa.Select[Any]:
        """Apply filter predicate for ``value`` onto ``stmt``."""

    def facet_predicate(self, value: str, model: type[Any]) -> sa.ColumnElement[bool] | None:
        """Return pure SQL predicate for ``value`` when expressible without extra joins (enables 1-query facets)."""
        _ = (value, model)
        return None


class RangeListFilter(ListFilter):
    """Zero-boilerplate numeric or date/datetime bucket filter."""

    column: ClassVar[str] = ""
    bands: ClassVar[Sequence[tuple[str, str, Any | None, Any | None]]] = ()

    def __init__(
        self,
        *,
        parameter_name: str | None = None,
        title: str | None = None,
        column: str | None = None,
        bands: Sequence[tuple[str, str, Any | None, Any | None]] | None = None,
    ) -> None:
        self._param_name = parameter_name or self.parameter_name
        self._title = title or self.title
        self._column = column or self.column
        self._bands = tuple(bands) if bands is not None else tuple(self.bands)
        self._by_key = {b[0]: b for b in self._bands}

    @property
    def param_key(self) -> str:
        return self._param_name

    @property
    def display_title(self) -> str:
        return self._title

    def lookups(
        self,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> Sequence[tuple[str, str]]:
        _ = (session, view, user)
        return tuple((k, lbl) for k, lbl, _, _ in self._bands)

    def facet_predicate(self, value: str, model: type[Any]) -> sa.ColumnElement[bool] | None:
        band = self._by_key.get(value)
        if band is None or not self._column or not hasattr(model, self._column):
            return None
        col: Any = getattr(model, self._column)
        _, _, low, high = band
        preds: list[sa.ColumnElement[bool]] = []
        if low is not None:
            preds.append(col >= low)
        if high is not None:
            preds.append(col < high)
        if not preds:
            return None
        return sa.and_(*preds) if len(preds) > 1 else preds[0]

    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> sa.Select[Any]:
        _ = (session, user)
        pred = self.facet_predicate(value, view.model)
        return stmt.where(pred) if pred is not None else stmt


class PredicateListFilter(ListFilter):
    """Custom business-logic filter mapping string keys to SQLAlchemy predicate callables."""

    def __init__(
        self,
        *,
        parameter_name: str,
        title: str,
        choices: Sequence[tuple[str, str, Callable[[type[Any]], sa.ColumnElement[bool]]]],
    ) -> None:
        self._param_name = parameter_name
        self._title = title
        self._choices = tuple(choices)
        self._pred_map = {k: fn for k, _, fn in self._choices}

    @property
    def param_key(self) -> str:
        return self._param_name

    @property
    def display_title(self) -> str:
        return self._title

    def lookups(
        self,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> Sequence[tuple[str, str]]:
        _ = (session, view, user)
        return tuple((k, lbl) for k, lbl, _ in self._choices)

    def facet_predicate(self, value: str, model: type[Any]) -> sa.ColumnElement[bool] | None:
        fn = self._pred_map.get(value)
        return fn(model) if fn is not None else None

    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> sa.Select[Any]:
        _ = (session, user)
        pred = self.facet_predicate(value, view.model)
        return stmt.where(pred) if pred is not None else stmt


class EmptyFieldListFilter(ListFilter):
    """Built-in filter distinguishing empty (``NULL`` or blank string ``""``) vs populated values."""

    column: ClassVar[str] = ""

    def __init__(
        self,
        *,
        parameter_name: str | None = None,
        title: str | None = None,
        column: str | None = None,
        empty_label: str = "Empty / None",
        non_empty_label: str = "Not Empty",
    ) -> None:
        self._column = column or self.column
        self._param_name = parameter_name or self.parameter_name or f"{self._column}_empty"
        self._title = title or self.title or f"{self._column.replace('_', ' ').title()}"
        self._empty_label = empty_label
        self._non_empty_label = non_empty_label

    @property
    def param_key(self) -> str:
        return self._param_name

    @property
    def display_title(self) -> str:
        return self._title

    def _is_restricted(self, view: Any, user: DeckUser | None) -> bool:
        if not self._column or self._column in view.meta.sensitive_fields:
            return True
        deck = getattr(view, "_deck", None)
        if deck is not None and hasattr(deck, "auth"):
            restricted = deck.auth.hidden_fields_for(user, view.meta.slug) | deck.auth.masked_fields_for(
                user, view.meta.slug
            )
            if self._column in restricted:
                return True
        return False

    def lookups(
        self,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> Sequence[tuple[str, str]]:
        _ = session
        if self._is_restricted(view, user):
            return ()
        return (("empty", self._empty_label), ("non_empty", self._non_empty_label))

    def facet_predicate(self, value: str, model: type[Any]) -> sa.ColumnElement[bool] | None:
        if not self._column or not hasattr(model, self._column):
            return None
        col: Any = getattr(model, self._column)
        col_type = getattr(col, "type", None)
        while isinstance(col_type, sa.TypeDecorator):
            col_type = getattr(col_type, "impl", None)
        is_string_col = isinstance(col_type, (sa.String, sa.Text)) and not isinstance(
            col_type, sa.Enum
        )
        if value == "empty":
            if is_string_col:
                return sa.or_(col.is_(None), col == "")
            expr_null: sa.ColumnElement[bool] = col.is_(None)
            return expr_null
        if value == "non_empty":
            if is_string_col:
                return sa.and_(col.is_not(None), col != "")
            expr_nn: sa.ColumnElement[bool] = col.is_not(None)
            return expr_nn
        return None

    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> sa.Select[Any]:
        _ = session
        if self._is_restricted(view, user):
            return stmt
        pred = self.facet_predicate(value, view.model)
        return stmt.where(pred) if pred is not None else stmt


class RelatedOnlyFieldListFilter(ListFilter):
    """FK filter listing ONLY related records actually referenced by scoped rows in the current table."""

    column: ClassVar[str] = ""

    def __init__(
        self,
        *,
        parameter_name: str | None = None,
        title: str | None = None,
        column: str | None = None,
        limit: int = 80,
    ) -> None:
        self._column = column or self.column
        self._param_name = parameter_name or self.parameter_name or f"{self._column}_rel"
        self._title = title or self.title or self._column.replace("_id", "").replace("_", " ").title()
        self._limit = max(1, min(int(limit), 250))

    @property
    def param_key(self) -> str:
        return self._param_name

    @property
    def display_title(self) -> str:
        return self._title

    def _is_restricted(self, view: Any, user: DeckUser | None) -> bool:
        if not self._column or self._column in view.meta.sensitive_fields:
            return True
        deck = getattr(view, "_deck", None)
        if deck is not None and hasattr(deck, "auth"):
            restricted = deck.auth.hidden_fields_for(user, view.meta.slug) | deck.auth.masked_fields_for(
                user, view.meta.slug
            )
            if self._column in restricted:
                return True
        return False

    def lookups(
        self,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> Sequence[tuple[str, str]]:
        from flask_deck.introspection import introspect_model
        from flask_deck.query import soft_delete_predicate

        if self._is_restricted(view, user):
            return ()
        fmeta = view.meta.fields_by_name.get(self._column)
        if fmeta is None or fmeta.fk_target_model is None or fmeta.is_sensitive:
            return ()
        fk_col: Any = getattr(view.model, self._column)
        distinct_stmt = view.scope_query(
            sa.select(fk_col).distinct().select_from(view.model), user
        )
        sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
        if sd_pred is not None:
            distinct_stmt = distinct_stmt.where(sd_pred)
        raw_ids = [r[0] for r in session.execute(distinct_stmt.limit(self._limit + 1)).all()]
        has_null = any(v is None for v in raw_ids)
        non_null_ids = [v for v in raw_ids if v is not None][: self._limit]

        choices: list[tuple[str, str]] = []
        if non_null_ids:
            target_cls = fmeta.fk_target_model
            deck = getattr(view, "_deck", None)
            target_view = (
                deck._views_by_model.get(target_cls)
                if deck is not None and hasattr(deck, "_views_by_model")
                else None
            )
            target_meta = target_view.meta if target_view is not None else introspect_model(target_cls)
            ref_col_name = fmeta.fk_target_column or (
                target_meta.primary_keys[0].name if len(target_meta.primary_keys) == 1 else None
            )
            if ref_col_name and hasattr(target_cls, ref_col_name):
                t_ref_col: Any = getattr(target_cls, ref_col_name)
                t_stmt = sa.select(target_cls).where(t_ref_col.in_(non_null_ids))
                if target_view is not None:
                    t_stmt = target_view.scope_query(t_stmt, user)
                    t_sd = soft_delete_predicate(
                        target_view.meta, target_view.soft_delete_column, trashed=False
                    )
                    if t_sd is not None:
                        t_stmt = t_stmt.where(t_sd)
                t_sess = (
                    deck.get_session(target_view.bind_key)
                    if (deck is not None and target_view is not None)
                    else session
                )
                auth_obj = deck.auth if deck is not None and hasattr(deck, "auth") else None
                for obj in t_sess.scalars(t_stmt).all():
                    opt_val = str(getattr(obj, ref_col_name))
                    lbl = (
                        target_view.format_record_repr(obj, auth=auth_obj, user=user)
                        if target_view is not None
                        else str(obj)
                    )
                    choices.append((opt_val, lbl))
                choices.sort(key=lambda p: p[1].lower())
        if fmeta.nullable and has_null:
            choices.append(("__null__", "(None)"))
        return tuple(choices)

    def facet_predicate(self, value: str, model: type[Any]) -> sa.ColumnElement[bool] | None:
        from urllib.parse import unquote

        from flask_deck.introspection import introspect_model
        from flask_deck.query import build_filter_condition

        if not self._column or not hasattr(model, self._column):
            return None
        meta = introspect_model(model)
        clean_v = unquote(value[3:]) if value.startswith("pk:") else value
        return build_filter_condition(meta, self._column, clean_v, op="eq")

    def apply(
        self,
        stmt: sa.Select[Any],
        value: str,
        session: Session,
        view: Any,
        user: DeckUser | None,
    ) -> sa.Select[Any]:
        _ = session
        if self._is_restricted(view, user):
            return stmt
        pred = self.facet_predicate(value, view.model)
        return stmt.where(pred) if pred is not None else stmt


def filter_param_name(flt: ListFilter) -> str:
    return str(getattr(flt, "param_key", "") or flt.parameter_name)


def filter_title(flt: ListFilter) -> str:
    return str(getattr(flt, "display_title", "") or flt.title or filter_param_name(flt))


def resolve_custom_filters(raw_filters: Sequence[Any]) -> tuple[ListFilter, ...]:
    """Instantiate custom ListFilter classes cleanly while preserving existing instances."""
    resolved: list[ListFilter] = []
    for item in raw_filters:
        inst = item() if isinstance(item, type) and issubclass(item, ListFilter) else item
        if isinstance(inst, ListFilter) and filter_param_name(inst):
            resolved.append(inst)
    return tuple(resolved)


@dataclass(frozen=True, slots=True)
class DateHierarchyResult:
    """Single-query date drill-down state rendered above the list grid."""

    field_name: str
    field_label: str
    active_dh: str
    level: str  # "year" | "month" | "day" | "exact_day"
    breadcrumbs: tuple[dict[str, str], ...] = field(default_factory=tuple)
    choices: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def _date_bounds_for_dh(
    dh_value: str,
    field_type: str,
) -> tuple[int | None, int | None, int | None, Any | None, Any | None, str]:
    clean = dh_value.strip()
    m = _DH_RE.fullmatch(clean)
    if m is None:
        return None, None, None, None, None, "year"
    y_str, mo_str, d_str = m.groups()
    if y_str is None:
        return None, None, None, None, None, "year"

    year = int(y_str)
    if year < 1900 or year > 2100:
        return None, None, None, None, None, "year"

    if mo_str is None:
        start_d = date(year, 1, 1)
        end_d = date(year + 1, 1, 1)
        level = "month"
        month: int | None = None
        day: int | None = None
    elif d_str is None:
        month = int(mo_str)
        if month < 1 or month > 12:
            return None, None, None, None, None, "year"
        start_d = date(year, month, 1)
        end_d = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
        level = "day"
        day = None
    else:
        month = int(mo_str)
        day = int(d_str)
        try:
            start_d = date(year, month, day)
        except ValueError:
            return None, None, None, None, None, "year"
        end_d = start_d + timedelta(days=1)
        level = "exact_day"

    if field_type == "date":
        return year, month, day, start_d, end_d, level
    start_dt = datetime(start_d.year, start_d.month, start_d.day, tzinfo=timezone.utc)
    end_dt = datetime(end_d.year, end_d.month, end_d.day, tzinfo=timezone.utc)
    return year, month, day, start_dt, end_dt, level


def build_date_hierarchy_predicate(
    meta: ModelMeta,
    column_name: str | None,
    dh_value: str,
) -> sa.ColumnElement[bool] | None:
    """Build index-friendly SARGable range predicate for ``dh`` without executing GROUP BY."""
    if not column_name or not dh_value.strip():
        return None
    fmeta = meta.fields_by_name.get(column_name)
    if fmeta is None or fmeta.field_type not in {"date", "datetime"} or fmeta.is_sensitive:
        return None
    _, _, _, start_bound, end_bound, _ = _date_bounds_for_dh(dh_value, fmeta.field_type)
    if start_bound is None or end_bound is None:
        return None
    col: Any = getattr(meta.model, column_name)
    expr: sa.ColumnElement[bool] = sa.and_(col >= start_bound, col < end_bound)
    return expr


def _dh_bucket_expr(col: Any, *, level: str, dialect_name: str) -> Any:
    if dialect_name == "sqlite":
        fmt = "%Y" if level == "year" else ("%m" if level == "month" else "%d")
        return sa.func.strftime(fmt, col)
    if dialect_name in {"mysql", "mariadb"}:
        fmt = "%Y" if level == "year" else ("%m" if level == "month" else "%d")
        return sa.func.date_format(col, fmt)
    part = "year" if level == "year" else ("month" if level == "month" else "day")
    return sa.func.extract(part, col)


def compute_date_hierarchy(
    session: Session,
    meta: ModelMeta,
    *,
    column_name: str,
    field_label: str,
    dh_value: str,
    where_clauses: Sequence[sa.ColumnElement[bool]],
    joins: Sequence[Any] = (),
    custom_appliers: Sequence[Callable[[sa.Select[Any]], sa.Select[Any]]] = (),
    base_stmt: sa.Select[Any] | None = None,
) -> tuple[DateHierarchyResult | None, sa.ColumnElement[bool] | None]:
    """Compute hierarchical Year/Month/Day drill-down choices and SARGable SQL predicate in ONE query."""
    from flask_deck.query import apply_base_stmt_extras

    fmeta = meta.fields_by_name.get(column_name)
    if fmeta is None or fmeta.field_type not in {"date", "datetime"} or fmeta.is_sensitive:
        return None, None

    year, month, day, start_bound, end_bound, level = _date_bounds_for_dh(dh_value, fmeta.field_type)
    col: Any = getattr(meta.model, column_name)
    active_pred: sa.ColumnElement[bool] | None = None
    if start_bound is not None and end_bound is not None:
        active_pred = sa.and_(col >= start_bound, col < end_bound)

    normalized_dh = ""
    crumbs: list[dict[str, str]] = [{"dh": "", "label": "All Dates"}]
    if year is not None:
        normalized_dh = f"{year:04d}"
        crumbs.append({"dh": normalized_dh, "label": f"{year:04d}"})
        if month is not None:
            normalized_dh = f"{year:04d}-{month:02d}"
            crumbs.append(
                {
                    "dh": normalized_dh,
                    "label": f"{calendar.month_abbr[month]} {year:04d}",
                }
            )
            if day is not None:
                normalized_dh = f"{year:04d}-{month:02d}-{day:02d}"
                crumbs.append({"dh": normalized_dh, "label": f"{day:02d}"})

    choices: list[dict[str, Any]] = []
    if level in {"year", "month", "day"}:
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind is not None else ""
        bucket_expr = _dh_bucket_expr(col, level=level, dialect_name=dialect_name)
        stmt = (
            sa.select(bucket_expr.label("_dh_b"), sa.func.count().label("_dh_cnt"))
            .select_from(meta.model)
        )
        if base_stmt is not None:
            stmt = apply_base_stmt_extras(stmt, base_stmt)
        for rel_attr in joins:
            stmt = stmt.outerjoin(rel_attr)
        if where_clauses:
            stmt = stmt.where(*where_clauses)
        if active_pred is not None:
            stmt = stmt.where(active_pred)
        stmt = stmt.where(col.is_not(None))
        for applier in custom_appliers:
            stmt = applier(stmt)
        stmt = stmt.group_by(bucket_expr)
        if level == "year":
            stmt = stmt.order_by(bucket_expr.desc()).limit(15)
        else:
            stmt = stmt.order_by(bucket_expr.asc()).limit(31)

        rows = session.execute(stmt).all()
        for raw_b, raw_cnt in rows:
            if raw_b is None:
                continue
            with contextlib.suppress(TypeError, ValueError):
                b_int = int(float(str(raw_b)))
                if level == "year":
                    dh_key = f"{b_int:04d}"
                    lbl = f"{b_int:04d}"
                elif level == "month" and year is not None and 1 <= b_int <= 12:
                    dh_key = f"{year:04d}-{b_int:02d}"
                    lbl = calendar.month_abbr[b_int]
                elif level == "day" and year is not None and month is not None and 1 <= b_int <= 31:
                    dh_key = f"{year:04d}-{month:02d}-{b_int:02d}"
                    lbl = f"{b_int:02d}"
                else:
                    continue
                choices.append({"dh": dh_key, "label": lbl, "count": int(raw_cnt or 0)})

    return (
        DateHierarchyResult(
            field_name=column_name,
            field_label=field_label,
            active_dh=normalized_dh,
            level=level,
            breadcrumbs=tuple(crumbs),
            choices=tuple(choices),
        ),
        active_pred,
    )


def collect_shared_facet_exprs(
    session: Session,
    view: Any,
    *,
    filter_specs: Sequence[Mapping[str, Any]],
    custom_filters: Sequence[ListFilter],
    build_condition_fn: Callable[..., sa.ColumnElement[bool] | None],
    user: DeckUser | None,
    dialect_name: str,
) -> list[tuple[str, str, sa.ColumnElement[bool]]]:
    """Collect ``(group_key, option_val, predicate)`` tuples for all single-pass foldable facets."""
    meta: ModelMeta = view.meta
    exprs: list[tuple[str, str, sa.ColumnElement[bool]]] = []
    for spec in filter_specs:
        fname = str(spec["name"])
        ftype = str(spec["type"])
        if "." in fname:
            continue
        if ftype == "boolean":
            pairs = ["true", "false"]
            if spec.get("nullable"):
                pairs.append("__null__")
        elif ftype == "enum":
            pairs = [str(v) for v, _ in spec.get("choices", ())]
        else:
            continue
        for opt_val in pairs:
            cond = build_condition_fn(meta, fname, opt_val, op="eq", dialect_name=dialect_name)
            if cond is not None:
                exprs.append((fname, opt_val, cond))

    for cf in custom_filters:
        p_name = filter_param_name(cf)
        group_key = f"cf_{p_name}"
        preds_for_cf: list[tuple[str, str, sa.ColumnElement[bool]]] = []
        all_pure = True
        for val, _ in cf.lookups(session, view, user):
            pred = cf.facet_predicate(val, meta.model)
            if pred is None:
                all_pure = False
                break
            preds_for_cf.append((group_key, val, pred))
        if all_pure and preds_for_cf:
            exprs.extend(preds_for_cf)
    return exprs


def compute_filter_facets(
    session: Session,
    view: Any,
    *,
    base_where: Sequence[sa.ColumnElement[bool]],
    joins: Sequence[Any],
    filter_specs: Sequence[Mapping[str, Any]],
    custom_filters: Sequence[ListFilter],
    custom_appliers_by_param: Mapping[str, Callable[[sa.Select[Any]], sa.Select[Any]]],
    filter_where_by_field: Mapping[str, Sequence[sa.ColumnElement[bool]]],
    build_condition_fn: Callable[..., sa.ColumnElement[bool] | None],
    user: DeckUser | None,
    dialect_name: str,
    precomputed_facets: Mapping[str, Mapping[str, int]] | None = None,
    base_stmt: sa.Select[Any] | None = None,
) -> dict[str, dict[str, int]]:
    """Compute exact faceted option counts batching enum/boolean/predicate filters into minimal SQL queries."""
    from flask_deck.query import apply_base_stmt_extras

    facets: dict[str, dict[str, int]] = (
        {k: dict(v) for k, v in precomputed_facets.items()}
        if precomputed_facets
        else {}
    )
    meta: ModelMeta = view.meta

    def _run_batch(
        exprs: list[tuple[str, str, sa.ColumnElement[bool]]],
        *,
        exclude_filter_field: str | None = None,
        exclude_custom_param: str | None = None,
    ) -> None:
        if not exprs:
            return
        agg_cols = [
            sa.func.count(sa.case((pred, 1))).label(f"f_{i}")
            for i, (_, _, pred) in enumerate(exprs)
        ]
        stmt: Any = sa.select(*agg_cols).select_from(meta.model)
        if base_stmt is not None:
            stmt = apply_base_stmt_extras(stmt, base_stmt)
        for rel_attr in joins:
            stmt = stmt.outerjoin(rel_attr)
        if base_where:
            stmt = stmt.where(*base_where)
        for f_name, f_conds in filter_where_by_field.items():
            if exclude_filter_field is not None and f_name == exclude_filter_field:
                continue
            if f_conds:
                stmt = stmt.where(*f_conds)
        for c_param, applier in custom_appliers_by_param.items():
            if exclude_custom_param is not None and c_param == exclude_custom_param:
                continue
            stmt = applier(stmt)
        row = session.execute(stmt).first()
        if row is None:
            return
        for i, (group_key, opt_val, _) in enumerate(exprs):
            facets.setdefault(group_key, {})[opt_val] = int(row[i] or 0)

    shared_batch: list[tuple[str, str, sa.ColumnElement[bool]]] = []
    per_field_batches: dict[str, list[tuple[str, str, sa.ColumnElement[bool]]]] = {}

    for spec in filter_specs:
        fname = str(spec["name"])
        ftype = str(spec["type"])
        if "." in fname:
            continue
        if ftype == "boolean":
            pairs = [("true", "true"), ("false", "false")]
            if spec.get("nullable"):
                pairs.append(("__null__", "__null__"))
        elif ftype == "enum":
            pairs = [(str(v), str(v)) for v, _ in spec.get("choices", ())]
        else:
            continue

        is_self_filtered = fname in filter_where_by_field and bool(filter_where_by_field[fname])
        if not is_self_filtered and fname in facets:
            continue
        bucket = per_field_batches.setdefault(fname, []) if is_self_filtered else shared_batch
        for opt_val, _ in pairs:
            cond = build_condition_fn(meta, fname, opt_val, op="eq", dialect_name=dialect_name)
            if cond is not None:
                bucket.append((fname, opt_val, cond))

    # Batch pure-SQL ListFilters into the exact same single query when not self-filtered!
    complex_custom_filters: list[ListFilter] = []
    for cf in custom_filters:
        p_name = filter_param_name(cf)
        group_key = f"cf_{p_name}"
        is_self_filtered = p_name in custom_appliers_by_param
        if not is_self_filtered and group_key in facets:
            continue
        preds_for_cf: list[tuple[str, str, sa.ColumnElement[bool]]] = []
        all_pure = True
        for val, _ in cf.lookups(session, view, user):
            pred = cf.facet_predicate(val, meta.model)
            if pred is None:
                all_pure = False
                break
            preds_for_cf.append((group_key, val, pred))
        if all_pure and preds_for_cf:
            if is_self_filtered:
                _run_batch(preds_for_cf, exclude_custom_param=p_name)
            else:
                shared_batch.extend(preds_for_cf)
        elif not all_pure:
            complex_custom_filters.append(cf)

    _run_batch(shared_batch)
    for fname, batch in per_field_batches.items():
        _run_batch(batch, exclude_filter_field=fname)

    # FK filters: 1 GROUP BY query per FK filter (including NULL bucket when nullable)
    for spec in filter_specs:
        fname = str(spec["name"])
        if spec.get("type") != "fk" or fname not in meta.fields_by_name or "." in fname:
            continue
        fk_col = getattr(meta.model, fname)
        stmt = sa.select(fk_col, sa.func.count()).select_from(meta.model)
        if base_stmt is not None:
            stmt = apply_base_stmt_extras(stmt, base_stmt)
        for rel_attr in joins:
            stmt = stmt.outerjoin(rel_attr)
        if base_where:
            stmt = stmt.where(*base_where)
        for other_f, f_conds in filter_where_by_field.items():
            if other_f != fname and f_conds:
                stmt = stmt.where(*f_conds)
        for applier in custom_appliers_by_param.values():
            stmt = applier(stmt)
        if not spec.get("nullable"):
            stmt = stmt.where(fk_col.is_not(None))
        stmt = stmt.group_by(fk_col)
        counts_map: dict[str, int] = {}
        for raw_fk, cnt in session.execute(stmt).all():
            if raw_fk is None:
                if spec.get("nullable"):
                    counts_map["__null__"] = int(cnt or 0)
            else:
                counts_map[str(raw_fk)] = int(cnt or 0)
        facets[fname] = counts_map

    # Bespoke ListFilters with custom joins in apply()
    for cf in complex_custom_filters:
        p_name = filter_param_name(cf)
        group_key = f"cf_{p_name}"
        cf_map: dict[str, int] = {}
        for val, _ in cf.lookups(session, view, user):
            sub_base = sa.select(meta.model)
            if base_stmt is not None:
                sub_base = apply_base_stmt_extras(sub_base, base_stmt)
            for rel_attr in joins:
                sub_base = sub_base.outerjoin(rel_attr)
            if base_where:
                sub_base = sub_base.where(*base_where)
            for f_conds in filter_where_by_field.values():
                if f_conds:
                    sub_base = sub_base.where(*f_conds)
            for other_p, applier in custom_appliers_by_param.items():
                if other_p != p_name:
                    sub_base = applier(sub_base)
            sub_stmt = cf.apply(sub_base, val, session, view, user)
            cnt = session.execute(sa.select(sa.func.count()).select_from(sub_stmt.subquery())).scalar()
            cf_map[val] = int(cnt or 0)
        facets[group_key] = cf_map

    return facets
