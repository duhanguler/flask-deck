from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import sqlalchemy as sa
from sqlalchemy.orm import RelationshipDirection, Session

from flask_deck.adapters.sqlalchemy import encode_pk, extract_pk
from flask_deck.introspection import introspect_model
from flask_deck.security import is_safe_display_url

if TYPE_CHECKING:
    from flask_deck.auth import DeckUser
    from flask_deck.deck import Deck
    from flask_deck.model_view import ModelView


@dataclass(frozen=True, slots=True)
class DependentImpact:
    """Single incoming foreign-key relation impacted by deleting target record(s)."""

    model_slug: str | None
    model_label: str
    table_name: str
    fk_column: str
    count: int
    action: Literal["blocked", "cascade", "set_null"]
    depth: int
    samples: tuple[dict[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_slug": self.model_slug,
            "model_label": self.model_label,
            "table_name": self.table_name,
            "fk_column": self.fk_column,
            "count": self.count,
            "action": self.action,
            "depth": self.depth,
            "samples": list(self.samples),
        }


@dataclass(frozen=True, slots=True)
class DeleteImpactReport:
    """Aggregated SQL cascade/restrict/set-null impact tree before delete confirmation."""

    target_label: str
    target_count: int
    is_soft_delete: bool
    can_proceed: bool
    total_affected: int
    items: tuple[DependentImpact, ...]
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_label": self.target_label,
            "target_count": self.target_count,
            "is_soft_delete": self.is_soft_delete,
            "can_proceed": self.can_proceed,
            "total_affected": self.total_affected,
            "truncated": self.truncated,
            "items": [it.to_dict() for it in self.items],
        }


@dataclass(frozen=True, slots=True)
class _IncomingEdge:
    child_cls: type[Any]
    child_table_name: str
    child_fk_col_name: str
    child_fk_nullable: bool
    action: Literal["blocked", "cascade", "set_null"]


def _build_reverse_fk_index(root_model: type[Any]) -> dict[str, list[_IncomingEdge]]:
    """Build table_name -> incoming FK edges index from SQLAlchemy mapper registry."""
    root_mapper = sa.inspect(root_model)
    mappers = list(root_mapper.registry.mappers)

    otm_by_pair: dict[tuple[type[Any], type[Any]], list[Any]] = {}
    for p_mapper in mappers:
        for rel in p_mapper.relationships:
            if rel.direction == RelationshipDirection.ONETOMANY:
                otm_by_pair.setdefault((p_mapper.class_, rel.mapper.class_), []).append(rel)

    edges_by_target_table: dict[str, list[_IncomingEdge]] = {}
    seen_table_cols: set[tuple[str, str, str]] = set()
    for c_mapper in mappers:
        c_cls = c_mapper.class_
        c_tbl = c_mapper.local_table
        if c_tbl is None:
            continue
        for fk in c_tbl.foreign_keys:
            target_col = fk.column
            target_tbl = target_col.table
            sig = (target_tbl.name, c_tbl.name, fk.parent.name)
            if sig in seen_table_cols:
                continue
            seen_table_cols.add(sig)

            ondelete = (fk.ondelete or "").strip().upper()
            matching_rels: list[Any] = []
            for p_mapper in mappers:
                if p_mapper.local_table is not None and p_mapper.local_table.name == target_tbl.name:
                    for rel in otm_by_pair.get((p_mapper.class_, c_cls), ()):
                        if fk.parent in rel.remote_side or any(
                            col.name == fk.parent.name for col in rel.remote_side
                        ):
                            matching_rels.append(rel)

            has_orm_cascade = any(
                "delete" in r.cascade or "delete-orphan" in r.cascade for r in matching_rels
            )
            has_orm_set_null = any(not r.passive_deletes for r in matching_rels) and bool(
                fk.parent.nullable
            )

            if ondelete == "CASCADE" or has_orm_cascade:
                edge_action: Literal["blocked", "cascade", "set_null"] = "cascade"
            elif (ondelete in {"SET NULL", "SET DEFAULT"} and bool(fk.parent.nullable)) or (
                has_orm_set_null and ondelete not in {"RESTRICT", "NO ACTION"}
            ):
                edge_action = "set_null"
            else:
                edge_action = "blocked"

            edges_by_target_table.setdefault(target_tbl.name, []).append(
                _IncomingEdge(
                    child_cls=c_cls,
                    child_table_name=c_tbl.name,
                    child_fk_col_name=fk.parent.name,
                    child_fk_nullable=bool(fk.parent.nullable),
                    action=edge_action,
                )
            )
    return edges_by_target_table


def analyze_delete_impact(
    session: Session,
    deck: Deck,
    view: ModelView,
    target_pk_select: sa.Select[tuple[Any]],
    target_count: int,
    *,
    user: DeckUser | None,
    force: bool = False,
    max_depth: int = 4,
) -> DeleteImpactReport:
    """Inspect reverse FK dependents using pure SQL COUNT + LIMIT 5 samples (O(tables) queries)."""
    is_soft = bool(view.soft_delete_column and not force)
    if target_count <= 0 or len(view.meta.primary_keys) != 1:
        return DeleteImpactReport(
            target_label=view.label,
            target_count=max(0, target_count),
            is_soft_delete=is_soft,
            can_proceed=True,
            total_affected=0,
            items=(),
        )

    reverse_index = _build_reverse_fk_index(view.model)
    root_sub = target_pk_select.subquery()
    root_sub_col = next(iter(root_sub.c))

    queue: deque[tuple[type[Any], Any, int, frozenset[type[Any]]]] = deque(
        [(view.model, root_sub_col, 1, frozenset({view.model}))]
    )
    items: list[DependentImpact] = []
    truncated = False
    max_items = 25
    edge_visits: dict[tuple[type[Any], str], int] = {}

    while queue:
        parent_cls, parent_pk_col_expr, depth, path_classes = queue.popleft()
        p_mapper = sa.inspect(parent_cls)
        if p_mapper.local_table is None:
            continue
        p_table_name = p_mapper.local_table.name
        edges = reverse_index.get(p_table_name, [])
        pk_in_select = sa.select(parent_pk_col_expr)

        for edge in edges:
            edge_key = (edge.child_cls, edge.child_fk_col_name)
            visits = edge_visits.get(edge_key, 0)
            if edge.child_cls is not parent_cls and edge.child_cls in path_classes:
                continue
            if visits >= max_depth:
                continue
            edge_visits[edge_key] = visits + 1

            fk_col = getattr(edge.child_cls, edge.child_fk_col_name, None)
            if fk_col is None:
                continue

            cnt_stmt = (
                sa.select(sa.func.count())
                .select_from(edge.child_cls)
                .where(fk_col.in_(pk_in_select))
            )
            cnt = int(session.execute(cnt_stmt).scalar() or 0)
            if cnt <= 0:
                continue

            child_view = deck._views_by_model.get(edge.child_cls)
            if child_view is not None:
                child_meta = child_view.meta
                model_slug: str | None = child_meta.slug
                model_label = child_view.plural_label
            else:
                child_meta = introspect_model(edge.child_cls)
                model_slug = None
                model_label = edge.child_cls.__name__

            # Fetch up to 5 authorized samples (never leak restricted rows!)
            sample_rows: list[Any] = []
            can_view_child = child_view is not None and deck.auth.has_permission(
                user, f"{child_view.meta.slug}:view", model_slug=child_view.meta.slug
            )
            if child_view is not None and can_view_child:
                sample_stmt = child_view.scope_query(sa.select(edge.child_cls), user).where(
                    fk_col.in_(pk_in_select)
                )
                sample_stmt = sample_stmt.limit(5)
                sample_rows = list(session.scalars(sample_stmt).all())

            rel_builder = deck._rel_url_builder(user)
            samples: list[dict[str, str]] = []
            for s_obj in sample_rows:
                s_pk = encode_pk(extract_pk(s_obj, child_meta))
                if child_view is not None:
                    s_label = child_view.format_record_repr(s_obj, auth=deck.auth, user=user)
                    raw_url = rel_builder(edge.child_cls, s_obj)
                    s_url = raw_url if raw_url and is_safe_display_url(raw_url) else ""
                else:
                    s_label = f"{edge.child_cls.__name__} #{s_pk}"
                    s_url = ""
                samples.append({"pk": s_pk, "label": s_label, "url": s_url})

            items.append(
                DependentImpact(
                    model_slug=model_slug,
                    model_label=model_label,
                    table_name=edge.child_table_name,
                    fk_column=edge.child_fk_col_name,
                    count=cnt,
                    action=edge.action,
                    depth=depth,
                    samples=tuple(samples),
                )
            )
            if len(items) >= max_items:
                truncated = True
                queue.clear()
                break

            if (
                edge.action == "cascade"
                and depth < max_depth
                and len(child_meta.primary_keys) == 1
            ):
                child_pk_col = getattr(edge.child_cls, child_meta.primary_keys[0].name)
                next_sub = (
                    sa.select(child_pk_col.label("_pk"))
                    .where(fk_col.in_(pk_in_select))
                    .subquery()
                )
                queue.append(
                    (
                        edge.child_cls,
                        next(iter(next_sub.c)),
                        depth + 1,
                        path_classes | {edge.child_cls},
                    )
                )

    total_affected = sum(it.count for it in items)
    has_blocked = any(it.action == "blocked" and it.count > 0 for it in items)
    can_proceed = True if is_soft else (not has_blocked)
    return DeleteImpactReport(
        target_label=view.label,
        target_count=target_count,
        is_soft_delete=is_soft,
        can_proceed=can_proceed,
        total_affected=total_affected,
        items=tuple(items),
        truncated=truncated,
    )


__all__ = [
    "DeleteImpactReport",
    "DependentImpact",
    "analyze_delete_impact",
]
