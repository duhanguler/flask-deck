from __future__ import annotations

import enum
import json
import secrets
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode

import sqlalchemy as sa
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.datastructures import MultiDict

from flask_deck.adapters.sqlalchemy import decode_pk, encode_pk, extract_pk
from flask_deck.approvals import make_approval_request
from flask_deck.audit import AuditEntry, compute_diff
from flask_deck.exceptions import (
    ImportLimitError,
    PermissionDeniedError,
    ReadOnlyError,
    ValidationError,
)
from flask_deck.exporter import iter_export_chunks, stream_export_response
from flask_deck.filters import (
    collect_shared_facet_exprs,
    compute_date_hierarchy,
    compute_filter_facets,
)
from flask_deck.formatters import CurrencyFormatter
from flask_deck.i18n import to_user_timezone
from flask_deck.importer import (
    auto_map_headers,
    commit_dry_run_import,
    format_failed_rows_csv,
    parse_import_payload,
    run_dry_run_import,
)
from flask_deck.jobs import JobContext, JobRecord
from flask_deck.query import (
    build_filter_condition,
    compute_all_aggregates,
    compute_page_aggregates,
    execute_calendar_query,
    execute_kanban_query,
    execute_list_query,
    execute_tree_query,
    parse_sort_specs,
    prepare_scoped_clauses,
    soft_delete_predicate,
)
from flask_deck.saved_views import SavedViewRecord, render_safe_markdown
from flask_deck.security import CSRF_SESSION_KEY, is_sensitive_field
from flask_deck.storage import build_storage_key, save_stream_to_storage

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_crud_routes(bp: Blueprint, deck: Deck) -> None:
    """Register CRUD, Revision History, Soft-Delete Restore, Actions, Export, and Import routes."""
    bp_name = deck.config.name

    @bp.route("/<slug>/")
    def model_list(slug: str) -> str:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)

        user = deck._current_user()
        saved_views_records: list[SavedViewRecord] = (
            deck.saved_view_store.list_for_model(
                slug,
                user_id=user.id if user else "",
                roles=user.roles if user else (),
            )
            if deck.saved_view_store is not None
            else []
        )
        active_role_default_view: SavedViewRecord | None = None
        eff_multi_items: list[tuple[str, str]]
        if not request.args and user is not None and user.roles:
            role_set = set(user.roles)
            for sv in saved_views_records:
                if sv.scope == "role" and sv.default_for_role in role_set:
                    active_role_default_view = sv
                    break
        if active_role_default_view is not None:
            eff_multi_items = [
                (k, v)
                for k, v in parse_qsl(
                    active_role_default_view.query_string.lstrip("?"), keep_blank_values=False
                )
            ]
        else:
            eff_multi_items = list(request.args.items(multi=True))

        eff_single: dict[str, str] = {}
        for k, v in eff_multi_items:
            eff_single.setdefault(k, v)

        visible_cols = view.visible_list_columns(deck.auth, user)
        search_term = eff_single.get("q", "").strip()
        active_tab = eff_single.get("tab", "").strip() or (
            view.quick_tabs[0].key if view.quick_tabs else ""
        )
        raw_sort = eff_single.get("sort", "").strip() or None
        raw_dir = eff_single.get("dir", "desc").strip()
        try:
            page = int(eff_single.get("page", "1"))
        except ValueError:
            page = 1
        default_ps = view.page_size or deck.config.page_size
        raw_ps = eff_single.get("page_size", "").strip().lower()
        effective_max_ps = deck.config.max_page_size
        if raw_ps == "all":
            page_size = view.list_max_show_all
            effective_max_ps = max(deck.config.max_page_size, view.list_max_show_all)
        else:
            try:
                page_size = int(raw_ps) if raw_ps else default_ps
            except ValueError:
                page_size = default_ps

        filter_pairs: list[tuple[str, str]] = []
        filter_params: dict[str, str] = {}
        for k, v in eff_multi_items:
            if k.startswith("f_") and v.strip():
                fk = k[2:]
                fv = v.strip()
                filter_pairs.append((fk, fv))
                filter_params[fk] = fv

        allowed_searchable, allowed_filterable, allowed_sortable = deck._allowed_query_fields(
            view, user
        )
        sort_specs = parse_sort_specs(
            raw_sort, raw_dir, allowed_sortable=allowed_sortable, max_levels=3
        )
        hidden_fields = deck.auth.hidden_fields_for(user, slug)
        masked_fields = deck.auth.masked_fields_for(user, slug)

        custom_filter_specs, appliers_by_param, active_custom_filters, dh_pred = (
            deck._resolve_custom_filters_and_dh(view, eff_multi_items, user)
        )
        custom_appliers = list(appliers_by_param.values())

        pag_mode = view.pagination_mode or deck.config.default_pagination_mode
        after_cursor = eff_single.get("after", "").strip() or None
        before_cursor = eff_single.get("before", "").strip() or None
        trashed = bool(view.soft_delete_column and eff_single.get("trashed") == "1")

        sess = deck.get_session(view.bind_key)
        dialect_name = sess.get_bind().dialect.name if sess.get_bind() is not None else ""
        base_stmt = view.scope_query(sa.select(view.model), user)

        date_hierarchy_data = None
        if (
            view.date_hierarchy
            and not trashed
            and view.date_hierarchy not in hidden_fields
            and view.date_hierarchy not in masked_fields
        ):
            _, dh_all_where, _, dh_joins = prepare_scoped_clauses(
                view.meta,
                base_stmt=base_stmt,
                searchable_columns=allowed_searchable,
                filterable_columns=allowed_filterable,
                quick_tabs=view.quick_tabs,
                active_tab_key=active_tab or None,
                search_term=search_term,
                filter_params=filter_pairs,
                soft_delete_column=view.soft_delete_column,
                trashed=trashed,
                dialect_name=dialect_name,
                views_by_model=deck._views_by_model,
                user=user,
                auth=deck.auth,
            )
            date_hierarchy_data, dh_pred = compute_date_hierarchy(
                sess,
                view.meta,
                column_name=view.date_hierarchy,
                field_label=view.get_column_label(view.date_hierarchy),
                dh_value=eff_single.get("dh", ""),
                where_clauses=dh_all_where,
                joins=dh_joins,
                custom_appliers=custom_appliers,
            )

        filter_specs = deck._build_filter_specs(view, allowed_filterable, filter_params, user)
        filter_panel_open = bool(filter_pairs or active_custom_filters)
        want_facets = view.show_facets == "always" or (
            view.show_facets == "auto" and filter_panel_open
        )
        active_tab_has_filters = any(t.key == active_tab and t.filters for t in view.quick_tabs)
        folded_facet_exprs: list[tuple[str, str, sa.ColumnElement[bool]]] = []
        if (
            want_facets
            and not trashed
            and not filter_pairs
            and not custom_appliers
            and dh_pred is None
            and not active_tab_has_filters
            and view.count_mode != "none"
            and (view.quick_tabs or view.soft_delete_column)
        ):
            folded_facet_exprs = collect_shared_facet_exprs(
                sess,
                view,
                filter_specs=filter_specs,
                custom_filters=view.resolved_custom_filters,
                build_condition_fn=build_filter_condition,
                user=user,
                dialect_name=dialect_name,
            )

        result = execute_list_query(
            sess,
            view.meta,
            base_stmt=base_stmt,
            displayed_columns=visible_cols,
            searchable_columns=allowed_searchable,
            filterable_columns=allowed_filterable,
            sortable_columns=allowed_sortable,
            quick_tabs=view.quick_tabs,
            active_tab_key=active_tab or None,
            search_term=search_term,
            filter_params=filter_pairs,
            sort_by=sort_specs[0][0] if sort_specs else None,
            sort_dir=sort_specs[0][1] if sort_specs else raw_dir,
            default_sort=view.default_sort,
            page=page,
            page_size=page_size,
            max_page_size=effective_max_ps,
            pagination_mode=pag_mode,
            count_mode=view.count_mode,
            after_cursor=after_cursor,
            before_cursor=before_cursor,
            cursor_secret=deck._cursor_secret(),
            soft_delete_column=view.soft_delete_column,
            trashed=trashed,
            views_by_model=deck._views_by_model,
            user=user,
            auth=deck.auth,
            sort_specs=sort_specs,
            display_fields=view.display_fields,
            extra_where=[dh_pred] if dh_pred is not None else (),
            custom_filter_appliers=custom_appliers,
            extra_facet_exprs=folded_facet_exprs,
        )

        filter_panel_open = bool(result.active_filters or active_custom_filters)
        facets_data: dict[str, dict[str, int]] = {}
        if view.show_facets == "always" or (view.show_facets == "auto" and filter_panel_open):
            nf_where, _, fw_by_field, f_joins = prepare_scoped_clauses(
                view.meta,
                base_stmt=base_stmt,
                searchable_columns=allowed_searchable,
                filterable_columns=allowed_filterable,
                quick_tabs=view.quick_tabs,
                active_tab_key=active_tab or None,
                search_term=search_term,
                filter_params=filter_pairs,
                soft_delete_column=view.soft_delete_column,
                trashed=trashed,
                dialect_name=dialect_name,
                views_by_model=deck._views_by_model,
                user=user,
                auth=deck.auth,
                extra_where=[dh_pred] if dh_pred is not None else (),
            )
            facets_data = compute_filter_facets(
                sess,
                view,
                base_where=nf_where,
                joins=f_joins,
                filter_specs=filter_specs,
                custom_filters=view.resolved_custom_filters,
                custom_appliers_by_param=appliers_by_param,
                filter_where_by_field=fw_by_field,
                build_condition_fn=build_filter_condition,
                user=user,
                dialect_name=dialect_name,
                precomputed_facets=result.precomputed_facets,
            )

        can_create = (
            view.can_create
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:create", model_slug=slug)
        )
        can_edit = (
            view.can_edit
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug)
        )
        can_delete = (
            view.can_delete
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:delete", model_slug=slug)
        )
        can_force_delete = can_delete and deck.auth.has_permission(
            user, f"{slug}:force_delete", model_slug=slug
        )
        can_export = view.can_export and deck.auth.has_permission(
            user, f"{slug}:export", model_slug=slug
        )
        can_import = (
            view.can_import
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:import", model_slug=slug)
        )

        readonly_fields = deck.auth.readonly_fields_for(user, slug) | view.resolved_readonly_fields
        inline_editable = (
            (view.resolved_inline_editable - readonly_fields - hidden_fields)
            if can_edit
            else frozenset()
        )
        inline_fk_options: dict[str, list[dict[str, str]]] = {}
        if inline_editable:
            cached_fk_by_name = {
                fs["name"]: fs["fk_options"]
                for fs in filter_specs
                if fs.get("type") == "fk" and "fk_options" in fs
            }
            for col in inline_editable:
                fm = view.meta.fields_by_name.get(col)
                if fm is not None and fm.fk_target_model is not None:
                    inline_fk_options[col] = cached_fk_by_name.get(col) or deck._fk_options_for_field(
                        fm.fk_target_model, limit=40, fallback_bind_key=view.bind_key
                    )

        bulk_actions = [
            spec
            for spec in view.actions.values()
            if spec.bulk_action
            and not deck.config.read_only
            and not (spec.async_job and deck.job_backend is None)
            and deck.auth.has_permission(
                user,
                spec.permission or f"{slug}:action:{spec.name}",
                model_slug=slug,
            )
        ]
        bulk_action_fields_json = {
            spec.name: json.dumps(
                [
                    {
                        "name": f.name,
                        "type": f.field_type,
                        "label": f.display_label,
                        "choices": list(f.choices),
                        "placeholder": f.placeholder,
                        "required": f.required,
                        "default": f.default,
                    }
                    for f in spec.fields
                ]
            )
            for spec in bulk_actions
            if spec.fields
        }

        row_actions = [
            spec
            for spec in view.actions.values()
            if spec.row_action
            and not deck.config.read_only
            and not (spec.async_job and deck.job_backend is None)
            and deck.auth.has_permission(
                user,
                spec.permission or f"{slug}:action:{spec.name}",
                model_slug=slug,
            )
        ]

        supports_kanban = bool(
            view.kanban_column
            and view.kanban_column in view.meta.fields_by_name
            and view.meta.fields_by_name[view.kanban_column].choices
            and view.kanban_column not in hidden_fields
            and view.kanban_column not in masked_fields
        )
        cal_field = view.resolved_calendar_field
        supports_calendar = bool(
            cal_field and cal_field not in hidden_fields and cal_field not in masked_fields
        )
        gal_field = view.resolved_gallery_field
        supports_gallery = bool(
            gal_field and gal_field not in hidden_fields and gal_field not in masked_fields
        )
        tree_field = view.resolved_tree_field
        supports_tree = bool(
            tree_field and tree_field not in hidden_fields and tree_field not in masked_fields
        )
        req_view = eff_single.get("view", "table").strip().lower()
        if req_view == "board" and supports_kanban and not trashed:
            view_mode = "board"
        elif req_view == "calendar" and supports_calendar and not trashed:
            view_mode = "calendar"
        elif req_view == "gallery" and supports_gallery and not trashed:
            view_mode = "gallery"
        elif req_view == "tree" and supports_tree and not trashed:
            view_mode = "tree"
        else:
            view_mode = "table"

        kanban_columns: list[dict[str, Any]] = []
        can_drag_kanban = False
        kanban_card_fields: tuple[str, ...] = ()
        if view_mode == "board" and view.kanban_column is not None:
            kanban_card_fields = tuple(
                c
                for c in (view.kanban_card_fields or visible_cols[:4])
                if c not in hidden_fields
            )
            kanban_columns = execute_kanban_query(
                deck.get_session(view.bind_key),
                view.meta,
                base_stmt=base_stmt,
                kanban_column=view.kanban_column,
                card_fields=kanban_card_fields,
                searchable_columns=allowed_searchable,
                filterable_columns=allowed_filterable,
                search_term=search_term,
                filter_params=filter_pairs,
                soft_delete_column=view.soft_delete_column,
                views_by_model=deck._views_by_model,
                user=user,
                auth=deck.auth,
            )
            writable_set = set(view.allowed_form_fields(deck.auth, user, mode="edit"))
            can_drag_kanban = can_edit and view.kanban_column in writable_set

        calendar_data: dict[str, Any] = {}
        if view_mode == "calendar" and cal_field is not None:
            calendar_data = execute_calendar_query(
                deck.get_session(view.bind_key),
                view.meta,
                base_stmt=base_stmt,
                date_field=cal_field,
                month_str=eff_single.get("month", ""),
                searchable_columns=allowed_searchable,
                filterable_columns=allowed_filterable,
                search_term=search_term,
                filter_params=filter_pairs,
                soft_delete_column=view.soft_delete_column,
                views_by_model=deck._views_by_model,
                user=user,
                auth=deck.auth,
            )

        tree_nodes: list[dict[str, Any]] = []
        if view_mode == "tree" and tree_field is not None:
            tree_nodes = execute_tree_query(
                deck.get_session(view.bind_key),
                view.meta,
                base_stmt=base_stmt,
                parent_field=tree_field,
                displayed_columns=visible_cols,
                soft_delete_column=view.soft_delete_column,
            )

        allowed_agg_spec = {
            k: v
            for k, v in view.column_aggregates.items()
            if k not in hidden_fields and k not in masked_fields
        }
        page_aggregates: dict[str, tuple[str, float]] = {}
        if view_mode in {"table", "tree"} and allowed_agg_spec:
            if view.aggregate_scope == "all":
                page_aggregates = compute_all_aggregates(
                    sess,
                    view.meta,
                    base_stmt=base_stmt,
                    column_aggregates=allowed_agg_spec,
                    searchable_columns=allowed_searchable,
                    filterable_columns=allowed_filterable,
                    quick_tabs=view.quick_tabs,
                    active_tab_key=active_tab or None,
                    search_term=search_term,
                    filter_params=filter_pairs,
                    soft_delete_column=view.soft_delete_column,
                    trashed=trashed,
                    views_by_model=deck._views_by_model,
                    user=user,
                    auth=deck.auth,
                    extra_where=[dh_pred] if dh_pred is not None else (),
                    custom_filter_appliers=custom_appliers,
                )
            else:
                page_aggregates = compute_page_aggregates(result.items, allowed_agg_spec)

        aggregates_display: dict[str, tuple[str, Any]] = {}
        for col, (agg_op, agg_val) in page_aggregates.items():
            fmt_obj = view.column_formatters.get(col)
            if isinstance(fmt_obj, CurrencyFormatter):
                rendered_val: Any = fmt_obj.format(agg_val, obj=None)
            elif col.endswith("_cents"):
                rendered_val = f"{agg_val / 100.0:,.2f}"
            else:
                rendered_val = f"{agg_val:,.1f}"
            aggregates_display[col] = (agg_op, rendered_val)

        def _qs(**overrides: Any) -> str:
            params = [(k, v) for k, v in eff_multi_items if k not in overrides]
            for k, v in overrides.items():
                if v is not None and v != "":
                    params.append((k, str(v)))
            encoded = urlencode(params)
            return f"?{encoded}" if encoded else ""

        can_save_views = (
            deck.saved_view_store is not None and not deck.config.read_only and user is not None
        )
        can_manage_shared_views = bool(
            user is not None
            and (user.is_superuser or deck.auth.has_permission(user, "saved_views:manage"))
        )
        eff_sorts = sort_specs or [
            (
                view.default_sort[0] if view.default_sort else view.meta.primary_keys[0].name,
                view.default_sort[1] if view.default_sort else "desc",
            )
        ]
        sort_rank_map = {col: (idx + 1, direction) for idx, (col, direction) in enumerate(eff_sorts)}
        sort_param_value = ",".join(f"{c}:{d}" for c, d in sort_specs)
        current_qs_raw = _qs().lstrip("?")
        return_qs = deck._sanitize_return_qs(current_qs_raw) if view.preserve_filters else ""
        select_across_token = deck._sign_select_across_token(
            slug,
            user,
            {"items": [[k, v] for k, v in eff_multi_items], "trashed": trashed},
        )
        facets_url = (
            url_for(f"{bp_name}.api_facets", slug=slug)
            if view.show_facets != "never"
            else ""
        )

        return render_template(
            "flask_deck/model_list.html",
            **deck._base_context(
                page_title=view.plural_label,
                active_nav=slug,
                view=view,
                result=result,
                visible_cols=visible_cols,
                search_term=search_term,
                active_tab=active_tab,
                sort_by=eff_sorts[0][0],
                sort_dir=eff_sorts[0][1],
                sort_specs=sort_specs,
                sort_rank_map=sort_rank_map,
                sort_param_value=sort_param_value,
                filter_specs=filter_specs,
                custom_filter_specs=custom_filter_specs,
                active_custom_filters=active_custom_filters,
                filter_panel_open=filter_panel_open,
                facets_data=facets_data,
                facets_url=facets_url,
                date_hierarchy_data=date_hierarchy_data,
                inline_fk_options=inline_fk_options,
                can_create=can_create,
                can_edit=can_edit,
                can_delete=can_delete,
                can_force_delete=can_force_delete,
                can_export=can_export,
                can_import=can_import,
                inline_editable=inline_editable,
                bulk_actions=bulk_actions,
                row_actions=row_actions,
                bulk_action_fields_json=bulk_action_fields_json,
                supports_kanban=supports_kanban,
                supports_calendar=supports_calendar,
                supports_gallery=supports_gallery,
                supports_tree=supports_tree,
                view_mode=view_mode,
                kanban_columns=kanban_columns,
                kanban_card_fields=kanban_card_fields,
                can_drag_kanban=can_drag_kanban,
                calendar_data=calendar_data,
                calendar_date_field=cal_field,
                calendar_title_field=view.calendar_title_field,
                gallery_media_field=gal_field,
                gallery_subtitle_field=view.gallery_subtitle_field,
                tree_nodes=tree_nodes,
                tree_title_field=view.tree_title_field,
                page_aggregates=page_aggregates,
                aggregates_display=aggregates_display,
                supports_soft_delete=bool(view.soft_delete_column),
                trashed=trashed,
                media_url_builder=deck._media_url_builder(view),
                saved_views_records=saved_views_records,
                active_role_default_view=active_role_default_view,
                can_save_views=can_save_views,
                can_manage_shared_views=can_manage_shared_views,
                current_user_id=user.id if user else "",
                is_superuser=bool(user and user.is_superuser),
                current_query_string=current_qs_raw,
                return_qs=return_qs,
                select_across_token=select_across_token,
                active_dh=eff_single.get("dh", ""),
                raw_page_size=raw_ps,
                qs=_qs,
            ),
        )

    @bp.route("/<slug>/new", methods=["GET", "POST"])
    def model_create(slug: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_create:
            abort(403)
        deck._require_perm(f"{slug}:create", model_slug=slug)

        errors: dict[str, list[str]] = {}
        submitted: Mapping[str, Any] | None = None
        return_qs = (
            deck._sanitize_return_qs(request.values.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = deck._list_url_with_return(slug, return_qs)
        clone_pk = request.args.get("clone", "").strip()
        if request.method == "GET" and clone_pk:
            deck._require_perm(f"{slug}:view", model_slug=slug)
            source_obj, _ = deck._fetch_scoped_record(view, clone_pk)
            if deck._is_soft_deleted(view, source_obj):
                abort(404)
            user = deck._current_user()
            hidden = deck.auth.hidden_fields_for(user, slug)
            masked = deck.auth.masked_fields_for(user, slug)
            cloned: dict[str, Any] = {}
            for f in view.meta.fields:
                if (
                    f.primary_key
                    or f.unique
                    or f.is_sensitive
                    or f.name in hidden
                    or f.name in masked
                    or f.name in view.file_fields
                    or f.name == view.soft_delete_column
                ):
                    continue
                val = getattr(source_obj, f.name, None)
                if isinstance(val, enum.Enum):
                    val = val.value
                elif isinstance(val, datetime):
                    val = to_user_timezone(val).strftime("%Y-%m-%dT%H:%M")
                elif f.field_type == "json" and isinstance(val, (dict, list)):
                    val = json.dumps(val, indent=2)
                if val is not None:
                    cloned[f.name] = val
            submitted = cloned

        if request.method == "POST":
            submitted = request.form
            sess = deck.get_session(view.bind_key)
            obj = view.model()
            newly_stored: list[tuple[Any, str]] = []
            cur_user = deck._current_user()

            def _scope_m2m(target_cls: type[Any], s: sa.Select[Any]) -> sa.Select[Any]:
                tv = deck._views_by_model.get(target_cls)
                return tv.scope_query(s, cur_user) if tv is not None else s

            try:
                view.apply_form_data(
                    sess,
                    obj,
                    request.form,
                    auth=deck.auth,
                    user=cur_user,
                    mode="create",
                    max_json_depth=deck.config.max_json_depth,
                    m2m_getter=request.form.getlist,
                    m2m_scope=_scope_m2m,
                )
                newly_stored, _ = view.apply_file_uploads(
                    obj,
                    request.files,
                    request.form,
                    auth=deck.auth,
                    user=cur_user,
                    mode="create",
                    default_max_bytes=deck.config.max_upload_bytes,
                )
                view.on_model_change(obj, is_created=True, user=cur_user)
                sess.add(obj)
                sess.flush()
                inline_diffs = view.apply_inline_forms(
                    sess,
                    obj,
                    request.form,
                    auth=deck.auth,
                    user=cur_user,
                    max_json_depth=deck.config.max_json_depth,
                )
                needs_approval = deck.approval_store is not None and view.requires_approval(
                    cur_user, "create", payload=dict(request.form)
                )
                if needs_approval and deck.approval_store is not None:
                    safe_repr = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
                    diff = compute_diff(
                        {},
                        view.extract_snapshot(obj),
                        sensitive_fields=view.meta.sensitive_fields,
                        extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                    )
                    if inline_diffs:
                        diff["__inlines__"] = {
                            "old": None,
                            "new": f"{len(inline_diffs)} inline item(s)",
                        }
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored)
                    req = make_approval_request(
                        model_slug=slug,
                        model_label=view.label,
                        operation="create",
                        record_pk="pending",
                        record_repr=safe_repr,
                        payload={
                            "form_items": [[k, v] for k, v in request.form.items(multi=True)],
                            "_actor_roles": list(cur_user.roles) if cur_user else [],
                            "_actor_superuser": bool(cur_user.is_superuser) if cur_user else False,
                        },
                        diff=diff,
                        reason=request.form.get("approval_reason", "").strip(),
                        requester_id=cur_user.id if cur_user else "system",
                        requester_name=cur_user.label if cur_user else "System",
                        actor_type="human",
                    )
                    saved_req = deck.approval_store.create(req)
                    deck._emit_event(
                        "approval.requested",
                        model_slug=slug,
                        record_pk=saved_req.id,
                        payload={"approval_id": saved_req.id, "operation": "create"},
                    )
                    flash(
                        f"Create request queued for four-eyes approval (#{saved_req.id}).",
                        "ok",
                    )
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))
                sess.commit()
                pk_str = encode_pk(extract_pk(obj, view.meta))
                safe_repr = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
                snap = view.extract_snapshot(obj)
                diff = compute_diff(
                    {},
                    snap,
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                deck._record_audit(
                    action_name="create",
                    view=view,
                    record_pk=pk_str,
                    record_repr=safe_repr,
                    changes=diff,
                )
                deck._record_inline_audits(
                    view=view,
                    parent_pk=pk_str,
                    inline_diffs=inline_diffs,
                )
                deck._emit_event(
                    "record.created",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"repr": safe_repr},
                )
                flash(f"Created {view.label} ({safe_repr}).", "ok")
                save_action = request.form.get("_save_action", "save").strip()
                if save_action == "continue":
                    return redirect(
                        url_for(
                            f"{bp_name}.model_edit",
                            slug=slug,
                            raw_pk=pk_str,
                            _return_qs=return_qs or None,
                        )
                    )
                if save_action == "add_another":
                    return redirect(
                        url_for(
                            f"{bp_name}.model_create",
                            slug=slug,
                            _return_qs=return_qs or None,
                        )
                    )
                return redirect(list_return_url)
            except ValidationError as exc:
                sess.rollback()
                deck._delete_orphan_files_best_effort(newly_stored)
                errors = exc.errors
            except IntegrityError as exc:
                sess.rollback()
                deck._delete_orphan_files_best_effort(newly_stored)
                errors = {"__all__": [f"Database integrity constraint failed: {exc.orig}"]}
            except SQLAlchemyError as exc:
                sess.rollback()
                deck._delete_orphan_files_best_effort(newly_stored)
                errors = {"__all__": [f"Database error: {exc.__class__.__name__}"]}
            except Exception:
                sess.rollback()
                deck._delete_orphan_files_best_effort(newly_stored)
                raise

        form_ctx = deck._build_form_context(
            view, obj=None, mode="create", errors=errors, submitted=submitted
        )
        cur_user_create = deck._current_user()
        requires_approval_hint = deck.approval_store is not None and view.requires_approval(
            cur_user_create, "create"
        )
        return render_template(
            "flask_deck/model_form.html",
            **deck._base_context(
                page_title=f"New {view.label}",
                active_nav=slug,
                requires_approval_hint=requires_approval_hint,
                return_qs=return_qs,
                list_return_url=list_return_url,
                can_add_another=True,
                can_save_as=False,
                view_on_site_url=None,
                **form_ctx,
            ),
        )

    @bp.route("/<slug>/<raw_pk>")
    def model_detail(slug: str, raw_pk: str) -> str:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()
        hidden = deck.auth.hidden_fields_for(user, slug)

        media_builder = deck._media_url_builder(view)
        rel_url_builder = deck._rel_url_builder(user)
        return_qs = (
            deck._sanitize_return_qs(request.args.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = (
            url_for(f"{bp_name}.model_list", slug=slug)
            + (f"?{return_qs}" if return_qs else "")
        )
        view_on_site_url = view.get_view_on_site_url(obj)
        fields_display = []
        for f in view.meta.fields:
            if f.name in hidden or f.is_sensitive:
                continue
            fk_rel = view.meta.fk_column_to_rel.get(f.name)
            col_key = fk_rel.name if (fk_rel is not None and fk_rel.name not in hidden) else f.name
            fields_display.append(
                {
                    "name": f.name,
                    "label": view.get_column_label(f.name),
                    "formatted": view.format_cell(
                        col_key,
                        obj,
                        auth=deck.auth,
                        user=user,
                        media_url_builder=media_builder,
                        rel_repr=deck._rel_repr,
                        rel_url_builder=rel_url_builder,
                    ),
                }
            )
        seen_disp_names = {d["name"] for d in fields_display}
        for disp_name in view.display_fields:
            if disp_name in hidden or disp_name in seen_disp_names:
                continue
            fields_display.append(
                {
                    "name": disp_name,
                    "label": view.get_column_label(disp_name),
                    "formatted": view.format_cell(
                        disp_name,
                        obj,
                        auth=deck.auth,
                        user=user,
                        media_url_builder=media_builder,
                        rel_repr=deck._rel_repr,
                        rel_url_builder=rel_url_builder,
                    ),
                }
            )

        relations_display = []
        subtables: list[dict[str, Any]] = []
        for rel in view.meta.relationships:
            if rel.name in hidden:
                continue
            val = getattr(obj, rel.name, None)
            items = list(val) if (rel.uselist and val is not None) else ([val] if val is not None else [])
            relations_display.append(
                {
                    "name": rel.name,
                    "label": rel.label,
                    "uselist": rel.uselist,
                    "count": len(items),
                    "records": [
                        {
                            "label": deck._rel_repr(rel.target_model, it),
                            "href": rel_url_builder(rel.target_model, it),
                        }
                        for it in items[:25]
                    ],
                }
            )
            if rel.uselist:
                t_view = deck._views_by_model.get(rel.target_model)
                if (
                    t_view is not None
                    and t_view.can_view
                    and deck.auth.has_permission(
                        user, f"{t_view.meta.slug}:view", model_slug=t_view.meta.slug
                    )
                ):
                    t_cols = t_view.visible_list_columns(deck.auth, user)[:6]
                    t_media = deck._media_url_builder(t_view)
                    active_items = [it for it in items if not deck._is_soft_deleted(t_view, it)]
                    sub_rows = []
                    for it in active_items[:25]:
                        it_pk = encode_pk(extract_pk(it, t_view.meta))
                        sub_rows.append(
                            {
                                "pk_str": it_pk,
                                "detail_url": url_for(
                                    f"{bp_name}.model_detail", slug=t_view.meta.slug, raw_pk=it_pk
                                ),
                                "cells": [
                                    t_view.format_cell(
                                        c,
                                        it,
                                        auth=deck.auth,
                                        user=user,
                                        media_url_builder=t_media,
                                        rel_repr=deck._rel_repr,
                                        rel_url_builder=rel_url_builder,
                                    )
                                    for c in t_cols
                                ],
                            }
                        )
                    t_create_url = (
                        url_for(f"{bp_name}.model_create", slug=t_view.meta.slug)
                        if (
                            t_view.can_create
                            and not deck.config.read_only
                            and deck.auth.has_permission(
                                user, f"{t_view.meta.slug}:create", model_slug=t_view.meta.slug
                            )
                        )
                        else None
                    )
                    subtables.append(
                        {
                            "label": rel.label,
                            "target_view": t_view,
                            "cols": t_cols,
                            "rows": sub_rows,
                            "total_count": len(active_items),
                            "list_url": url_for(f"{bp_name}.model_list", slug=t_view.meta.slug),
                            "create_url": t_create_url,
                        }
                    )

        history: list[AuditEntry] = []
        if deck.audit_store is not None and deck.auth.has_permission(user, "audit:view"):
            raw_history, _ = deck.audit_store.list_entries(
                model_slug=slug, record_pk=pk_str, limit=25
            )
            history = [deck._sanitize_audit_entry(e, user) for e in raw_history]

        can_create = (
            view.can_create
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:create", model_slug=slug)
        )
        can_edit = (
            view.can_edit
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
        )
        can_delete = (
            view.can_delete
            and not deck.config.read_only
            and deck.auth.has_permission(user, f"{slug}:delete", model_slug=slug, obj=obj)
        )
        can_force_delete = (
            can_delete
            and deck.auth.has_permission(user, f"{slug}:force_delete", model_slug=slug, obj=obj)
        )

        is_soft_deleted = deck._is_soft_deleted(view, obj)
        record_notes = (
            deck.note_store.list_notes(slug, pk_str) if deck.note_store is not None else []
        )
        can_write_notes = bool(
            deck.note_store is not None
            and not deck.config.read_only
            and (
                deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
                or deck.auth.has_permission(user, "notes:write", model_slug=slug, obj=obj)
            )
        )

        return render_template(
            "flask_deck/model_detail.html",
            **deck._base_context(
                page_title=view.format_record_repr(obj, auth=deck.auth, user=user),
                active_nav=slug,
                view=view,
                obj=obj,
                pk_str=pk_str,
                record_repr=view.format_record_repr(obj, auth=deck.auth, user=user),
                fields_display=fields_display,
                relations_display=relations_display,
                subtables=subtables,
                history=history,
                record_notes=record_notes,
                render_note_md=render_safe_markdown,
                can_write_notes=can_write_notes,
                current_user_id=user.id if user else "",
                is_superuser=bool(user and user.is_superuser),
                can_create=can_create,
                can_edit=can_edit,
                can_delete=can_delete,
                can_force_delete=can_force_delete,
                is_soft_deleted=is_soft_deleted,
                return_qs=return_qs,
                list_return_url=list_return_url,
                view_on_site_url=view_on_site_url,
            ),
        )

    @bp.route("/<slug>/<raw_pk>/history")
    def model_history(slug: str, raw_pk: str) -> str:
        if deck.audit_store is None:
            abort(404)
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        deck._require_perm("audit:view")
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
        pk_str = encode_pk(pk_vals)
        user = deck._current_user()
        raw_entries, _ = deck.audit_store.list_entries(
            model_slug=slug, record_pk=pk_str, limit=50
        )
        entries = [deck._sanitize_audit_entry(e, user) for e in raw_entries]
        selected_id = request.args.get("rev", "").strip()
        selected_entry = next((e for e in entries if e.id == selected_id), None) or (
            entries[0] if entries else None
        )
        current_snap = view.extract_snapshot(obj)
        hidden = deck.auth.hidden_fields_for(user, slug)
        masked = deck.auth.masked_fields_for(user, slug)
        diff_rows: list[dict[str, Any]] = []
        if selected_entry is not None:
            for fname, delta in selected_entry.changes.items():
                if fname in hidden:
                    continue
                old_v = delta.get("old")
                new_v = delta.get("new")
                live_v = current_snap.get(fname)
                if isinstance(live_v, enum.Enum):
                    live_v = live_v.value
                elif isinstance(live_v, datetime):
                    live_v = to_user_timezone(live_v).strftime("%Y-%m-%d %H:%M")
                if (
                    fname in view.meta.sensitive_fields
                    or fname in masked
                    or is_sensitive_field(fname, deck.config.extra_sensitive_patterns)
                ):
                    old_v = "[REDACTED]" if old_v is not None else None
                    new_v = "[REDACTED]" if new_v is not None else None
                    live_v = "[REDACTED]" if live_v is not None else None
                diff_rows.append(
                    {
                        "field": fname,
                        "label": view.get_column_label(fname),
                        "old": old_v,
                        "new": new_v,
                        "live": live_v,
                    }
                )

        can_revert = (
            deck.config.enable_audit_revert
            and not deck.config.read_only
            and deck.auth.has_permission(user, "audit:revert")
        )
        return render_template(
            "flask_deck/record_history.html",
            **deck._base_context(
                page_title=f"Revision History · {view.format_record_repr(obj, auth=deck.auth, user=user)}",
                active_nav=slug,
                view=view,
                pk_str=pk_str,
                record_repr=view.format_record_repr(obj, auth=deck.auth, user=user),
                entries=entries,
                selected_entry=selected_entry,
                diff_rows=diff_rows,
                can_revert=can_revert,
            ),
        )

    @bp.route("/<slug>/<raw_pk>/edit", methods=["GET", "POST"])
    def model_edit(slug: str, raw_pk: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_edit:
            abort(403)
        deck._require_perm(f"{slug}:edit", model_slug=slug)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:edit", model_slug=slug, obj=obj)
        if deck._is_soft_deleted(view, obj):
            flash(
                f"Restore {view.label} from Trash before editing.",
                "warn",
            )
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=encode_pk(pk_vals)))
        pk_str = encode_pk(pk_vals)
        cur_user = deck._current_user()
        return_qs = (
            deck._sanitize_return_qs(request.values.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = deck._list_url_with_return(slug, return_qs)
        can_add_another = bool(
            view.can_create
            and not deck.config.read_only
            and deck.auth.has_permission(cur_user, f"{slug}:create", model_slug=slug)
        )
        can_save_as = bool(view.save_as and can_add_another)

        errors: dict[str, list[str]] = {}
        submitted: Mapping[str, Any] | None = None
        occ_conflict: list[dict[str, Any]] | None = None
        if request.method == "POST":
            submitted = request.form
            sess = deck.get_session(view.bind_key)
            save_action = request.form.get("_save_action", "save").strip()
            if save_action == "save_as":
                if not can_save_as:
                    raise PermissionDeniedError(f"Save as new is not allowed on {slug}.")
                clone_pairs: list[tuple[str, str]] = []
                for fk_name, fv_val in request.form.items(multi=True):
                    if fk_name.startswith("inline__") and fk_name.endswith("___pk"):
                        clone_pairs.append((fk_name, ""))
                    else:
                        clone_pairs.append((fk_name, fv_val))
                clone_md = MultiDict(clone_pairs)
                new_obj = view.model()
                newly_stored_as: list[tuple[Any, str]] = []

                def _scope_m2m_as(target_cls: type[Any], s: sa.Select[Any]) -> sa.Select[Any]:
                    tv = deck._views_by_model.get(target_cls)
                    return tv.scope_query(s, cur_user) if tv is not None else s

                try:
                    view.apply_form_data(
                        sess,
                        new_obj,
                        clone_md,
                        auth=deck.auth,
                        user=cur_user,
                        mode="create",
                        max_json_depth=deck.config.max_json_depth,
                        m2m_getter=clone_md.getlist,
                        m2m_scope=_scope_m2m_as,
                    )
                    newly_stored_as, _ = view.apply_file_uploads(
                        new_obj,
                        request.files,
                        clone_md,
                        auth=deck.auth,
                        user=cur_user,
                        mode="create",
                        default_max_bytes=deck.config.max_upload_bytes,
                    )
                    view.on_model_change(new_obj, is_created=True, user=cur_user)
                    sess.add(new_obj)
                    sess.flush()
                    inline_diffs_as = view.apply_inline_forms(
                        sess,
                        new_obj,
                        clone_md,
                        auth=deck.auth,
                        user=cur_user,
                        max_json_depth=deck.config.max_json_depth,
                    )
                    if deck.approval_store is not None and view.requires_approval(
                        cur_user, "create", payload=dict(clone_md)
                    ):
                        safe_repr = view.format_record_repr(new_obj, auth=deck.auth, user=cur_user)
                        diff = compute_diff(
                            {},
                            view.extract_snapshot(new_obj),
                            sensitive_fields=view.meta.sensitive_fields,
                            extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                        )
                        sess.rollback()
                        deck._delete_orphan_files_best_effort(newly_stored_as)
                        req = make_approval_request(
                            model_slug=slug,
                            model_label=view.label,
                            operation="create",
                            record_pk="pending",
                            record_repr=safe_repr,
                            payload={
                                "form_items": [[k, v] for k, v in clone_md.items(multi=True)],
                                "_actor_roles": list(cur_user.roles) if cur_user else [],
                                "_actor_superuser": bool(cur_user.is_superuser) if cur_user else False,
                            },
                            diff=diff,
                            reason=request.form.get("approval_reason", "").strip(),
                            requester_id=cur_user.id if cur_user else "system",
                            requester_name=cur_user.label if cur_user else "System",
                            actor_type="human",
                        )
                        saved_req = deck.approval_store.create(req)
                        flash(
                            f"Save-as-new request queued for four-eyes approval (#{saved_req.id}).",
                            "ok",
                        )
                        return redirect(list_return_url)
                    sess.commit()
                    new_pk_str = encode_pk(extract_pk(new_obj, view.meta))
                    safe_repr = view.format_record_repr(new_obj, auth=deck.auth, user=cur_user)
                    diff = compute_diff(
                        {},
                        view.extract_snapshot(new_obj),
                        sensitive_fields=view.meta.sensitive_fields,
                        extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                    )
                    deck._record_audit(
                        action_name="create",
                        view=view,
                        record_pk=new_pk_str,
                        record_repr=safe_repr,
                        changes=diff,
                        metadata={"saved_as_from": pk_str},
                    )
                    deck._record_inline_audits(
                        view=view,
                        parent_pk=new_pk_str,
                        inline_diffs=inline_diffs_as,
                    )
                    deck._emit_event(
                        "record.created",
                        model_slug=slug,
                        record_pk=new_pk_str,
                        payload={"repr": safe_repr, "saved_as_from": pk_str},
                    )
                    flash(f"Saved as new {view.label} ({safe_repr}).", "ok")
                    return redirect(
                        url_for(
                            f"{bp_name}.model_edit",
                            slug=slug,
                            raw_pk=new_pk_str,
                            _return_qs=return_qs or None,
                        )
                    )
                except ValidationError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored_as)
                    errors = exc.errors
                except IntegrityError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored_as)
                    errors = {"__all__": [f"Database integrity constraint failed: {exc.orig}"]}
                except SQLAlchemyError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored_as)
                    errors = {"__all__": [f"Database error: {exc.__class__.__name__}"]}
                except Exception:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored_as)
                    raise
            else:
                current_ver = view.compute_version_token(obj, auth=deck.auth, user=cur_user)
                submitted_ver = request.form.get("_deck_version")
                force_overwrite = request.form.get("_deck_force_overwrite", "").strip() == "1"
                if (
                    submitted_ver is not None
                    and not force_overwrite
                    and submitted_ver.strip() != current_ver
                ):
                    conflicts: list[dict[str, Any]] = []
                    writable_fields = view.allowed_form_fields(deck.auth, cur_user, mode="edit")
                    masked = deck.auth.masked_fields_for(cur_user, slug)
                    for col in writable_fields:
                        if col in masked or col in view.file_fields:
                            continue
                        fmeta = view.meta.fields_by_name.get(col)
                        if fmeta is None or fmeta.primary_key:
                            continue
                        cur_val = getattr(obj, col, None)
                        if isinstance(cur_val, enum.Enum):
                            cur_val = cur_val.value
                        sub_raw = request.form.get(col)
                        cur_str = "" if cur_val is None else str(cur_val)
                        if fmeta.field_type == "boolean":
                            sub_bool = str(sub_raw or "").strip().lower() in {
                                "1",
                                "true",
                                "yes",
                                "on",
                            }
                            cur_bool = bool(cur_val)
                            if sub_bool != cur_bool:
                                conflicts.append(
                                    {
                                        "field": col,
                                        "label": view.get_column_label(col),
                                        "submitted": str(sub_bool),
                                        "current": str(cur_bool),
                                    }
                                )
                        elif sub_raw is not None and sub_raw != cur_str:
                            conflicts.append(
                                {
                                    "field": col,
                                    "label": view.get_column_label(col),
                                    "submitted": sub_raw,
                                    "current": cur_str,
                                }
                            )
                    if not conflicts:
                        conflicts.append(
                            {
                                "field": "__version__",
                                "label": "Record Version",
                                "submitted": submitted_ver.strip() or "(stale)",
                                "current": current_ver,
                            }
                        )
                    sess.rollback()
                    form_ctx = deck._build_form_context(
                        view,
                        obj=obj,
                        mode="edit",
                        errors={
                            "__all__": [
                                "Concurrent modification detected (409). Another user updated this record since you opened it."
                            ]
                        },
                        submitted=submitted,
                    )
                    return (
                        render_template(
                            "flask_deck/model_form.html",
                            **deck._base_context(
                                page_title=f"Edit {view.format_record_repr(obj, auth=deck.auth, user=cur_user)}",
                                active_nav=slug,
                                pk_str=pk_str,
                                occ_conflict=conflicts,
                                return_qs=return_qs,
                                list_return_url=list_return_url,
                                can_add_another=can_add_another,
                                can_save_as=can_save_as,
                                view_on_site_url=view.get_view_on_site_url(obj),
                                requires_approval_hint=(
                                    deck.approval_store is not None
                                    and view.requires_approval(cur_user, "edit", obj=obj)
                                ),
                                **form_ctx,
                            ),
                        ),
                        409,
                    )

                before_snap = view.extract_snapshot(obj)
                newly_stored: list[tuple[Any, str]] = []
                orphans: list[tuple[Any, str]] = []

                def _scope_m2m(target_cls: type[Any], s: sa.Select[Any]) -> sa.Select[Any]:
                    tv = deck._views_by_model.get(target_cls)
                    return tv.scope_query(s, cur_user) if tv is not None else s

                try:
                    needs_approval = deck.approval_store is not None and view.requires_approval(
                        cur_user, "edit", obj=obj, payload=dict(request.form)
                    )
                    view.apply_form_data(
                        sess,
                        obj,
                        request.form,
                        auth=deck.auth,
                        user=cur_user,
                        mode="edit",
                        max_json_depth=deck.config.max_json_depth,
                        m2m_getter=request.form.getlist,
                        m2m_scope=_scope_m2m,
                    )
                    newly_stored, orphans = view.apply_file_uploads(
                        obj,
                        request.files,
                        request.form,
                        auth=deck.auth,
                        user=cur_user,
                        mode="edit",
                        default_max_bytes=deck.config.max_upload_bytes,
                    )
                    if not needs_approval and view.version_column:
                        vf = view.meta.fields_by_name.get(view.version_column)
                        if vf is not None and vf.field_type == "integer":
                            setattr(
                                obj,
                                view.version_column,
                                int(before_snap.get(view.version_column) or 0) + 1,
                            )
                    view.on_model_change(obj, is_created=False, user=cur_user)
                    sess.flush()
                    inline_diffs = view.apply_inline_forms(
                        sess,
                        obj,
                        request.form,
                        auth=deck.auth,
                        user=cur_user,
                        max_json_depth=deck.config.max_json_depth,
                    )
                    if needs_approval and deck.approval_store is not None:
                        safe_repr = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
                        diff = compute_diff(
                            before_snap,
                            view.extract_snapshot(obj),
                            sensitive_fields=view.meta.sensitive_fields,
                            extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                        )
                        if inline_diffs:
                            diff["__inlines__"] = {
                                "old": None,
                                "new": f"{len(inline_diffs)} inline item(s)",
                            }
                        sess.rollback()
                        deck._delete_orphan_files_best_effort(newly_stored)
                        req = make_approval_request(
                            model_slug=slug,
                            model_label=view.label,
                            operation="edit",
                            record_pk=pk_str,
                            record_repr=safe_repr,
                            payload={
                                "form_items": [[k, v] for k, v in request.form.items(multi=True)],
                                "_actor_roles": list(cur_user.roles) if cur_user else [],
                                "_actor_superuser": bool(cur_user.is_superuser) if cur_user else False,
                            },
                            diff=diff,
                            reason=request.form.get("approval_reason", "").strip(),
                            requester_id=cur_user.id if cur_user else "system",
                            requester_name=cur_user.label if cur_user else "System",
                            actor_type="human",
                        )
                        saved_req = deck.approval_store.create(req)
                        deck._emit_event(
                            "approval.requested",
                            model_slug=slug,
                            record_pk=pk_str,
                            payload={"approval_id": saved_req.id, "operation": "edit"},
                        )
                        flash(
                            f"Edit request queued for four-eyes approval (#{saved_req.id}).",
                            "ok",
                        )
                        return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
                    sess.commit()
                    deck._delete_orphan_files_best_effort(orphans)
                    after_snap = view.extract_snapshot(obj)
                    safe_repr = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
                    diff = compute_diff(
                        before_snap,
                        after_snap,
                        sensitive_fields=view.meta.sensitive_fields,
                        extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                    )
                    if diff:
                        deck._record_audit(
                            action_name="update",
                            view=view,
                            record_pk=pk_str,
                            record_repr=safe_repr,
                            changes=diff,
                        )
                        deck._emit_event(
                            "record.updated",
                            model_slug=slug,
                            record_pk=pk_str,
                            payload={"fields": sorted(diff.keys())},
                        )
                    deck._record_inline_audits(
                        view=view,
                        parent_pk=pk_str,
                        inline_diffs=inline_diffs,
                    )
                    flash(f"Saved changes to {safe_repr}.", "ok")
                    if save_action == "continue":
                        return redirect(
                            url_for(
                                f"{bp_name}.model_edit",
                                slug=slug,
                                raw_pk=pk_str,
                                _return_qs=return_qs or None,
                            )
                        )
                    if save_action == "add_another" and can_add_another:
                        return redirect(
                            url_for(
                                f"{bp_name}.model_create",
                                slug=slug,
                                _return_qs=return_qs or None,
                            )
                        )
                    if return_qs:
                        return redirect(list_return_url)
                    return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
                except ValidationError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored)
                    errors = exc.errors
                except IntegrityError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored)
                    errors = {"__all__": [f"Database integrity constraint failed: {exc.orig}"]}
                except SQLAlchemyError as exc:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored)
                    errors = {"__all__": [f"Database error: {exc.__class__.__name__}"]}
                except Exception:
                    sess.rollback()
                    deck._delete_orphan_files_best_effort(newly_stored)
                    raise

        form_ctx = deck._build_form_context(
            view, obj=obj, mode="edit", errors=errors, submitted=submitted
        )
        return render_template(
            "flask_deck/model_form.html",
            **deck._base_context(
                page_title=f"Edit {view.format_record_repr(obj, auth=deck.auth, user=cur_user)}",
                active_nav=slug,
                pk_str=pk_str,
                occ_conflict=occ_conflict,
                return_qs=return_qs,
                list_return_url=list_return_url,
                can_add_another=can_add_another,
                can_save_as=can_save_as,
                view_on_site_url=view.get_view_on_site_url(obj),
                requires_approval_hint=(
                    deck.approval_store is not None
                    and view.requires_approval(cur_user, "edit", obj=obj)
                ),
                **form_ctx,
            ),
        )

    @bp.route("/<slug>/<raw_pk>/delete", methods=["POST"])
    def model_delete(slug: str, raw_pk: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_delete:
            abort(403)
        deck._require_perm(f"{slug}:delete", model_slug=slug)
        force_delete = request.form.get("force", "").strip() == "1"
        if view.soft_delete_column and force_delete:
            deck._require_perm(f"{slug}:force_delete", model_slug=slug)
        if deck.config.demo_safe_mode and (not view.soft_delete_column or force_delete):
            raise ReadOnlyError("Permanent record deletion is disabled in public Demo Safe Mode.")
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:delete", model_slug=slug, obj=obj)
        cur_user = deck._current_user()
        pk_str = encode_pk(pk_vals)
        repr_str = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
        before_snap = view.extract_snapshot(obj)
        return_qs = (
            deck._sanitize_return_qs(request.values.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = deck._list_url_with_return(slug, return_qs)

        sess = deck.get_session(view.bind_key)
        if deck.approval_store is not None and view.requires_approval(
            cur_user, "delete", obj=obj, payload={"force": force_delete}
        ):
            if view.soft_delete_column and not force_delete:
                del_diff = {
                    view.soft_delete_column: {
                        "old": before_snap.get(view.soft_delete_column),
                        "new": "trashed",
                    }
                }
            else:
                del_diff = compute_diff(
                    before_snap,
                    {},
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
            sess.rollback()
            req = make_approval_request(
                model_slug=slug,
                model_label=view.label,
                operation="delete",
                record_pk=pk_str,
                record_repr=repr_str,
                payload={
                    "force": force_delete,
                    "_actor_roles": list(cur_user.roles) if cur_user else [],
                    "_actor_superuser": bool(cur_user.is_superuser) if cur_user else False,
                },
                diff=del_diff,
                reason=request.form.get("approval_reason", "").strip(),
                requester_id=cur_user.id if cur_user else "system",
                requester_name=cur_user.label if cur_user else "System",
                actor_type="human",
            )
            saved_req = deck.approval_store.create(req)
            deck._emit_event(
                "approval.requested",
                model_slug=slug,
                record_pk=pk_str,
                payload={"approval_id": saved_req.id, "operation": "delete"},
            )
            flash(
                f"Delete request queued for four-eyes approval (#{saved_req.id}).",
                "ok",
            )
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
        if view.soft_delete_column and not force_delete:
            fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
            if fmeta is not None:
                try:
                    view.on_model_delete(obj, user=cur_user)
                    setattr(
                        obj,
                        view.soft_delete_column,
                        True if fmeta.field_type == "boolean" else datetime.now(timezone.utc),
                    )
                    sess.commit()
                except SQLAlchemyError:
                    sess.rollback()
                    flash(f"Could not move {repr_str} to Trash.", "danger")
                    return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
                after_snap = view.extract_snapshot(obj)
                deck._record_audit(
                    action_name="soft_delete",
                    view=view,
                    record_pk=pk_str,
                    record_repr=repr_str,
                    changes=compute_diff(
                        before_snap,
                        after_snap,
                        sensitive_fields=view.meta.sensitive_fields,
                        extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                    ),
                )
                deck._emit_event(
                    "record.deleted",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"soft": True, "repr": repr_str},
                )
                flash(f"Moved {view.label} ({repr_str}) to Trash.", "ok")
                return redirect(list_return_url)

        if view.soft_delete_column and force_delete:
            deck._require_perm(f"{slug}:force_delete", model_slug=slug, obj=obj)

        orphan_files = deck._collect_orphan_files(view, obj)
        try:
            view.on_model_delete(obj, user=cur_user)
            sess.delete(obj)
            sess.commit()
        except IntegrityError:
            sess.rollback()
            flash(
                f"Cannot delete {repr_str}: referenced by dependent records.",
                "danger",
            )
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))

        deck._delete_orphan_files_best_effort(orphan_files)
        deck._record_audit(
            action_name="delete",
            view=view,
            record_pk=pk_str,
            record_repr=repr_str,
            changes=compute_diff(
                before_snap,
                {},
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            ),
        )
        deck._emit_event(
            "record.deleted",
            model_slug=slug,
            record_pk=pk_str,
            payload={"soft": False, "repr": repr_str},
        )
        flash(f"Deleted {view.label} ({repr_str}).", "ok")
        return redirect(list_return_url)

    @bp.route("/<slug>/<raw_pk>/restore", methods=["POST"])
    def model_restore(slug: str, raw_pk: str) -> Any:
        view = deck.get_view(slug)
        if not view.soft_delete_column:
            abort(404)
        if not view.can_edit:
            abort(403)
        deck._require_perm(f"{slug}:edit", model_slug=slug)
        obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:edit", model_slug=slug, obj=obj)
        fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
        if fmeta is None:
            abort(404)
        pk_str = encode_pk(pk_vals)
        cur_user = deck._current_user()
        repr_str = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
        return_qs = (
            deck._sanitize_return_qs(request.values.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = deck._list_url_with_return(slug, return_qs)
        if not deck._is_soft_deleted(view, obj):
            flash(f"{view.label} ({repr_str}) is already active.", "neutral")
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
        before_snap = view.extract_snapshot(obj)
        sess = deck.get_session(view.bind_key)
        try:
            setattr(obj, view.soft_delete_column, False if fmeta.field_type == "boolean" else None)
            view.on_model_change(obj, is_created=False, user=cur_user)
            sess.commit()
        except (ValidationError, SQLAlchemyError) as exc:
            sess.rollback()
            flash(f"Restore failed: {exc}", "danger")
            return redirect(url_for(f"{bp_name}.model_detail", slug=slug, raw_pk=pk_str))
        after_snap = view.extract_snapshot(obj)
        deck._record_audit(
            action_name="restore",
            view=view,
            record_pk=pk_str,
            record_repr=repr_str,
            changes=compute_diff(
                before_snap,
                after_snap,
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            ),
        )
        deck._emit_event(
            "record.restored",
            model_slug=slug,
            record_pk=pk_str,
            payload={"repr": repr_str},
        )
        flash(f"Restored {view.label} ({repr_str}) from Trash.", "ok")
        return redirect(list_return_url)

    @bp.route("/<slug>/action/<action_name>", methods=["POST"])
    def model_action(slug: str, action_name: str) -> Any:
        view = deck.get_view(slug)
        user = deck._current_user()
        return_qs = (
            deck._sanitize_return_qs(request.form.get("_return_qs", ""))
            if view.preserve_filters
            else ""
        )
        list_return_url = deck._list_url_with_return(slug, return_qs)
        trash_return_url = (
            list_return_url
            if return_qs
            else url_for(f"{bp_name}.model_list", slug=slug, trashed="1")
        )
        is_trash_bulk = action_name in {"restore", "force_delete"}
        sd_pred = (
            soft_delete_predicate(view.meta, view.soft_delete_column, trashed=is_trash_bulk)
            if view.soft_delete_column
            else None
        )
        sess = deck.get_session(view.bind_key)

        select_across = request.form.get("select_across") == "1"
        if select_across:
            slice_token = request.form.get("slice_token", "").strip()
            token_state = deck._verify_select_across_token(
                slice_token, expected_slug=slug, user=user
            )
            if token_state is None:
                abort(403)
            if view.soft_delete_column and bool(token_state.get("trashed")) != is_trash_bulk:
                abort(403)
            raw_items = token_state.get("items", [])
            eff_items = [
                (str(pair[0]), str(pair[1]))
                for pair in raw_items
                if isinstance(pair, (list, tuple)) and len(pair) == 2
            ]
            scoped_pk_stmt, _ = deck._build_filtered_pk_statement(
                view, eff_items, user=user, trashed_override=is_trash_bulk if view.soft_delete_column else None
            )
            pk_cols = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
            pk_rows = sess.execute(
                scoped_pk_stmt.with_only_columns(*pk_cols).limit(deck.config.max_select_across + 1)
            ).all()
            if len(pk_rows) > deck.config.max_select_across:
                flash(
                    f"Selection exceeds maximum select-across limit ({deck.config.max_select_across:,}). Refine filters first.",
                    "danger",
                )
                return redirect(trash_return_url if is_trash_bulk else list_return_url)
            decoded_pks = [tuple(row) for row in pk_rows]
            raw_pks = [encode_pk(pk) for pk in decoded_pks]
            if not decoded_pks:
                flash("No matching authorized records found.", "warn")
                return redirect(trash_return_url if is_trash_bulk else list_return_url)
        else:
            raw_pks = [p for p in request.form.getlist("selected_pks") if p.strip()]
            if not raw_pks:
                flash("Select at least one record.", "warn")
                return redirect(list_return_url)
            decoded_pks = [decode_pk(p, view.meta) for p in raw_pks]

        if deck.config.demo_safe_mode:
            if action_name == "force_delete" or (
                action_name == "delete" and not view.soft_delete_column
            ):
                raise ReadOnlyError(
                    "Permanent bulk deletion is disabled in public Demo Safe Mode."
                )
            if select_across:
                raise ReadOnlyError(
                    "Select-across mass actions are disabled in public Demo Safe Mode."
                )

        def _load_pk_batch(session_obj: Any, pk_batch: list[tuple[Any, ...]]) -> list[Any]:
            q = view.scope_query(sa.select(view.model), user)
            if sd_pred is not None:
                q = q.where(sd_pred)
            if len(view.meta.primary_keys) == 1:
                pk_c = getattr(view.model, view.meta.primary_keys[0].name)
                q = q.where(pk_c.in_([p[0] for p in pk_batch]))
            else:
                pk_cs = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
                q = q.where(sa.tuple_(*pk_cs).in_(pk_batch))
            return list(session_obj.scalars(q).all())

        # Large select-across / bulk mutations automatically offload to chunked background jobs
        if (
            len(decoded_pks) > deck.config.bulk_sync_limit
            and deck.job_backend is not None
        ):
            target_total = len(decoded_pks)
            if action_name == "restore":
                if not view.soft_delete_column:
                    abort(404)
                if not view.can_edit:
                    abort(403)
                deck._require_perm(f"{slug}:edit", model_slug=slug)
                if view.meta.fields_by_name.get(view.soft_delete_column) is None:
                    abort(404)
                bulk_label = f"Bulk Restore ({target_total:,} {view.plural_label})"
                bulk_perm = f"{slug}:edit"
                bulk_spec = None
                form_snap: dict[str, str] = {}
            elif action_name == "force_delete":
                if not view.soft_delete_column:
                    abort(404)
                if not view.can_delete:
                    abort(403)
                deck._require_perm(f"{slug}:delete", model_slug=slug)
                deck._require_perm(f"{slug}:force_delete", model_slug=slug)
                if deck.approval_store is not None and view.requires_approval(
                    user, "delete", payload={"force": True, "count": target_total}
                ):
                    flash(
                        "Deletions on this model require four-eyes approval; delete records individually to submit for review.",
                        "warn",
                    )
                    return redirect(trash_return_url)
                if (
                    deck.config.environment == "production"
                    and deck.config.require_confirm_text_in_prod
                    and request.form.get("confirm_text", "").strip() != f"DELETE {target_total}"
                ):
                    flash(
                        f"Production safeguard: enter 'DELETE {target_total}' to confirm permanent deletion.",
                        "danger",
                    )
                    return redirect(trash_return_url)
                bulk_label = f"Bulk Force Delete ({target_total:,} {view.plural_label})"
                bulk_perm = f"{slug}:force_delete"
                bulk_spec = None
                form_snap = {}
            elif action_name == "delete":
                if not view.can_delete:
                    abort(403)
                deck._require_perm(f"{slug}:delete", model_slug=slug)
                if deck.approval_store is not None and view.requires_approval(
                    user, "delete", payload={"count": target_total}
                ):
                    flash(
                        "Deletions on this model require four-eyes approval; delete records individually to submit for review.",
                        "warn",
                    )
                    return redirect(list_return_url)
                if (
                    deck.config.environment == "production"
                    and deck.config.require_confirm_text_in_prod
                    and request.form.get("confirm_text", "").strip() != f"DELETE {target_total}"
                ):
                    flash(
                        f"Production safeguard: enter 'DELETE {target_total}' to confirm bulk delete.",
                        "danger",
                    )
                    return redirect(list_return_url)
                bulk_label = f"Bulk Delete ({target_total:,} {view.plural_label})"
                bulk_perm = f"{slug}:delete"
                bulk_spec = None
                form_snap = {}
            else:
                bulk_spec = view.actions.get(action_name)
                if bulk_spec is None:
                    abort(404)
                bulk_perm = bulk_spec.permission or f"{slug}:action:{action_name}"
                deck._require_perm(bulk_perm, model_slug=slug)
                if (
                    bulk_spec.require_confirm_text
                    and deck.config.environment == "production"
                    and deck.config.require_confirm_text_in_prod
                    and request.form.get("confirm_text", "").strip() != f"CONFIRM {target_total}"
                ):
                    flash(f"Production safeguard: enter 'CONFIRM {target_total}' to confirm.", "danger")
                    return redirect(list_return_url)
                form_snap = {}
                for af in bulk_spec.fields:
                    raw_v = request.form.get(af.name, "").strip()
                    if af.required and not raw_v:
                        flash(f"Action '{bulk_spec.label}' requires '{af.display_label}'.", "danger")
                        return redirect(list_return_url)
                    if raw_v and af.choices and raw_v not in {str(c[0]) for c in af.choices}:
                        flash(f"Invalid value for '{af.display_label}'.", "danger")
                        return redirect(list_return_url)
                    form_snap[af.name] = raw_v
                if deck.approval_store is not None and (
                    bulk_spec.require_approval
                    or view.requires_approval(
                        user,
                        "action",
                        payload={"action_name": action_name, "count": target_total, **form_snap},
                    )
                ):
                    flash(
                        "Large bulk actions requiring four-eyes approval must be submitted in smaller batches.",
                        "warn",
                    )
                    return redirect(list_return_url)
                bulk_label = f"{bulk_spec.label} ({target_total:,} {view.plural_label})"

            pk_chunks_all = [decoded_pks[i : i + 200] for i in range(0, len(decoded_pks), 200)]

            def _run_chunked_bulk(job_ctx: JobContext) -> str:
                job_sess = deck.get_session(view.bind_key)
                processed = 0
                orphan_queue: list[tuple[Any, str]] = []
                sd_col_name = view.soft_delete_column
                sd_f = view.meta.fields_by_name.get(sd_col_name) if sd_col_name else None
                for idx_c, chunk in enumerate(pk_chunks_all, start=1):
                    if job_ctx.is_cancelled():
                        return f"Cancelled after {processed} record(s)."
                    recs_c = _load_pk_batch(job_sess, chunk)
                    if action_name == "restore" and sd_col_name and sd_f is not None:
                        for r in recs_c:
                            if not deck.auth.has_permission(user, bulk_perm, model_slug=slug, obj=r):
                                raise PermissionDeniedError(f"Missing permission: {bulk_perm}")
                            setattr(r, sd_col_name, False if sd_f.field_type == "boolean" else None)
                            view.on_model_change(r, is_created=False, user=user)
                    elif action_name == "force_delete":
                        for r in recs_c:
                            if not (
                                deck.auth.has_permission(
                                    user, f"{slug}:delete", model_slug=slug, obj=r
                                )
                                and deck.auth.has_permission(
                                    user, f"{slug}:force_delete", model_slug=slug, obj=r
                                )
                            ):
                                raise PermissionDeniedError(f"Missing permission: {slug}:force_delete")
                            orphan_queue.extend(deck._collect_orphan_files(view, r))
                            view.on_model_delete(r, user=user)
                            job_sess.delete(r)
                    elif action_name == "delete":
                        for r in recs_c:
                            if not deck.auth.has_permission(
                                user, f"{slug}:delete", model_slug=slug, obj=r
                            ):
                                raise PermissionDeniedError(f"Missing permission: {slug}:delete")
                            if sd_col_name and sd_f is not None:
                                view.on_model_delete(r, user=user)
                                setattr(
                                    r,
                                    sd_col_name,
                                    True
                                    if sd_f.field_type == "boolean"
                                    else datetime.now(timezone.utc),
                                )
                            else:
                                orphan_queue.extend(deck._collect_orphan_files(view, r))
                                view.on_model_delete(r, user=user)
                                job_sess.delete(r)
                    elif bulk_spec is not None:
                        for r in recs_c:
                            if not deck.auth.has_permission(
                                user, bulk_perm, model_slug=slug, obj=r
                            ):
                                raise PermissionDeniedError(f"Missing permission: {bulk_perm}")
                        h_fn = getattr(view, bulk_spec.handler_name)
                        if bulk_spec.async_job:
                            h_fn(recs_c, form_snap, user, job_ctx)
                        else:
                            h_fn(recs_c, form_snap, user)
                    job_sess.commit()
                    processed += len(recs_c)
                    pct = int((idx_c / max(1, len(pk_chunks_all))) * 100)
                    job_ctx.set_progress(pct, f"Processed {processed:,}/{target_total:,} records")
                deck._delete_orphan_files_best_effort(orphan_queue)
                return f"Processed {processed:,} {view.plural_label}."

            def _on_chunk_done(rec: JobRecord) -> None:
                ev_name = (
                    "job.completed"
                    if rec.status == "succeeded"
                    else ("job.cancelled" if rec.status == "cancelled" else "job.failed")
                )
                deck._emit_event(
                    ev_name,
                    model_slug=slug,
                    record_pk=rec.id,
                    payload={"label": rec.label, "status": rec.status, "error": rec.error},
                    actor=user,
                )

            sess.close()
            job = deck.job_backend.submit(
                name=f"{slug}:{action_name}:bulk",
                label=bulk_label,
                actor_id=user.id if user else "system",
                actor_name=user.label if user else "System",
                model_slug=slug,
                fn=_run_chunked_bulk,
                app=deck.app,
                on_complete=_on_chunk_done,
            )
            deck._record_audit(
                action_name="async_job",
                view=view,
                record_pk=job.id,
                record_repr=job.label,
                metadata={
                    "action": action_name,
                    "count": target_total,
                    "job_id": job.id,
                    "select_across": select_across,
                },
            )
            flash(f"Large selection ({target_total:,} rows) offloaded to background job #{job.id}.", "ok")
            return redirect(url_for(f"{bp_name}.jobs_list", focus=job.id))

        records: list[Any] = []
        for i in range(0, len(decoded_pks), 200):
            records.extend(_load_pk_batch(sess, decoded_pks[i : i + 200]))

        if not records:
            flash("No matching authorized records found.", "warn")
            return redirect(trash_return_url if is_trash_bulk else list_return_url)

        if action_name == "restore":
            if not view.soft_delete_column:
                abort(404)
            if not view.can_edit:
                abort(403)
            deck._require_perm(f"{slug}:edit", model_slug=slug)
            for rec in records:
                deck._require_perm(f"{slug}:edit", model_slug=slug, obj=rec)
            sd_fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
            if sd_fmeta is None:
                abort(404)
            try:
                for rec in records:
                    setattr(
                        rec,
                        view.soft_delete_column,
                        False if sd_fmeta.field_type == "boolean" else None,
                    )
                    view.on_model_change(rec, is_created=False, user=user)
                sess.commit()
            except (ValidationError, SQLAlchemyError) as exc:
                sess.rollback()
                flash(f"Bulk restore failed: {exc}", "danger")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug, trashed="1"))
            deck._record_audit(
                action_name="bulk_action",
                view=view,
                record_pk=",".join(raw_pks[:10]),
                record_repr=f"Bulk restore ({len(records)} {view.plural_label})",
                metadata={"action": "restore", "count": len(records)},
            )
            deck._emit_event(
                "record.restored",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"count": len(records)},
            )
            deck._emit_event(
                "action.executed",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"action": "restore", "count": len(records), "async": False},
            )
            flash(f"Restored {len(records)} {view.plural_label} from Trash.", "ok")
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        if action_name == "force_delete":
            if not view.soft_delete_column:
                abort(404)
            if not view.can_delete:
                abort(403)
            deck._require_perm(f"{slug}:delete", model_slug=slug)
            deck._require_perm(f"{slug}:force_delete", model_slug=slug)
            for rec in records:
                deck._require_perm(f"{slug}:delete", model_slug=slug, obj=rec)
                deck._require_perm(f"{slug}:force_delete", model_slug=slug, obj=rec)
            if deck.approval_store is not None and any(
                view.requires_approval(user, "delete", obj=rec, payload={"force": True})
                for rec in records
            ):
                sess.rollback()
                flash(
                    "Deletions on this model require four-eyes approval; delete records individually to submit for review.",
                    "warn",
                )
                return redirect(url_for(f"{bp_name}.model_list", slug=slug, trashed="1"))
            if (
                deck.config.environment == "production"
                and deck.config.require_confirm_text_in_prod
            ):
                expected_phrase = f"DELETE {len(records)}"
                if request.form.get("confirm_text", "").strip() != expected_phrase:
                    flash(
                        f"Production safeguard: enter '{expected_phrase}' to confirm permanent deletion.",
                        "danger",
                    )
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug, trashed="1"))
            orphan_files: list[tuple[Any, str]] = []
            try:
                for rec in records:
                    orphan_files.extend(deck._collect_orphan_files(view, rec))
                    view.on_model_delete(rec, user=user)
                    sess.delete(rec)
                sess.commit()
            except IntegrityError:
                sess.rollback()
                flash("Bulk force delete failed due to foreign key references.", "danger")
                return redirect(trash_return_url)
            deck._delete_orphan_files_best_effort(orphan_files)
            deck._record_audit(
                action_name="bulk_action",
                view=view,
                record_pk=",".join(raw_pks[:10]),
                record_repr=f"Bulk force delete ({len(records)} {view.plural_label})",
                metadata={"action": "force_delete", "count": len(records)},
            )
            deck._emit_event(
                "record.deleted",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"soft": False, "count": len(records)},
            )
            deck._emit_event(
                "action.executed",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"action": "force_delete", "count": len(records), "async": False},
            )
            flash(f"Permanently deleted {len(records)} {view.plural_label}.", "ok")
            return redirect(trash_return_url)

        if action_name == "delete":
            if not view.can_delete:
                abort(403)
            deck._require_perm(f"{slug}:delete", model_slug=slug)
            for rec in records:
                deck._require_perm(f"{slug}:delete", model_slug=slug, obj=rec)
            if deck.approval_store is not None and any(
                view.requires_approval(user, "delete", obj=rec) for rec in records
            ):
                sess.rollback()
                flash(
                    "Deletions on this model require four-eyes approval; delete records individually to submit for review.",
                    "warn",
                )
                return redirect(list_return_url)
            if (
                deck.config.environment == "production"
                and deck.config.require_confirm_text_in_prod
            ):
                expected_phrase = f"DELETE {len(records)}"
                confirm_input = request.form.get("confirm_text", "").strip()
                if confirm_input != expected_phrase:
                    flash(
                        f"Production safeguard: enter '{expected_phrase}' to confirm bulk delete.",
                        "danger",
                    )
                    return redirect(list_return_url)
            orphan_files = []
            try:
                sd_col = view.soft_delete_column
                sd_fmeta = view.meta.fields_by_name.get(sd_col) if sd_col else None
                for rec in records:
                    if sd_col and sd_fmeta is not None:
                        view.on_model_delete(rec, user=user)
                        setattr(
                            rec,
                            sd_col,
                            True if sd_fmeta.field_type == "boolean" else datetime.now(timezone.utc),
                        )
                    else:
                        orphan_files.extend(deck._collect_orphan_files(view, rec))
                        view.on_model_delete(rec, user=user)
                        sess.delete(rec)
                sess.commit()
            except IntegrityError:
                sess.rollback()
                flash("Bulk delete failed due to foreign key references.", "danger")
                return redirect(list_return_url)

            deck._delete_orphan_files_best_effort(orphan_files)
            deck._record_audit(
                action_name="bulk_action",
                view=view,
                record_pk=",".join(raw_pks[:10]),
                record_repr=f"Bulk delete ({len(records)} {view.plural_label})",
                metadata={"action": "delete", "count": len(records)},
            )
            deck._emit_event(
                "record.deleted",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"soft": bool(view.soft_delete_column), "count": len(records)},
            )
            deck._emit_event(
                "action.executed",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"action": "delete", "count": len(records), "async": False},
            )
            flash(
                f"Moved {len(records)} {view.plural_label} to Trash."
                if view.soft_delete_column
                else f"Deleted {len(records)} {view.plural_label}.",
                "ok",
            )
            return redirect(list_return_url)

        spec = view.actions.get(action_name)
        if spec is None:
            abort(404)
        action_perm = spec.permission or f"{slug}:action:{action_name}"
        deck._require_perm(action_perm, model_slug=slug)
        for rec in records:
            deck._require_perm(action_perm, model_slug=slug, obj=rec)

        if (
            spec.require_confirm_text
            and deck.config.environment == "production"
            and deck.config.require_confirm_text_in_prod
        ):
            expected = f"CONFIRM {len(records)}"
            if request.form.get("confirm_text", "").strip() != expected:
                flash(f"Production safeguard: enter '{expected}' to confirm.", "danger")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        action_params: dict[str, Any] = {}
        form_snapshot: dict[str, str] = {}
        for af in spec.fields:
            raw_v = request.form.get(af.name, "").strip()
            if af.required and not raw_v:
                flash(f"Action '{spec.label}' requires '{af.display_label}'.", "danger")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))
            if raw_v and af.choices:
                valid_choices = {str(c[0]) for c in af.choices}
                if raw_v not in valid_choices:
                    flash(
                        f"Invalid value for '{af.display_label}' in action '{spec.label}'.",
                        "danger",
                    )
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))
            if raw_v and af.field_type == "number":
                try:
                    float(raw_v)
                except ValueError:
                    flash(f"'{af.display_label}' must be a valid number.", "danger")
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))
            form_snapshot[af.name] = raw_v
            action_params[af.name] = (
                "[REDACTED]"
                if is_sensitive_field(af.name, deck.config.extra_sensitive_patterns)
                else raw_v
            )

        handler = getattr(view, spec.handler_name)

        needs_action_approval = deck.approval_store is not None and (
            spec.require_approval
            or view.requires_approval(
                user,
                "action",
                payload={"action_name": action_name, "pks": raw_pks, **form_snapshot},
            )
        )
        if needs_action_approval and deck.approval_store is not None:
            sess.rollback()
            act_diff: dict[str, dict[str, Any]] = {
                "action": {"old": None, "new": f"{spec.label} ({len(records)} {view.plural_label})"}
            }
            for pk_k, pk_v in action_params.items():
                act_diff[f"param:{pk_k}"] = {"old": None, "new": pk_v}
            req = make_approval_request(
                model_slug=slug,
                model_label=view.label,
                operation="action",
                record_pk=",".join(raw_pks[:10]),
                record_repr=f"{spec.label} ({len(records)} {view.plural_label})",
                payload={
                    "action_name": action_name,
                    "pks": raw_pks,
                    "form_items": [[k, v] for k, v in request.form.items(multi=True)],
                    "params": action_params,
                    "_actor_roles": list(user.roles) if user else [],
                    "_actor_superuser": bool(user.is_superuser) if user else False,
                },
                diff=act_diff,
                reason=request.form.get("approval_reason", "").strip(),
                requester_id=user.id if user else "system",
                requester_name=user.label if user else "System",
                actor_type="human",
            )
            saved_req = deck.approval_store.create(req)
            deck._emit_event(
                "approval.requested",
                model_slug=slug,
                record_pk=",".join(raw_pks[:10]),
                payload={"approval_id": saved_req.id, "operation": "action", "action": action_name},
            )
            flash(
                f"Action '{spec.label}' queued for four-eyes approval (#{saved_req.id}).",
                "ok",
            )
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        if spec.async_job:
            if deck.job_backend is None:
                flash(
                    f"Action '{spec.label}' requires background jobs (enable_jobs=True).",
                    "danger",
                )
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))
            pk_list_copy = list(decoded_pks)

            def _run_async_action(job_ctx: JobContext) -> str | None:
                job_sess = deck.get_session(view.bind_key)
                q_stmt = view.scope_query(sa.select(view.model), user)
                sd_active = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
                if sd_active is not None:
                    q_stmt = q_stmt.where(sd_active)
                if len(view.meta.primary_keys) == 1:
                    col_pk = getattr(view.model, view.meta.primary_keys[0].name)
                    q_stmt = q_stmt.where(col_pk.in_([p[0] for p in pk_list_copy]))
                else:
                    cols_pk = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
                    q_stmt = q_stmt.where(sa.tuple_(*cols_pk).in_(pk_list_copy))
                fresh_recs = list(job_sess.scalars(q_stmt).all())
                job_ctx.log(f"Loaded {len(fresh_recs)} authorized {view.plural_label} record(s).")
                res_msg = handler(fresh_recs, form_snapshot, user, job_ctx)
                job_sess.commit()
                return str(res_msg or f"Processed {len(fresh_recs)} {view.plural_label}.")

            def _on_job_done(rec: JobRecord) -> None:
                ev_name = (
                    "job.completed"
                    if rec.status == "succeeded"
                    else ("job.cancelled" if rec.status == "cancelled" else "job.failed")
                )
                deck._emit_event(
                    ev_name,
                    model_slug=slug,
                    record_pk=rec.id,
                    payload={"label": rec.label, "status": rec.status, "error": rec.error},
                    actor=user,
                )

            sess.close()
            job = deck.job_backend.submit(
                name=f"{slug}:{action_name}",
                label=f"{spec.label} ({len(records)} {view.plural_label})",
                actor_id=user.id if user else "system",
                actor_name=user.label if user else "System",
                model_slug=slug,
                fn=_run_async_action,
                app=deck.app,
                on_complete=_on_job_done,
            )
            deck._record_audit(
                action_name="async_job",
                view=view,
                record_pk=job.id,
                record_repr=job.label,
                metadata={"action": action_name, "count": len(records), "job_id": job.id},
            )
            deck._emit_event(
                "action.executed",
                model_slug=slug,
                record_pk=job.id,
                payload={"action": action_name, "count": len(records), "async": True},
            )
            flash(f"Queued background job '{spec.label}' (#{job.id}).", "ok")
            return redirect(url_for(f"{bp_name}.jobs_list", focus=job.id))

        try:
            msg = handler(records, request.form, user)
            sess.commit()
        except (ValueError, ValidationError, SQLAlchemyError) as exc:
            sess.rollback()
            flash(f"Action '{spec.label}' failed: {exc}", "danger")
            return redirect(list_return_url)
        meta_payload: dict[str, Any] = {"action": action_name, "count": len(records)}
        if action_params:
            meta_payload["params"] = action_params
        deck._record_audit(
            action_name="bulk_action",
            view=view,
            record_pk=",".join(raw_pks[:10]),
            record_repr=f"{spec.label} ({len(records)} {view.plural_label})",
            metadata=meta_payload,
        )
        deck._emit_event(
            "action.executed",
            model_slug=slug,
            record_pk=",".join(raw_pks[:10]),
            payload={"action": action_name, "count": len(records), "async": False},
        )
        flash(str(msg or f"Executed '{spec.label}' on {len(records)} records."), "ok")
        return redirect(list_return_url)

    @bp.route("/<slug>/export.<fmt>")
    def model_export(slug: str, fmt: str) -> Response:
        if fmt.lower() not in {"csv", "json", "jsonl", "xlsx"}:
            abort(404)
        view = deck.get_view(slug)
        if not view.can_export:
            abort(403)
        deck._require_perm(f"{slug}:export", model_slug=slug)

        user = deck._current_user()
        allowed_searchable, _, _ = deck._allowed_query_fields(view, user)
        select_across = request.args.get("select_across") == "1"
        if select_across:
            slice_token = request.args.get("slice_token", "").strip()
            token_state = deck._verify_select_across_token(
                slice_token, expected_slug=slug, user=user
            )
            if token_state is None:
                abort(403)
            raw_items = token_state.get("items", [])
            eff_items = [
                (str(pair[0]), str(pair[1]))
                for pair in raw_items
                if isinstance(pair, (list, tuple)) and len(pair) == 2
            ]
            trashed = bool(view.soft_delete_column and token_state.get("trashed"))
            selected_pks: list[tuple[Any, ...]] = []
        else:
            eff_items = list(request.args.items(multi=True))
            trashed = bool(view.soft_delete_column and request.args.get("trashed") == "1")
            raw_ids = [p for p in request.args.get("ids", "").split(",") if p.strip()]
            selected_pks = [decode_pk(p, view.meta) for p in raw_ids]

        eff_single: dict[str, str] = {}
        filter_pairs: list[tuple[str, str]] = []
        for k, v in eff_items:
            eff_single.setdefault(k, v)
            if k.startswith("f_") and v.strip():
                filter_pairs.append((k[2:], v.strip()))

        search_term = eff_single.get("q", "").strip()
        active_tab = eff_single.get("tab", "").strip() or (
            view.quick_tabs[0].key if view.quick_tabs else None
        )
        _, appliers_by_param, _, dh_pred = deck._resolve_custom_filters_and_dh(
            view, eff_items, user
        )

        try:
            resp = stream_export_response(
                deck.get_session(view.bind_key),
                view,
                fmt=fmt,
                auth=deck.auth,
                user=user,
                search_term=search_term,
                filter_params=filter_pairs,
                active_tab_key=active_tab,
                selected_pks=selected_pks,
                sanitize_csv=deck.config.sanitize_csv,
                trashed=trashed,
                searchable_columns=allowed_searchable,
                views_by_model=deck._views_by_model,
                extra_where=[dh_pred] if dh_pred is not None else (),
                custom_filter_appliers=list(appliers_by_param.values()),
            )
        except ImportError as exc:
            return Response(str(exc), status=501, mimetype="text/plain; charset=utf-8")

        deck._record_audit(
            action_name="export",
            view=view,
            record_pk=f"format:{fmt.lower()}",
            record_repr=f"Exported {view.plural_label} ({fmt.upper()})",
            metadata={
                "format": fmt.lower(),
                "selected": len(selected_pks),
                "select_across": select_across,
                "trashed": trashed,
            },
        )
        return resp

    @bp.route("/<slug>/export-async", methods=["POST"])
    def model_export_async(slug: str) -> Any:
        if deck.job_backend is None:
            abort(404)
        view = deck.get_view(slug)
        if not view.can_export:
            abort(403)
        deck._require_perm(f"{slug}:export", model_slug=slug)
        fmt = request.form.get("fmt", "csv").strip().lower()
        if fmt not in {"csv", "json", "jsonl", "xlsx"}:
            abort(400)
        user = deck._current_user()
        allowed_searchable, _, _ = deck._allowed_query_fields(view, user)
        search_q = request.form.get("q", "").strip()
        active_tab = request.form.get("tab", "").strip() or None
        trashed = bool(view.soft_delete_column and request.form.get("trashed") == "1")
        form_items = list(request.form.items(multi=True))
        filter_pairs = [
            (k[2:], v.strip())
            for k, v in form_items
            if k.startswith("f_") and v.strip()
        ]
        _, appliers_by_param, _, dh_pred = deck._resolve_custom_filters_and_dh(
            view, form_items, user
        )
        extra_where_tuple = (dh_pred,) if dh_pred is not None else ()
        custom_appliers_list = list(appliers_by_param.values())

        def _run_export(job_ctx: JobContext) -> str:
            job_ctx.set_progress(15, f"Streaming {view.plural_label} as {fmt.upper()}…")
            chunks, mimetype, fname = iter_export_chunks(
                deck.get_session(view.bind_key),
                view,
                fmt=fmt,
                auth=deck.auth,
                user=user,
                search_term=search_q,
                filter_params=filter_pairs,
                active_tab_key=active_tab,
                sanitize_csv=deck.config.sanitize_csv,
                trashed=trashed,
                searchable_columns=allowed_searchable,
                views_by_model=deck._views_by_model,
                extra_where=extra_where_tuple,
                custom_filter_appliers=custom_appliers_list,
            )
            mime_base = mimetype.split(";", 1)[0].strip()
            key = build_storage_key(f"exports/{slug}", mime_base)
            total_bytes = 0
            with tempfile.SpooledTemporaryFile(max_size=2 * 1024 * 1024, mode="w+b") as spool:
                for chunk in chunks:
                    if job_ctx.is_cancelled():
                        return "Export cancelled"
                    encoded = chunk if isinstance(chunk, bytes) else chunk.encode("utf-8")
                    total_bytes += len(encoded)
                    spool.write(encoded)
                spool.seek(0)
                save_stream_to_storage(deck.job_storage, spool, key=key, content_type=mime_base)
            job_ctx.attach_artifact(key=key, filename=fname, content_type=mime_base)
            job_ctx.log(f"Exported {total_bytes:,} bytes to {fname}.")
            return f"Ready: {fname} ({total_bytes / 1024:.1f} KB)"

        def _on_export_done(rec: JobRecord) -> None:
            ev_name = (
                "job.completed"
                if rec.status == "succeeded"
                else ("job.cancelled" if rec.status == "cancelled" else "job.failed")
            )
            deck._emit_event(
                ev_name,
                model_slug=slug,
                record_pk=rec.id,
                payload={"label": rec.label, "status": rec.status, "error": rec.error},
                actor=user,
            )

        job = deck.job_backend.submit(
            name=f"{slug}:export:{fmt}",
            label=f"Export {view.plural_label} ({fmt.upper()})",
            actor_id=user.id if user else "system",
            actor_name=user.label if user else "System",
            model_slug=slug,
            fn=_run_export,
            app=deck.app,
            on_complete=_on_export_done,
        )
        deck._record_audit(
            action_name="async_job",
            view=view,
            record_pk=job.id,
            record_repr=job.label,
            metadata={"action": f"export_{fmt}", "job_id": job.id},
        )
        flash(f"Queued background export job #{job.id}.", "ok")
        return redirect(url_for(f"{bp_name}.jobs_list", focus=job.id))

    @bp.route("/<slug>/import", methods=["GET", "POST"])
    def model_import(slug: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_import:
            abort(403)
        deck._require_perm(f"{slug}:import", model_slug=slug)

        user = deck._current_user()
        user_id = user.id if user else "anonymous"
        sess_token = str(session.get(CSRF_SESSION_KEY, ""))

        hidden = deck.auth.hidden_fields_for(user, slug)
        masked = deck.auth.masked_fields_for(user, slug)
        readonly = deck.auth.readonly_fields_for(user, slug)
        upsert_candidates = [
            f.name
            for f in view.meta.fields
            if (f.unique or f.primary_key or f.name in view.import_key_columns)
            and f.name not in hidden
            and f.name not in masked
            and not f.is_sensitive
        ]

        report = None
        mapping_ctx: dict[str, Any] | None = None
        error_msg = ""
        bind_sess = deck.get_session(view.bind_key)

        if request.method == "POST":
            step = request.form.get("step", "preview").strip().lower()
            if step == "commit":
                if deck.config.demo_safe_mode:
                    raise ReadOnlyError(
                        "Committing imports is disabled in public Demo Safe Mode (Dry-Run SAVEPOINT preview remains available)."
                    )
                token = request.form.get("preview_token", "").strip()
                skip_errors = request.form.get("skip_errors") in {"1", "true", "on"}
                async_commit = request.form.get("async_commit") in {"1", "true", "on"}
                cached = deck._preview_store.consume(
                    token,
                    user_id=user_id,
                    session_token=sess_token,
                    model_slug=slug,
                )
                if cached is None:
                    error_msg = "Preview token expired, already used, or invalid. Please re-run dry-run preview."
                elif cached.errors > 0 and not skip_errors:
                    deck._preview_store.put(cached, user_id=user_id, session_token=sess_token)
                    report = cached
                    error_msg = (
                        f"Import contains {cached.errors} errored row(s). "
                        "Fix errors or enable 'Skip errored rows'."
                    )
                elif deck.job_backend is not None and (
                    async_commit or cached.applicable_count > deck.config.max_sync_import_rows
                ):
                    def _run_async_import(job_ctx: JobContext) -> str:
                        job_ctx.set_progress(15, f"Importing {cached.applicable_count} rows into {view.plural_label}…")
                        job_sess = deck.get_session(view.bind_key)
                        c_created, c_updated = commit_dry_run_import(
                            job_sess,
                            view,
                            cached,
                            user=user,
                            skip_errors=skip_errors,
                        )
                        job_ctx.set_progress(100, f"Committed +{c_created} / ~{c_updated}.")
                        deck._record_audit(
                            action_name="import",
                            view=view,
                            record_pk=job_ctx.job_id,
                            record_repr=f"Async import {cached.filename} (+{c_created} / ~{c_updated})",
                            metadata={
                                "filename": cached.filename,
                                "created": c_created,
                                "updated": c_updated,
                                "job_id": job_ctx.job_id,
                            },
                            actor=user,
                        )
                        deck._emit_event(
                            "import.committed",
                            model_slug=slug,
                            record_pk=f"batch:{c_created + c_updated}",
                            payload={
                                "filename": cached.filename,
                                "created": c_created,
                                "updated": c_updated,
                                "async": True,
                            },
                            actor=user,
                        )
                        return f"Imported {cached.filename}: {c_created} created, {c_updated} updated."

                    job = deck.job_backend.submit(
                        name=f"{slug}:import",
                        label=f"Import {view.plural_label} ({cached.filename})",
                        actor_id=user.id if user else "system",
                        actor_name=user.label if user else "System",
                        model_slug=slug,
                        fn=_run_async_import,
                        app=deck.app,
                    )
                    flash(f"Queued background import job #{job.id}.", "ok")
                    return redirect(url_for(f"{bp_name}.jobs_list", focus=job.id))
                else:
                    try:
                        import_row_audits: list[
                            tuple[str, str, str, dict[str, dict[str, Any]]]
                        ] = []

                        def _collect_import_audit(
                            op: str,
                            pk_s: str,
                            repr_s: str,
                            row_diff: dict[str, dict[str, Any]],
                        ) -> None:
                            import_row_audits.append((op, pk_s, repr_s, row_diff))

                        created, updated = commit_dry_run_import(
                            bind_sess,
                            view,
                            cached,
                            user=user,
                            skip_errors=skip_errors,
                            row_audit_cb=_collect_import_audit,
                        )
                        for row_op, row_pk, row_repr, row_diff in import_row_audits:
                            deck._record_audit(
                                action_name=row_op,
                                view=view,
                                record_pk=row_pk,
                                record_repr=row_repr,
                                changes=row_diff,
                                metadata={"source": "import", "filename": cached.filename},
                            )
                        deck._record_audit(
                            action_name="import",
                            view=view,
                            record_pk=f"batch:{created + updated}",
                            record_repr=f"Imported {cached.filename} (+{created} / ~{updated})",
                            metadata={
                                "filename": cached.filename,
                                "format": cached.format,
                                "created": created,
                                "updated": updated,
                                "skipped_errors": cached.errors if skip_errors else 0,
                            },
                        )
                        deck._emit_event(
                            "import.committed",
                            model_slug=slug,
                            record_pk=f"batch:{created + updated}",
                            payload={
                                "filename": cached.filename,
                                "created": created,
                                "updated": updated,
                            },
                        )
                        flash(
                            f"Import committed: {created} created, {updated} updated.",
                            "ok",
                        )
                        return redirect(url_for(f"{bp_name}.model_list", slug=slug))
                    except (ImportLimitError, SQLAlchemyError) as exc:
                        bind_sess.rollback()
                        error_msg = str(exc)
            elif step == "map":
                upload = request.files.get("file")
                raw_upsert = request.form.get("upsert_key", "").strip() or None
                upsert_key = raw_upsert if (raw_upsert and raw_upsert in upsert_candidates) else None
                if upload is None or not upload.filename:
                    error_msg = "Select a CSV, JSON, or XLSX file first."
                else:
                    try:
                        raw_bytes = upload.stream.read(deck.config.max_upload_bytes + 1)
                    finally:
                        upload.stream.close()
                    try:
                        _fmt, headers, parsed_rows = parse_import_payload(
                            raw_bytes,
                            filename=upload.filename,
                            max_bytes=deck.config.max_upload_bytes,
                            max_rows=deck.config.max_import_rows,
                            max_columns=deck.config.max_import_columns,
                            max_json_depth=deck.config.max_json_depth,
                        )
                        writable = [
                            c
                            for c in view.resolved_import_columns
                            if c not in hidden
                            and c not in readonly
                            and c not in masked
                            and c not in view.meta.sensitive_fields
                        ]
                        if upsert_key and upsert_key not in writable:
                            writable.append(upsert_key)
                        auto_map = auto_map_headers(headers, writable)
                        stage_token = secrets.token_urlsafe(24)
                        now_ts = time.monotonic()
                        with deck._api_rate_lock:
                            expired = [
                                k
                                for k, v in deck._staged_imports.items()
                                if (now_ts - v[0]) > deck.config.import_preview_ttl_seconds
                            ]
                            for k in expired:
                                deck._staged_imports.pop(k, None)
                            while len(deck._staged_imports) >= 32:
                                oldest = next(iter(deck._staged_imports))
                                deck._staged_imports.pop(oldest, None)
                            deck._staged_imports[stage_token] = (
                                now_ts,
                                user_id,
                                sess_token,
                                slug,
                                upload.filename,
                                raw_bytes,
                            )
                        mapping_ctx = {
                            "stage_token": stage_token,
                            "filename": upload.filename,
                            "headers": headers,
                            "sample_rows": parsed_rows[:3],
                            "auto_map": auto_map,
                            "writable_fields": writable,
                            "upsert_key": upsert_key or "",
                        }
                    except ImportLimitError as exc:
                        error_msg = str(exc)
            else:
                stage_token = request.form.get("stage_token", "").strip()
                raw_upsert = request.form.get("upsert_key", "").strip() or None
                upsert_key = raw_upsert if (raw_upsert and raw_upsert in upsert_candidates) else None
                raw_bytes = b""
                filename = ""
                column_overrides: dict[str, str] = {}
                if stage_token:
                    with deck._api_rate_lock:
                        staged = deck._staged_imports.pop(stage_token, None)
                    if staged is None:
                        error_msg = "Column mapping session expired. Please re-upload your file."
                    else:
                        s_ts, s_uid, s_tok, s_slug, s_fname, s_bytes = staged
                        if (
                            (time.monotonic() - s_ts) > deck.config.import_preview_ttl_seconds
                            or s_uid != user_id
                            or s_tok != sess_token
                            or s_slug != slug
                        ):
                            error_msg = "Column mapping session invalid or expired."
                        else:
                            filename = s_fname
                            raw_bytes = s_bytes
                            idx = 0
                            while f"src_header_{idx}" in request.form:
                                src_h = request.form.get(f"src_header_{idx}", "")
                                dst_f = request.form.get(f"dst_field_{idx}", "").strip()
                                if src_h and dst_f:
                                    column_overrides[src_h] = dst_f
                                idx += 1
                else:
                    upload = request.files.get("file")
                    if upload is None or not upload.filename:
                        error_msg = "Select a CSV, JSON, or XLSX file to preview."
                    else:
                        filename = upload.filename
                        try:
                            raw_bytes = upload.stream.read(deck.config.max_upload_bytes + 1)
                        finally:
                            upload.stream.close()

                if not error_msg and filename:
                    try:
                        report = run_dry_run_import(
                            bind_sess,
                            view,
                            raw_bytes=raw_bytes,
                            filename=filename,
                            auth=deck.auth,
                            user=user,
                            upsert_key=upsert_key,
                            column_overrides=column_overrides or None,
                            max_bytes=deck.config.max_upload_bytes,
                            max_rows=deck.config.max_import_rows,
                            max_columns=deck.config.max_import_columns,
                            max_json_depth=deck.config.max_json_depth,
                        )
                        bind_sess.rollback()
                        deck._preview_store.put(
                            report,
                            user_id=user_id,
                            session_token=sess_token,
                        )
                    except ImportLimitError as exc:
                        error_msg = str(exc)

        return render_template(
            "flask_deck/import_wizard.html",
            **deck._base_context(
                page_title=f"Import {view.plural_label}",
                active_nav=slug,
                view=view,
                report=report,
                mapping_ctx=mapping_ctx,
                error_msg=error_msg,
                upsert_candidates=upsert_candidates,
            ),
        )

    @bp.route("/<slug>/import/errors/<token>.csv")
    def model_import_errors(slug: str, token: str) -> Response:
        view = deck.get_view(slug)
        if not view.can_import:
            abort(403)
        deck._require_perm(f"{slug}:import", model_slug=slug)
        user = deck._current_user()
        user_id = user.id if user else "anonymous"
        sess_token = str(session.get(CSRF_SESSION_KEY, ""))
        cached = deck._preview_store.peek(
            token,
            user_id=user_id,
            session_token=sess_token,
            model_slug=slug,
        )
        if cached is None or cached.errors == 0:
            abort(404)
        csv_data = format_failed_rows_csv(cached, sanitize_csv=deck.config.sanitize_csv)
        resp = Response(csv_data, mimetype="text/csv; charset=utf-8")
        resp.headers["Content-Disposition"] = f'attachment; filename="{slug}-import-errors.csv"'
        return resp
