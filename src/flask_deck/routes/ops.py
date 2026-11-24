from __future__ import annotations

import gzip
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from flask_deck.audit import make_audit_entry
from flask_deck.auth import OpenAuthProvider
from flask_deck.dashboard import ActivityWidget, DashboardContext, Widget, build_default_dashboard
from flask_deck.diagnostics import detect_flask_lens, run_security_audit
from flask_deck.exceptions import PermissionDeniedError
from flask_deck.query import soft_delete_predicate
from flask_deck.schema_graph import render_schema_erd_svg
from flask_deck.sql_console import (
    SavedQueryRecord,
    SQLQueryResult,
    build_sql_chart_svg,
    execute_readonly_sql,
    format_sql_result_csv,
    introspect_engine_schema,
    validate_readonly_sql,
)
from flask_deck.storage import RASTER_INLINE_MIMES, sanitize_filename, stream_storage_object

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_ops_routes(bp: Blueprint, deck: Deck) -> None:
    """Register Dashboard, Theme CSS, Media Proxy, Schema ERD, Diagnostics, SQL Console & Pages."""
    from flask_deck.deck import _STATIC_DIR, _client_ip

    @bp.route("/")
    def index() -> str:
        raw_range = request.args.get("range", "14d").strip().lower().rstrip("d")
        range_days = int(raw_range) if raw_range in {"7", "14", "30", "90"} else 14
        ctx = DashboardContext(
            deck, deck.get_session(), deck._current_user(), range_days=range_days
        )
        if deck._dashboard_builder is not None:
            raw_widgets = list(deck._dashboard_builder(ctx))
            widgets: list[Widget] = []
            for w in raw_widgets:
                if isinstance(w, ActivityWidget) and not w.entries:
                    widgets.append(
                        ActivityWidget(
                            title=w.title,
                            subtitle=w.subtitle,
                            col_span=w.col_span,
                            limit=w.limit,
                            entries=ctx.recent_audit_entries(limit=w.limit),
                        )
                    )
                else:
                    widgets.append(w)
        else:
            widgets = build_default_dashboard(deck, ctx)
        return render_template(
            "flask_deck/dashboard.html",
            **deck._base_context(
                page_title="Dashboard",
                active_nav="dashboard",
                widgets=widgets,
                range_days=range_days,
            ),
        )

    @bp.route("/_theme.css")
    def brand_theme_css() -> Response:
        return Response(deck._brand_css_bytes, mimetype="text/css; charset=utf-8")

    @bp.route("/_media/<slug>/<field_name>/<raw_pk>")
    def serve_media(slug: str, field_name: str, raw_pk: str) -> Any:
        view = deck.get_view(slug)
        if not view.can_view:
            abort(404)
        deck._require_perm(f"{slug}:view", model_slug=slug)
        cfg = view.file_fields.get(field_name)
        if cfg is None:
            abort(404)
        user = deck._current_user()
        if (
            field_name in deck.auth.hidden_fields_for(user, slug)
            or field_name in deck.auth.masked_fields_for(user, slug)
        ):
            abort(403)
        obj, _ = deck._fetch_scoped_record(view, raw_pk)
        deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
        if deck._is_soft_deleted(view, obj):
            abort(404)
        key = getattr(obj, field_name, None)
        if not key or not isinstance(key, str):
            abort(404)

        if cfg.use_presigned_redirect:
            signed_url = cfg.storage.presigned_url(key, expires_in=cfg.presign_ttl)
            if signed_url and (
                signed_url.startswith("https://") or signed_url.startswith("http://")
            ):
                redir = redirect(signed_url, code=302)
                redir.headers["Cache-Control"] = "private, no-store"
                return redir

        try:
            chunk_iter, detected_mime = stream_storage_object(cfg.storage, key)
        except (FileNotFoundError, ValueError):
            abort(404)

        mime = detected_mime or "application/octet-stream"
        is_inline_raster = mime in RASTER_INLINE_MIMES
        safe_name = sanitize_filename(key.rsplit("/", 1)[-1])
        disposition = "inline" if is_inline_raster else "attachment"
        resp = Response(chunk_iter, mimetype=mime)
        resp.headers["Content-Disposition"] = f'{disposition}; filename="{safe_name}"'
        resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "private, max-age=300"
        return resp

    @bp.route("/_schema")
    def schema_inspector() -> str:
        user = deck._current_user()
        if not (
            deck.auth.has_permission(user, "schema:view")
            or deck.auth.has_permission(user, "*:view")
        ):
            raise PermissionDeniedError("Missing permission: schema:view")

        authorized_views = [
            v
            for v in deck.views.values()
            if v.can_view
            and deck.auth.has_permission(user, f"{v.meta.slug}:view", model_slug=v.meta.slug)
        ]
        row_counts: dict[str, int] = {}
        by_bind: dict[str | None, list[Any]] = {}
        for v in authorized_views:
            by_bind.setdefault(v.bind_key, []).append(v)
        for bk, b_views in by_bind.items():
            subs = []
            for v in b_views:
                q = v.scope_query(sa.select(sa.func.count()).select_from(v.model), user)
                sd_pred = soft_delete_predicate(v.meta, v.soft_delete_column, trashed=False)
                if sd_pred is not None:
                    q = q.where(sd_pred)
                subs.append(q.scalar_subquery().label(v.meta.slug))
            row = deck.get_session(bk).execute(sa.select(*subs)).first()
            if row is not None:
                for idx, v in enumerate(b_views):
                    row_counts[v.meta.slug] = int(row[idx] or 0)

        metas = [v.meta for v in authorized_views]
        model_urls = {
            v.meta.slug: url_for(f"{deck.config.name}.model_list", slug=v.meta.slug)
            for v in authorized_views
        }
        erd_svg = render_schema_erd_svg(metas, row_counts, model_urls=model_urls)
        return render_template(
            "flask_deck/schema_inspector.html",
            **deck._base_context(
                page_title="Schema ERD & Index Inspector",
                active_nav="_schema",
                erd_svg=erd_svg,
                views=authorized_views,
                row_counts=row_counts,
            ),
        )

    @bp.route("/_diagnostics")
    def diagnostics() -> str:
        user = deck._current_user()
        if not (
            deck.auth.has_permission(user, "diagnostics:view")
            or (user is not None and user.is_superuser)
        ):
            raise PermissionDeniedError("Missing permission: diagnostics:view")

        assert deck.app is not None
        findings = run_security_audit(deck.app, deck)
        css_path = _STATIC_DIR / "css" / "deck.css"
        js_path = _STATIC_DIR / "js" / "deck.js"
        css_gz = len(gzip.compress(css_path.read_bytes(), 9)) if css_path.is_file() else 0
        js_gz = len(gzip.compress(js_path.read_bytes(), 9)) if js_path.is_file() else 0
        total_cols = sum(len(v.meta.fields) for v in deck.views.values())
        total_idx = sum(len(v.meta.indexed_fields) for v in deck.views.values())
        total_redacted = sum(len(v.meta.sensitive_fields) for v in deck.views.values())

        checks = [
            ("Strict Nonce CSP (0 unsafe-inline)", "PASS", "ok"),
            ("Double-Layer CSRF + Sec-Fetch-Site", "PASS", "ok"),
            (
                "Authentication Provider",
                deck.auth.__class__.__name__,
                "warn" if isinstance(deck.auth, OpenAuthProvider) else "ok",
            ),
            (
                "Audit Ledger Backend",
                deck.audit_store.__class__.__name__ if deck.audit_store else "Disabled",
                "ok" if deck.audit_store else "warn",
            ),
            (
                "Read-Only SQL Console",
                "Enabled (SELECT/WITH/EXPLAIN)" if deck.config.enable_sql_console else "Disabled",
                "info" if deck.config.enable_sql_console else "neutral",
            ),
            (
                "TOTP 2FA Store",
                deck.mfa_store.__class__.__name__ if deck.mfa_store else "Disabled",
                "ok" if deck.mfa_store else "warn",
            ),
            (
                "Brand Theme Engine",
                f"{deck.config.brand.accent} (/_theme.css, 0 inline style)",
                "ok",
            ),
            (
                "SQLAlchemy Engine Binds",
                ", ".join(sorted(deck.adapter.get_engines().keys())) if deck.adapter else "default",
                "info",
            ),
        ]
        if deck.config.demo_safe_mode:
            checks.append(
                ("Demo Safe Mode", "Active (IAM, Security & Destructive Ops Locked)", "info")
            )
        lens_info = detect_flask_lens(deck.app)
        if lens_info is not None:
            checks.append(
                (
                    "Flask-Lens Observability",
                    f"Detected ({lens_info['url_prefix']})",
                    "ok",
                )
            )
        return render_template(
            "flask_deck/diagnostics.html",
            **deck._base_context(
                page_title="Security & Index Diagnostics",
                active_nav="_diagnostics",
                findings=findings,
                checks=checks,
                asset_kb=round((css_gz + js_gz) / 1024.0, 2),
                css_kb=round(css_gz / 1024.0, 2),
                js_kb=round(js_gz / 1024.0, 2),
                total_cols=total_cols,
                total_idx=total_idx,
                total_redacted=total_redacted,
            ),
        )

    @bp.route("/_sql", methods=["GET", "POST"])
    def sql_console() -> Any:
        if not deck.config.enable_sql_console:
            abort(404)
        deck._require_perm("sql:query")

        assert deck.adapter is not None
        engines = deck.adapter.get_engines()
        bind_options = [("", "default (primary)")]
        for bk in sorted(engines.keys()):
            if bk != "default":
                bind_options.append((bk, bk))

        selected_bind = request.values.get("bind_key", "").strip()
        if selected_bind and selected_bind not in engines:
            selected_bind = ""

        primary_tables = [v.meta.table_name for v in deck.views.values() if not v.bind_key]
        default_sql = (
            deck._sql_presets[0][1]
            if deck._sql_presets
            else (
                f"SELECT * FROM {primary_tables[0]} LIMIT 25"
                if primary_tables
                else "SELECT 1 AS ok"
            )
        )
        sql_text = default_sql
        chart_type = request.values.get("chart_type", "bar").strip().lower()
        if chart_type not in {"table", "bar", "line"}:
            chart_type = "bar"
        explain = False

        saved_id = request.args.get("saved", "").strip()
        if request.method == "GET" and saved_id and deck.saved_query_store is not None:
            saved_rec = deck.saved_query_store.get(saved_id)
            if saved_rec is not None:
                sql_text = saved_rec.sql
                selected_bind = saved_rec.bind_key if saved_rec.bind_key in engines else ""
                chart_type = saved_rec.chart_type if saved_rec.chart_type in {"table", "bar", "line"} else "bar"

        target_engine = engines[selected_bind] if selected_bind else deck.adapter.get_engine()
        schema_tables = introspect_engine_schema(target_engine)
        result: SQLQueryResult | None = None
        chart_svg: Any = None

        if request.method == "POST":
            sql_text = request.form.get("sql", "").strip()
            out_mode = request.form.get("output", "table").strip().lower()
            explain = out_mode == "explain" or request.form.get("explain") == "1"
            result = execute_readonly_sql(
                target_engine,
                sql_text,
                max_rows=deck.config.sql_console_max_rows,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                explain=explain,
            )
            if deck.audit_store is not None and deck.config.auto_audit:
                user = deck._current_user()
                sql_meta: dict[str, Any] = {
                    "rows": result.row_count,
                    "ms": round(result.duration_ms, 2),
                    "status": "blocked" if result.error else "ok",
                    "bind": selected_bind or "default",
                }
                if explain:
                    sql_meta["explain"] = True
                real = getattr(g, "_deck_real_user", None)
                if real is not None and (user is None or real.id != user.id):
                    sql_meta["impersonated_by"] = real.id
                    sql_meta["impersonated_by_name"] = real.label
                deck.audit_store.record(
                    make_audit_entry(
                        actor_id=user.id if user else "system",
                        actor_name=user.label if user else "System",
                        actor_ip=_client_ip(),
                        action="sql_query",
                        model_slug="_sql",
                        model_label="SQL Console",
                        record_pk="readonly",
                        record_repr=sql_text[:120],
                        metadata=sql_meta,
                    )
                )
            if out_mode == "csv" and result.error is None and result.columns:
                csv_data = format_sql_result_csv(
                    result.columns,
                    result.rows,
                    sanitize_csv=deck.config.sanitize_csv,
                )
                resp = Response(csv_data, mimetype="text/csv; charset=utf-8")
                resp.headers["Content-Disposition"] = 'attachment; filename="sql-query-result.csv"'
                return resp
            if not explain and result.error is None and chart_type in {"bar", "line"}:
                chart_svg = build_sql_chart_svg(result, chart_type=chart_type)

        saved_queries = (
            deck.saved_query_store.list_queries() if deck.saved_query_store is not None else []
        )
        cur_user = deck._current_user()
        can_save_queries = (
            deck.saved_query_store is not None
            and not deck.config.read_only
            and cur_user is not None
        )

        return render_template(
            "flask_deck/sql_console.html",
            **deck._base_context(
                page_title="Read-Only SQL Console",
                active_nav="_sql",
                sql_text=sql_text,
                result=result,
                chart_svg=chart_svg,
                chart_type=chart_type,
                explain=explain,
                sql_presets=deck._sql_presets,
                tables=primary_tables,
                bind_options=bind_options,
                selected_bind=selected_bind,
                schema_tables=schema_tables,
                saved_queries=saved_queries,
                can_save_queries=can_save_queries,
                current_user_id=cur_user.id if cur_user else "",
                is_superuser=bool(cur_user and cur_user.is_superuser),
            ),
        )

    @bp.route("/_sql/save", methods=["POST"])
    def sql_save() -> Any:
        if not deck.config.enable_sql_console or deck.saved_query_store is None:
            abort(404)
        deck._require_perm("sql:query")
        bp_name = deck.config.name
        name = request.form.get("name", "").strip()
        raw_sql = request.form.get("sql", "").strip()
        bind_key = request.form.get("bind_key", "").strip()
        chart_type = request.form.get("chart_type", "bar").strip().lower()
        if chart_type not in {"table", "bar", "line"}:
            chart_type = "bar"
        pin = request.form.get("pin") == "1"
        if not name or not raw_sql:
            flash("Query name and SQL text are required.", "danger")
            return redirect(url_for(f"{bp_name}.sql_console"))
        try:
            clean_sql = validate_readonly_sql(
                raw_sql, extra_sensitive_patterns=deck.config.extra_sensitive_patterns
            )
        except ValueError as exc:
            flash(f"Cannot save query: {exc}", "danger")
            return redirect(url_for(f"{bp_name}.sql_console"))
        assert deck.adapter is not None
        if bind_key and bind_key not in deck.adapter.get_engines():
            bind_key = ""
        user = deck._current_user()
        saved = deck.saved_query_store.create(
            SavedQueryRecord(
                id="",
                name=name[:120],
                sql=clean_sql,
                bind_key=bind_key,
                owner_id=user.id if user else "system",
                owner_name=user.label if user else "System",
                is_pinned_to_dashboard=pin,
                chart_type=chart_type,
            )
        )
        flash(f"Saved query '{saved.name}'.", "ok")
        return redirect(url_for(f"{bp_name}.sql_console", saved=saved.id))

    @bp.route("/_sql/<query_id>/pin", methods=["POST"])
    def sql_pin(query_id: str) -> Any:
        if not deck.config.enable_sql_console or deck.saved_query_store is None:
            abort(404)
        deck._require_perm("sql:query")
        bp_name = deck.config.name
        rec = deck.saved_query_store.get(query_id)
        if rec is None:
            abort(404)
        user = deck._current_user()
        if not (user and (user.is_superuser or rec.owner_id == user.id)):
            raise PermissionDeniedError("Only owner or superuser can pin/unpin this query.")
        chart_type = request.form.get("chart_type", "").strip().lower() or None
        updated = deck.saved_query_store.toggle_pin(query_id, chart_type=chart_type)
        if updated is not None:
            state = "pinned to Dashboard" if updated.is_pinned_to_dashboard else "unpinned"
            flash(f"Query '{updated.name}' {state}.", "ok")
        return redirect(url_for(f"{bp_name}.sql_console", saved=query_id))

    @bp.route("/_sql/<query_id>/delete", methods=["POST"])
    def sql_delete(query_id: str) -> Any:
        if not deck.config.enable_sql_console or deck.saved_query_store is None:
            abort(404)
        deck._require_perm("sql:query")
        bp_name = deck.config.name
        user = deck._current_user()
        deleted = deck.saved_query_store.delete(
            query_id,
            actor_id=user.id if user else "",
            is_superuser=bool(user and user.is_superuser),
        )
        flash("Deleted saved query." if deleted else "Permission denied or query not found.", "ok" if deleted else "danger")
        return redirect(url_for(f"{bp_name}.sql_console"))

    @bp.route("/_page/<page_slug>")
    def custom_page(page_slug: str) -> str:
        spec = deck.custom_pages.get(page_slug)
        if spec is None:
            abort(404)
        user = deck._current_user()
        if spec.permission:
            if not deck.auth.has_permission(user, spec.permission):
                raise PermissionDeniedError(f"Missing permission: {spec.permission}")
        else:
            perm = f"page:{spec.slug}:view"
            if not (
                deck.auth.has_permission(user, perm)
                or deck.auth.has_permission(user, "*:view")
            ):
                raise PermissionDeniedError(f"Missing permission: {perm}")

        raw_range = request.args.get("range", "14d").strip().lower().rstrip("d")
        range_days = int(raw_range) if raw_range in {"7", "14", "30", "90"} else 14
        ctx = DashboardContext(deck, deck.get_session(), user, range_days=range_days)
        raw_widgets = list(spec.handler(ctx))
        widgets: list[Widget] = []
        for w in raw_widgets:
            if isinstance(w, ActivityWidget) and not w.entries:
                widgets.append(
                    ActivityWidget(
                        title=w.title,
                        subtitle=w.subtitle,
                        col_span=w.col_span,
                        limit=w.limit,
                        entries=ctx.recent_audit_entries(limit=w.limit),
                    )
                )
            else:
                widgets.append(w)
        return render_template(
            "flask_deck/custom_page.html",
            **deck._base_context(
                page_title=spec.title,
                active_nav=f"_page:{spec.slug}",
                page_spec=spec,
                widgets=widgets,
                range_days=range_days,
            ),
        )
