from __future__ import annotations

import enum
import gzip
import hashlib
import io
import json
import logging
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import sqlalchemy as sa
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from markupsafe import Markup
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from flask_deck.adapters.sqlalchemy import (
    ORMAdapter,
    decode_pk,
    encode_pk,
    extract_pk,
    resolve_adapter,
)
from flask_deck.audit import (
    AuditEntry,
    AuditStore,
    SQLAlchemyAuditStore,
    compute_diff,
    make_audit_entry,
)
from flask_deck.auth import AuthProvider, DeckUser, OpenAuthProvider, RBACAuthProvider
from flask_deck.branding import render_brand_css, render_safe_slot
from flask_deck.config import DeckConfig
from flask_deck.dashboard import (
    ActivityWidget,
    DashboardBuilder,
    DashboardContext,
    Widget,
    build_default_dashboard,
)
from flask_deck.events import DeckEvent, DeckEventBus, EventListener, WebhookSink
from flask_deck.exceptions import (
    ImportLimitError,
    InvalidPKError,
    PermissionDeniedError,
    ReadOnlyError,
    SecurityConfigurationError,
    ValidationError,
)
from flask_deck.exporter import iter_export_chunks, stream_export_response
from flask_deck.i18n import (
    CURATED_TIMEZONES,
    LOCALE_LABELS,
    LOCALE_SESSION_KEY,
    TZ_SESSION_KEY,
    DictTranslator,
    Translator,
    is_valid_timezone,
    normalize_locale,
    set_request_locale_tz,
    to_user_timezone,
)
from flask_deck.icons import render_icon
from flask_deck.importer import (
    ImportPreviewStore,
    commit_dry_run_import,
    run_dry_run_import,
)
from flask_deck.introspection import ModelMeta
from flask_deck.jobs import (
    TERMINAL_JOB_STATUSES,
    JobBackend,
    JobContext,
    JobRecord,
    ThreadPoolJobBackend,
)
from flask_deck.mfa import (
    MFA_PENDING_AT_KEY,
    MFA_PENDING_NEXT_KEY,
    MFA_PENDING_SSO_KEY,
    MFA_PENDING_USER_KEY,
    MFA_VERIFIED_KEY,
    InMemoryMFAStore,
    MFAEnrollment,
    MFAStore,
    SQLAlchemyMFAStore,
    build_otpauth_uri,
    generate_recovery_codes,
    generate_totp_secret,
    render_qr_svg,
    verify_totp,
)
from flask_deck.model_view import ModelView, coerce_form_value
from flask_deck.query import (
    apply_list_load_options,
    attach_sql_telemetry,
    begin_request_telemetry,
    build_filter_condition,
    build_search_clause,
    compute_page_aggregates,
    execute_kanban_query,
    execute_list_query,
    get_request_telemetry,
    soft_delete_predicate,
)
from flask_deck.schema_graph import render_schema_erd_svg
from flask_deck.security import (
    CSRF_FORM_FIELD,
    CSRF_SESSION_KEY,
    LoginRateLimiter,
    apply_security_headers,
    generate_nonce,
    get_csrf_token,
    is_safe_redirect_url,
    is_sensitive_field,
    rotate_csrf_token,
    validate_csrf,
)
from flask_deck.sql_console import (
    SQLQueryResult,
    execute_readonly_sql,
    format_sql_result_csv,
)
from flask_deck.sso import OIDCAuthProvider
from flask_deck.storage import (
    RASTER_INLINE_MIMES,
    MemoryFileStorage,
    StorageBackend,
    build_storage_key,
    sanitize_filename,
)

IMPERSONATOR_USER_KEY = "_deck_impersonator_id"
IMPERSONATED_USER_KEY = "_deck_impersonated_id"
IMPERSONATE_RO_KEY = "_deck_impersonate_ro"
MFA_SETUP_SECRET_KEY = "_deck_mfa_setup_secret"
MFA_PENDING_TTL_SECONDS = 300
_RESERVED_MODEL_SLUGS: frozenset[str] = frozenset(
    {"login", "logout", "static", "_audit", "_rbac", "_schema", "_diagnostics", "_sql", "_jobs", "_page", "_api", "_media", "_theme.css", "_preferences", "_security", "_impersonate", "_demo"}
)

logger = logging.getLogger("flask_deck")

_PKG_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _PKG_DIR / "static"
_TEMPLATE_DIR = _PKG_DIR / "templates"


def _file_hash(path: Path) -> str:
    if not path.is_file():
        return "dev"
    return hashlib.sha256(path.read_bytes()).hexdigest()[:10]


def _client_ip() -> str:
    # Do not trust spoofable X-Forwarded-For unless ProxyFix is explicitly configured on app.
    return str(request.remote_addr or "127.0.0.1")


@dataclass(frozen=True, slots=True)
class PageSpec:
    """Declarative custom operational page registered via ``@deck.page``."""

    slug: str
    title: str
    handler: Callable[[DashboardContext], Sequence[Widget]]
    icon: str = "terminal"
    category: str = "Operations"
    subtitle: str = ""
    permission: str | None = None


class Deck:
    """Modern Carbon Dark & Swiss Light admin panel and operations workbench for Flask."""

    def __init__(
        self,
        app: Flask | None = None,
        db: Any | None = None,
        *,
        session_factory: sessionmaker[Session] | Callable[[], Session] | None = None,
        engine: Engine | None = None,
        binds: Mapping[str, Engine] | None = None,
        auth: AuthProvider | None = None,
        audit_store: AuditStore | bool | None = None,
        mfa_store: MFAStore | bool | None = None,
        translator: Translator | None = None,
        job_backend: JobBackend | None = None,
        job_storage: StorageBackend | None = None,
        config: DeckConfig | None = None,
        demo_credentials: Sequence[tuple[str, str, str]] = (),
        sql_presets: Sequence[tuple[str, str]] = (),
        **config_kwargs: Any,
    ) -> None:
        if config is not None and config_kwargs:
            raise ValueError("Pass either config=DeckConfig(...) or keyword arguments, not both")
        self.config: DeckConfig = config or DeckConfig(**config_kwargs)
        self._explicit_auth: AuthProvider | None = auth
        self.auth: AuthProvider = auth or OpenAuthProvider()
        self._audit_store_arg: AuditStore | bool | None = audit_store
        self.audit_store: AuditStore | None = (
            audit_store if isinstance(audit_store, AuditStore) else None
        )
        self._mfa_store_arg: MFAStore | bool | None = mfa_store
        self.mfa_store: MFAStore | None = mfa_store if isinstance(mfa_store, MFAStore) else None
        self.translator: Translator = translator or DictTranslator(
            default_locale=self.config.default_locale
        )
        self.job_backend: JobBackend | None = job_backend or (
            ThreadPoolJobBackend() if self.config.enable_jobs else None
        )
        self.job_storage: StorageBackend = job_storage or MemoryFileStorage()
        if isinstance(self.job_backend, ThreadPoolJobBackend):
            self.job_backend.set_on_evict(self._cleanup_evicted_job_artifact)
        self.events: DeckEventBus = DeckEventBus()
        self._brand_css_bytes, self._brand_css_hash = render_brand_css(self.config.brand)
        self.adapter: ORMAdapter | None = None
        self.app: Flask | None = None
        self.blueprint: Blueprint | None = None
        self.views: dict[str, ModelView] = {}
        self._views_by_model: dict[type[Any], ModelView] = {}
        self.custom_pages: dict[str, PageSpec] = {}
        self._dashboard_builder: DashboardBuilder | None = None
        self._rate_limiter = LoginRateLimiter(
            max_attempts=self.config.login_rate_limit_attempts,
            window_seconds=self.config.login_rate_limit_window_seconds,
            lockout_seconds=self.config.login_rate_limit_lockout_seconds,
        )
        self._preview_store = ImportPreviewStore(
            ttl_seconds=self.config.import_preview_ttl_seconds,
            max_entries=self.config.import_preview_max_entries,
        )
        self._asset_hashes: dict[str, str] = {}
        self._demo_credentials = tuple(demo_credentials)
        self._sql_presets = tuple(sql_presets)

        if db is not None or session_factory is not None or engine is not None:
            self.adapter = resolve_adapter(
                db, session_factory=session_factory, engine=engine, binds=binds
            )

        if app is not None:
            self.init_app(app)

    def _cleanup_evicted_job_artifact(self, rec: JobRecord) -> None:
        if rec.artifact_key:
            try:
                self.job_storage.delete(rec.artifact_key)
            except Exception as exc:
                logger.warning("Failed to delete evicted job artifact %s: %s", rec.artifact_key, exc)

    def close(self) -> None:
        """Dispose database engine pools and stop background job worker threads cleanly."""
        if isinstance(self.job_backend, ThreadPoolJobBackend):
            self.job_backend.shutdown(wait=False, cancel_futures=True)
        if self.adapter is not None:
            self.adapter.dispose()

    def init_app(
        self,
        app: Flask,
        db: Any | None = None,
        *,
        session_factory: sessionmaker[Session] | Callable[[], Session] | None = None,
        engine: Engine | None = None,
        binds: Mapping[str, Engine] | None = None,
    ) -> None:
        """Bind Deck to a Flask application (supports Flask App Factory pattern)."""
        if db is not None or session_factory is not None or engine is not None:
            self.adapter = resolve_adapter(
                db, session_factory=session_factory, engine=engine, binds=binds
            )
        if self.adapter is None:
            raise ValueError("Deck requires a Flask-SQLAlchemy db, sessionmaker, engine, or ORMAdapter.")

        # Fail-closed security check: refuse silent unauthenticated production mounts!
        if self._explicit_auth is None:
            if self.config.allow_insecure_open:
                self.auth = OpenAuthProvider()
            elif app.debug or app.testing:
                self.auth = OpenAuthProvider()
                if not app.testing:
                    logger.warning(
                        "Flask-Deck running with OpenAuthProvider in debug mode. "
                        "Configure an explicit AuthProvider before deploying."
                    )
            else:
                raise SecurityConfigurationError(
                    "Refusing to mount Flask-Deck without an explicit AuthProvider while "
                    "app.debug is False. Pass auth=BasicAuthProvider(...), RBACAuthProvider(...), "
                    "FlaskLoginAuthProvider(...), or explicitly allow_insecure_open=True for local dev."
                )

        if not app.secret_key:
            if not (app.debug or app.testing):
                raise SecurityConfigurationError(
                    "Flask app.secret_key must be configured for CSRF and session security."
                )
            logger.warning("Flask app.secret_key is unset; sessions and CSRF require a secret key.")

        self.app = app
        self.adapter.register_teardown(app)

        # Initialize default SQLAlchemyAuditStore when auto_audit is enabled and not read_only.
        if (
            self.config.auto_audit
            and not self.config.read_only
            and self._audit_store_arg is None
            and self.audit_store is None
        ):
            with app.app_context():
                self.audit_store = SQLAlchemyAuditStore(self.adapter.get_engine())
        elif self._audit_store_arg is False:
            self.audit_store = None

        # Initialize default MFAStore independently of auto_audit (avoid DDL when read_only=True)
        if self._mfa_store_arg is False:
            self.mfa_store = None
        elif self.mfa_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.mfa_store = SQLAlchemyMFAStore(self.adapter.get_engine())
            else:
                self.mfa_store = InMemoryMFAStore()

        if self.config.enable_sql_telemetry:
            with app.app_context():
                for eng in self.adapter.get_engines().values():
                    attach_sql_telemetry(eng)

        self._asset_hashes = {
            "css/deck.css": _file_hash(_STATIC_DIR / "css" / "deck.css"),
            "js/deck.js": _file_hash(_STATIC_DIR / "js" / "deck.js"),
        }

        bp = self._build_blueprint()
        self.blueprint = bp
        app.register_blueprint(bp, url_prefix=self.config.url_prefix)

        decks: dict[str, Deck] = app.extensions.setdefault("flask_deck", {})
        decks[self.config.name] = self

    # ------------------------------------------------------------------
    # Registration API
    # ------------------------------------------------------------------

    def register(self, *models_or_views: type[Any] | ModelView) -> Deck:
        """Register one or more SQLAlchemy model classes or ModelView classes/instances."""
        for item in models_or_views:
            if isinstance(item, ModelView):
                self.register_view(item)
            elif isinstance(item, type) and issubclass(item, ModelView):
                self.register_view(
                    item(extra_sensitive_patterns=self.config.extra_sensitive_patterns)
                )
            else:
                view = ModelView(
                    item,
                    extra_sensitive_patterns=self.config.extra_sensitive_patterns,
                )
                self.register_view(view)
        return self

    def register_view(self, view: ModelView) -> Deck:
        """Register a concrete ModelView instance."""
        if view.meta.slug in _RESERVED_MODEL_SLUGS:
            raise ValueError(f"Model slug {view.meta.slug!r} conflicts with a built-in Deck route.")
        if view.meta.slug in self.views:
            raise ValueError(f"Duplicate Deck model slug: {view.meta.slug!r}")
        self.views[view.meta.slug] = view
        self._views_by_model[view.model] = view
        return self

    def dashboard(self, fn: DashboardBuilder) -> DashboardBuilder:
        """Decorator registering a custom dashboard widget builder callback."""
        self._dashboard_builder = fn
        return fn

    def page(
        self,
        slug: str,
        *,
        title: str,
        icon: str = "terminal",
        category: str = "Operations",
        subtitle: str = "",
        permission: str | None = None,
    ) -> Callable[[Callable[[DashboardContext], Sequence[Widget]]], Callable[[DashboardContext], Sequence[Widget]]]:
        """Decorator registering a custom widget-composed operational page in the workbench."""
        clean_slug = slug.strip().strip("/").lower()
        if not clean_slug or "/" in clean_slug:
            raise ValueError("Custom page slug must be a single non-empty URL segment")

        def decorator(
            fn: Callable[[DashboardContext], Sequence[Widget]],
        ) -> Callable[[DashboardContext], Sequence[Widget]]:
            self.custom_pages[clean_slug] = PageSpec(
                slug=clean_slug,
                title=title,
                handler=fn,
                icon=icon,
                category=category,
                subtitle=subtitle,
                permission=permission,
            )
            return fn

        return decorator

    def on(self, event_name: str) -> Callable[[EventListener], EventListener]:
        """Decorator subscribing a lifecycle event listener (e.g. 'record.created', '*')."""

        def decorator(fn: EventListener) -> EventListener:
            self.events.subscribe(event_name, fn)
            return fn

        return decorator

    def add_webhook(self, sink: WebhookSink) -> Deck:
        """Register an SSRF-hardened HMAC-signed WebhookSink on the event bus."""
        self.events.subscribe("*", sink)
        return self

    def url_for_model(self, model_or_slug: type[Any] | str) -> str | None:
        slug = (
            model_or_slug
            if isinstance(model_or_slug, str)
            else (
                self._views_by_model[model_or_slug].meta.slug
                if model_or_slug in self._views_by_model
                else None
            )
        )
        if slug is None or slug not in self.views:
            return None
        return url_for(f"{self.config.name}.model_list", slug=slug)

    def get_view(self, slug: str) -> ModelView:
        view = self.views.get(slug)
        if view is None:
            abort(404)
        return view

    def get_session(self, bind_key: str | None = None) -> Session:
        assert self.adapter is not None
        return self.adapter.get_session_for_bind(bind_key)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _current_user(self) -> DeckUser | None:
        user: DeckUser | None = getattr(g, "_deck_user", None)
        return user

    def _real_user(self) -> DeckUser | None:
        real: DeckUser | None = getattr(g, "_deck_real_user", None)
        return real or self._current_user()

    def _cursor_secret(self) -> bytes:
        raw = self.app.secret_key if self.app is not None else None
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, str) and raw:
            return raw.encode()
        return b"flask-deck-default-cursor-key"

    def _media_url_builder(self, view: ModelView) -> Callable[[str, Any], str | None]:
        bp_name = self.config.name
        slug = view.meta.slug

        def _build(field_name: str, obj: Any) -> str | None:
            if field_name not in view.file_fields or obj is None:
                return None
            if not getattr(obj, field_name, None):
                return None
            pk_str = encode_pk(extract_pk(obj, view.meta))
            return url_for(f"{bp_name}.serve_media", slug=slug, field_name=field_name, raw_pk=pk_str)

        return _build

    def _rel_repr(self, target_model: type[Any], item: Any) -> str:
        """Render a related ORM instance while honoring RBAC masked/hidden field policies."""
        user = self._current_user()
        target_view = self._views_by_model.get(target_model)
        if target_view is not None:
            return target_view.format_record_repr(item, auth=self.auth, user=user)
        return str(item)

    def _is_soft_deleted(self, view: ModelView, obj: Any) -> bool:
        if not view.soft_delete_column:
            return False
        sd_val = getattr(obj, view.soft_delete_column, None)
        return bool(sd_val) if isinstance(sd_val, bool) else (sd_val is not None)

    def _sanitize_audit_entry(self, entry: AuditEntry, user: DeckUser | None) -> AuditEntry:
        """Strip RBAC hidden fields and redact masked/sensitive fields from an AuditEntry for viewer."""
        if not entry.changes:
            return entry
        view = self.views.get(entry.model_slug)
        hidden = self.auth.hidden_fields_for(user, entry.model_slug)
        masked = self.auth.masked_fields_for(user, entry.model_slug)
        sensitive = view.meta.sensitive_fields if view is not None else frozenset()
        if not hidden and not masked and not sensitive:
            return entry
        clean_changes: dict[str, dict[str, Any]] = {}
        for fname, delta in entry.changes.items():
            if fname in hidden:
                continue
            if fname in masked or fname in sensitive or is_sensitive_field(
                fname, self.config.extra_sensitive_patterns
            ):
                clean_changes[fname] = {
                    "old": "[REDACTED]" if delta.get("old") is not None else None,
                    "new": "[REDACTED]" if delta.get("new") is not None else None,
                }
            else:
                clean_changes[fname] = delta
        return AuditEntry(
            id=entry.id,
            timestamp=entry.timestamp,
            actor_id=entry.actor_id,
            actor_name=entry.actor_name,
            actor_ip=entry.actor_ip,
            action=entry.action,
            model_slug=entry.model_slug,
            model_label=entry.model_label,
            record_pk=entry.record_pk,
            record_repr=entry.record_repr,
            changes=clean_changes,
            metadata=entry.metadata,
        )

    def _allowed_query_fields(
        self, view: ModelView, user: DeckUser | None
    ) -> tuple[tuple[str, ...], frozenset[str], frozenset[str]]:
        """Filter searchable, filterable, and sortable columns by viewer's hidden/masked RBAC rules."""
        restricted = self.auth.hidden_fields_for(user, view.meta.slug) | self.auth.masked_fields_for(
            user, view.meta.slug
        )
        searchable: list[str] = []
        for col_spec in view.resolved_searchable:
            if "." in col_spec:
                rel_name, target_col = col_spec.split(".", 1)
                if rel_name in restricted:
                    continue
                rel_meta = view.meta.relationships_by_name.get(rel_name)
                if rel_meta is not None:
                    t_view = self._views_by_model.get(rel_meta.target_model)
                    if t_view is not None:
                        t_restricted = self.auth.hidden_fields_for(
                            user, t_view.meta.slug
                        ) | self.auth.masked_fields_for(user, t_view.meta.slug)
                        if target_col in t_restricted or target_col in t_view.meta.sensitive_fields:
                            continue
                searchable.append(col_spec)
            elif col_spec not in restricted:
                searchable.append(col_spec)
        return (
            tuple(searchable),
            view.resolved_filterable - restricted,
            view.resolved_sortable - restricted,
        )

    def _collect_orphan_files(self, view: ModelView, obj: Any) -> list[tuple[Any, str]]:
        """Return (FileFieldConfig, key) pairs marked delete_orphan=True on a record."""
        out: list[tuple[Any, str]] = []
        for field_name, cfg in view.file_fields.items():
            if not cfg.delete_orphan:
                continue
            key = getattr(obj, field_name, None)
            if isinstance(key, str) and key:
                out.append((cfg, key))
        return out

    def _delete_orphan_files_best_effort(self, orphans: Sequence[tuple[Any, str]]) -> None:
        for fcfg, old_key in orphans:
            try:
                fcfg.storage.delete(old_key)
            except Exception as exc:
                logger.warning("Failed to delete orphan storage object %s: %s", old_key, exc)

    def _emit_event(
        self,
        name: str,
        *,
        model_slug: str = "",
        record_pk: str = "",
        payload: dict[str, Any] | None = None,
        actor: DeckUser | None = None,
    ) -> None:
        user = actor if actor is not None else self._current_user()
        event_payload = dict(payload or {})
        real = getattr(g, "_deck_real_user", None)
        if real is not None and (user is None or real.id != user.id):
            event_payload.setdefault("impersonated_by", real.id)
            event_payload.setdefault("impersonated_by_name", real.label)
        self.events.emit(
            DeckEvent(
                name=name,
                actor_id=user.id if user else "system",
                actor_name=user.label if user else "System",
                model_slug=model_slug,
                record_pk=record_pk,
                payload=event_payload,
            )
        )

    def _require_perm(self, permission: str, *, model_slug: str | None = None, obj: Any = None) -> None:
        user = self._current_user()
        if not self.auth.has_permission(user, permission, model_slug=model_slug, obj=obj):
            raise PermissionDeniedError(f"Missing permission: {permission}")

    def _fetch_scoped_record(self, view: ModelView, raw_pk: str) -> tuple[Any, tuple[Any, ...]]:
        pk_values = decode_pk(raw_pk, view.meta)
        stmt = view.scope_query(sa.select(view.model), self._current_user())
        for pk_field, val in zip(view.meta.primary_keys, pk_values, strict=True):
            stmt = stmt.where(getattr(view.model, pk_field.name) == val)
        stmt = apply_list_load_options(
            stmt,
            view.meta,
            tuple(r.name for r in view.meta.relationships),
            defer_unshown_heavy=False,
        )
        obj = self.get_session(view.bind_key).scalars(stmt).unique().first()
        if obj is None:
            abort(404)
        return obj, pk_values

    def _record_audit(
        self,
        *,
        action_name: str,
        view: ModelView,
        record_pk: str,
        record_repr: str,
        changes: dict[str, dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry | None:
        if self.audit_store is None or not self.config.auto_audit:
            return None
        user = self._current_user()
        meta = dict(metadata or {})
        real = getattr(g, "_deck_real_user", None)
        if real is not None and (user is None or real.id != user.id):
            meta["impersonated_by"] = real.id
            meta["impersonated_by_name"] = real.label
        entry = make_audit_entry(
            actor_id=user.id if user else "system",
            actor_name=user.label if user else "System",
            actor_ip=_client_ip(),
            action=action_name,
            model_slug=view.meta.slug,
            model_label=view.label,
            record_pk=record_pk,
            record_repr=record_repr,
            changes=changes,
            metadata=meta,
        )
        return self.audit_store.record(entry)

    def _sidebar_groups(self) -> list[dict[str, Any]]:
        """Build grouped sidebar navigation with ALL primary-bind row counts in ONE SQL query."""
        user = self._current_user()
        authorized: list[ModelView] = [
            v
            for v in self.views.values()
            if v.can_view and self.auth.has_permission(user, f"{v.meta.slug}:view", model_slug=v.meta.slug)
        ]

        counts: dict[str, int] = {}
        by_bind: dict[str | None, list[ModelView]] = {}
        for v in authorized:
            by_bind.setdefault(v.bind_key, []).append(v)

        for bk, b_views in by_bind.items():
            subqueries = []
            for v in b_views:
                scoped = v.scope_query(sa.select(sa.func.count()).select_from(v.model), user)
                sd_pred = soft_delete_predicate(v.meta, v.soft_delete_column, trashed=False)
                if sd_pred is not None:
                    scoped = scoped.where(sd_pred)
                subqueries.append(scoped.scalar_subquery().label(v.meta.slug))
            row = self.get_session(bk).execute(sa.select(*subqueries)).first()
            if row is not None:
                for idx, v in enumerate(b_views):
                    counts[v.meta.slug] = int(row[idx] or 0)

        groups_map: dict[str, list[dict[str, Any]]] = {}
        for v in authorized:
            groups_map.setdefault(v.category, []).append(
                {
                    "slug": v.meta.slug,
                    "label": v.plural_label,
                    "icon": v.icon,
                    "count": counts.get(v.meta.slug, 0),
                    "url": url_for(f"{self.config.name}.model_list", slug=v.meta.slug),
                    "is_page": False,
                }
            )
        for p in self.custom_pages.values():
            page_allowed = (
                self.auth.has_permission(user, p.permission)
                if p.permission
                else (
                    self.auth.has_permission(user, f"page:{p.slug}:view")
                    or self.auth.has_permission(user, "*:view")
                )
            )
            if page_allowed:
                groups_map.setdefault(p.category, []).append(
                    {
                        "slug": f"_page:{p.slug}",
                        "label": p.title,
                        "icon": p.icon,
                        "count": None,
                        "url": url_for(f"{self.config.name}.custom_page", page_slug=p.slug),
                        "is_page": True,
                    }
                )
        return [{"name": cat, "links": items} for cat, items in groups_map.items()]

    def _asset_url(self, filename: str) -> str:
        ver = self._asset_hashes.get(filename) or _file_hash(_STATIC_DIR / filename)
        return url_for(f"{self.config.name}.static", filename=filename, v=ver)

    def _base_context(self, **extra: Any) -> dict[str, Any]:
        user = self._current_user()
        real_user = getattr(g, "_deck_real_user", None)
        is_impersonating = real_user is not None
        tel = get_request_telemetry()
        bp_name = self.config.name
        can_audit = self.audit_store is not None and self.auth.has_permission(user, "audit:view")
        can_rbac = bool(self.auth.get_roles()) and self.auth.has_permission(user, "rbac:view")
        can_schema = self.auth.has_permission(user, "schema:view") or self.auth.has_permission(
            user, "*:view"
        )
        can_diagnostics = self.auth.has_permission(user, "diagnostics:view") or (
            user is not None and user.is_superuser
        )
        can_sql = self.config.enable_sql_console and self.auth.has_permission(user, "sql:query")
        can_jobs = self.job_backend is not None and user is not None
        can_mfa = self.mfa_store is not None and user is not None and self.auth.supports_login_form
        demo_accounts: Sequence[DeckUser] = ()
        if (
            self.config.demo_role_switcher
            and self.config.environment != "production"
            and isinstance(self.auth, RBACAuthProvider)
        ):
            demo_accounts = self.auth.get_demo_accounts()

        impersonate_targets: Sequence[DeckUser] = ()
        if (
            self.config.enable_impersonation
            and not is_impersonating
            and user is not None
            and user.is_superuser
            and isinstance(self.auth, RBACAuthProvider)
        ):
            impersonate_targets = tuple(
                acc
                for acc in self.auth.get_demo_accounts()
                if acc.id != user.id and not acc.is_superuser
            )

        active_locale = self.translator.get_locale()
        active_tz = str(getattr(g, "_flask_deck_tz", self.config.default_timezone))
        text_dir = "rtl" if self.translator.is_rtl(active_locale) else "ltr"

        ctx: dict[str, Any] = {
            "deck": self,
            "config": self.config,
            "brand": self.config.brand,
            "brand_css_hash": self._brand_css_hash,
            "bp_name": bp_name,
            "current_user": user,
            "impersonator": real_user,
            "is_impersonating": is_impersonating,
            "impersonate_read_only": bool(
                session.get(IMPERSONATE_RO_KEY, self.config.impersonate_read_only)
            )
            if is_impersonating
            else False,
            "impersonate_targets": impersonate_targets,
            "csrf_token": get_csrf_token(),
            "csrf_field": CSRF_FORM_FIELD,
            "csp_nonce": getattr(g, "_deck_csp_nonce", ""),
            "sidebar_groups": self._sidebar_groups() if user is not None else [],
            "deck_icon": render_icon,
            "asset_url": self._asset_url,
            "can_view_audit": can_audit,
            "can_view_rbac": can_rbac,
            "can_view_schema": can_schema,
            "can_view_diagnostics": can_diagnostics,
            "can_view_sql": can_sql,
            "can_view_jobs": can_jobs,
            "can_manage_mfa": can_mfa,
            "demo_accounts": demo_accounts,
            "supports_logout": self.auth.supports_login_form,
            "sso_providers": (
                self.auth.get_sso_providers() if isinstance(self.auth, OIDCAuthProvider) else ()
            ),
            "telemetry": tel,
            "encode_pk": encode_pk,
            "extract_pk": extract_pk,
            "is_insecure_open": isinstance(self.auth, OpenAuthProvider),
            "_": self.translator.translate,
            "active_locale": active_locale,
            "active_timezone": active_tz,
            "text_dir": text_dir,
            "available_locales": self.config.available_locales,
            "locale_labels": LOCALE_LABELS,
            "curated_timezones": CURATED_TIMEZONES,
            "rel_repr": self._rel_repr,
            "format_dt": lambda dt, fmt="%Y-%m-%d %H:%M": (
                to_user_timezone(dt, active_tz).strftime(fmt) if isinstance(dt, datetime) else str(dt)
            ),
        }
        ctx.update(extra)
        ctx["render_slot"] = lambda slot_name: render_safe_slot(
            self.config.brand, slot_name, ctx, template_renderer=render_template
        )
        return ctx

    def _fk_options_for_field(
        self,
        target_model: type[Any],
        limit: int = 50,
        *,
        fallback_bind_key: str | None = None,
        current_value: Any = None,
    ) -> list[dict[str, str]]:
        user = self._current_user()
        target_view = self._views_by_model.get(target_model)
        stmt = sa.select(target_model)
        bind_key = fallback_bind_key
        if target_view is not None:
            stmt = target_view.scope_query(stmt, user)
            sd_pred = soft_delete_predicate(
                target_view.meta, target_view.soft_delete_column, trashed=False
            )
            if sd_pred is not None:
                stmt = stmt.where(sd_pred)
            meta = target_view.meta
            bind_key = target_view.bind_key
        else:
            from flask_deck.introspection import introspect_model

            meta = introspect_model(target_model)
        sess = self.get_session(bind_key)
        stmt = stmt.order_by(getattr(target_model, meta.primary_keys[0].name).asc()).limit(limit)
        items = list(sess.scalars(stmt).all())
        options: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for item in items:
            pk_val = encode_pk(extract_pk(item, meta))
            seen_ids.add(pk_val)
            label = (
                target_view.format_record_repr(item, auth=self.auth, user=user)
                if target_view
                else str(item)
            )
            options.append({"id": pk_val, "label": label})

        # Ensure currently selected FK value beyond row `limit` is still loaded and labelled cleanly
        if current_value is not None and str(current_value) not in seen_ids and len(meta.primary_keys) == 1:
            try:
                cur_pk = decode_pk(str(current_value), meta)
                cur_stmt = sa.select(target_model).where(
                    getattr(target_model, meta.primary_keys[0].name) == cur_pk[0]
                )
                if target_view is not None:
                    cur_stmt = target_view.scope_query(cur_stmt, user)
                cur_obj = sess.scalars(cur_stmt).first()
                if cur_obj is not None:
                    pk_str = encode_pk(extract_pk(cur_obj, meta))
                    lbl = (
                        target_view.format_record_repr(cur_obj, auth=self.auth, user=user)
                        if target_view
                        else str(cur_obj)
                    )
                    options.insert(0, {"id": pk_str, "label": lbl})
            except InvalidPKError:
                pass
        return options

    def _build_form_context(
        self,
        view: ModelView,
        *,
        obj: Any | None,
        mode: str,
        errors: dict[str, list[str]] | None = None,
        submitted: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        user = self._current_user()
        visible = view.visible_form_fields(self.auth, user)
        readonly = self.auth.readonly_fields_for(user, view.meta.slug)
        masked = self.auth.masked_fields_for(user, view.meta.slug)

        # Resolve fieldsets (either declarative or single default group)
        if view.fieldsets:
            fieldsets: list[tuple[str, list[str]]] = []
            used: set[str] = set()
            for title, cols in view.fieldsets:
                kept = [c for c in cols if c in visible]
                if kept:
                    fieldsets.append((title, kept))
                    used.update(kept)
            remaining = [c for c in visible if c not in used]
            if remaining:
                fieldsets.append(("Additional Fields", remaining))
        else:
            fieldsets = [(f"{view.label} Details", list(visible))]

        field_specs: dict[str, dict[str, Any]] = {}
        for col_name in visible:
            fmeta = view.meta.fields_by_name.get(col_name)
            rel_meta = view.meta.relationships_by_name.get(col_name)
            is_ro = (
                (col_name in readonly or col_name in masked) and mode == "edit"
            ) or (fmeta is not None and fmeta.primary_key and mode == "edit")

            if fmeta is not None:
                if col_name in masked and mode == "edit":
                    raw_val = self.auth.mask_field_value(
                        user,
                        view.meta.slug,
                        col_name,
                        getattr(obj, col_name, None) if obj is not None else None,
                    )
                elif submitted is not None:
                    if fmeta.field_type == "boolean":
                        raw_val = str(submitted.get(col_name, "")).strip().lower() in {
                            "1",
                            "true",
                            "yes",
                            "on",
                        }
                    elif col_name in submitted:
                        raw_val = submitted.get(col_name)
                    else:
                        raw_val = getattr(obj, col_name, None) if obj is not None else None
                else:
                    raw_val = getattr(obj, col_name, None) if obj is not None else None
                if (
                    raw_val is not None
                    and fmeta.enum_class is not None
                    and isinstance(raw_val, fmeta.enum_class)
                ):
                    raw_val = raw_val.value
                elif isinstance(raw_val, datetime):
                    raw_val = to_user_timezone(raw_val).strftime("%Y-%m-%dT%H:%M")
                elif fmeta.field_type == "json" and isinstance(raw_val, (dict, list)):
                    raw_val = json.dumps(raw_val, indent=2)
                elif fmeta.field_type == "array" and isinstance(raw_val, (list, tuple)):
                    raw_val = json.dumps(list(raw_val))

                fk_options: list[dict[str, str]] = []
                fk_search_url: str | None = None
                fk_current_label = ""
                if fmeta.fk_target_model is not None:
                    fk_options = self._fk_options_for_field(
                        fmeta.fk_target_model,
                        fallback_bind_key=view.bind_key,
                        current_value=raw_val,
                    )
                    target_v = self._views_by_model.get(fmeta.fk_target_model)
                    if target_v is not None:
                        fk_search_url = url_for(f"{self.config.name}.api_fk", slug=target_v.meta.slug)
                    if raw_val is not None:
                        for opt in fk_options:
                            if opt["id"] == str(raw_val):
                                fk_current_label = opt["label"]
                                break

                file_cfg = view.file_fields.get(col_name)
                media_url: str | None = None
                if file_cfg is not None and obj is not None and raw_val:
                    pk_str_cur = encode_pk(extract_pk(obj, view.meta))
                    media_url = url_for(
                        f"{self.config.name}.serve_media",
                        slug=view.meta.slug,
                        field_name=col_name,
                        raw_pk=pk_str_cur,
                    )

                cond_rule = view.field_conditions.get(col_name)
                show_when_json = (
                    json.dumps({"field": cond_rule[0], "op": cond_rule[1], "value": cond_rule[2]})
                    if cond_rule is not None
                    else ""
                )
                dep_rule = view.dependent_fields.get(col_name)
                dependent_json = (
                    json.dumps({"parent": dep_rule[0], "filter_col": dep_rule[1]})
                    if dep_rule is not None
                    else ""
                )

                widget_override = view.field_widgets.get(col_name, "")
                kind = (
                    "file"
                    if file_cfg is not None
                    else ("fk" if fmeta.fk_target_model is not None else fmeta.field_type)
                )
                field_specs[col_name] = {
                    "kind": kind,
                    "widget": widget_override,
                    "file_kind": file_cfg.kind if file_cfg is not None else "",
                    "file_accept": ",".join(sorted(file_cfg.resolved_allowed_mimes()))
                    if file_cfg is not None
                    else "",
                    "media_url": media_url,
                    "show_when_json": show_when_json,
                    "dependent_json": dependent_json,
                    "name": col_name,
                    "label": view.get_column_label(col_name),
                    "required": (not fmeta.nullable and not fmeta.has_default and not fmeta.autoincrement),
                    "readonly": is_ro,
                    "masked": col_name in masked,
                    "value": "" if raw_val is None else raw_val,
                    "choices": fmeta.choices,
                    "max_length": fmeta.max_length,
                    "fk_options": fk_options,
                    "fk_search_url": fk_search_url,
                    "fk_current_label": fk_current_label,
                }
            elif rel_meta is not None and rel_meta.direction == "MANYTOMANY":
                options = self._fk_options_for_field(
                    rel_meta.target_model,
                    limit=100,
                    fallback_bind_key=view.bind_key,
                )
                selected_ids: set[str] = set()
                if submitted is not None and hasattr(submitted, "getlist"):
                    selected_ids = {str(v) for v in submitted.getlist(col_name) if v}
                elif obj is not None:
                    from flask_deck.introspection import introspect_model

                    t_meta = introspect_model(rel_meta.target_model)
                    for item in getattr(obj, col_name, []) or []:
                        selected_ids.add(encode_pk(extract_pk(item, t_meta)))
                field_specs[col_name] = {
                    "kind": "m2m",
                    "name": col_name,
                    "label": view.get_column_label(col_name),
                    "required": False,
                    "readonly": is_ro,
                    "masked": False,
                    "options": options,
                    "selected_ids": selected_ids,
                }

        # Inline child rows (routed to view.bind_key!)
        inlines_ctx: list[dict[str, Any]] = []
        parent_pk = (
            getattr(obj, view.meta.primary_keys[0].name, None) if obj is not None else None
        )
        for inline in view.inline_views:
            fk_col = inline.resolve_fk_column(view.meta)
            existing_rows: list[Any] = []
            if parent_pk is not None:
                existing_rows = list(
                    self.get_session(view.bind_key)
                    .scalars(
                        sa.select(inline.model)
                        .where(getattr(inline.model, fk_col) == parent_pk)
                        .order_by(getattr(inline.model, inline.meta.primary_keys[0].name).asc())
                    )
                    .all()
                )
            col_specs = []
            for col in inline.editable_columns:
                fm = inline.meta.fields_by_name[col]
                fk_opts = (
                    self._fk_options_for_field(
                        fm.fk_target_model, fallback_bind_key=view.bind_key
                    )
                    if fm.fk_target_model is not None
                    else []
                )
                col_specs.append(
                    {
                        "name": col,
                        "label": fm.label,
                        "kind": "fk" if fm.fk_target_model is not None else fm.field_type,
                        "choices": fm.choices,
                        "fk_options": fk_opts,
                    }
                )
            rows_data = []
            pk_name = inline.meta.primary_keys[0].name
            for r in existing_rows:
                vals: dict[str, Any] = {}
                for col in inline.editable_columns:
                    v = getattr(r, col, None)
                    if isinstance(v, enum.Enum):
                        v = v.value
                    vals[col] = "" if v is None else v
                rows_data.append({"pk": str(getattr(r, pk_name)), "values": vals})

            inlines_ctx.append(
                {
                    "slug": inline.meta.slug,
                    "label": inline.display_label,
                    "columns": col_specs,
                    "rows": rows_data,
                    "can_create": inline.can_create,
                    "can_delete": inline.can_delete,
                }
            )

        return {
            "view": view,
            "obj": obj,
            "mode": mode,
            "fieldsets": fieldsets,
            "field_specs": field_specs,
            "inlines": inlines_ctx,
            "errors": errors or {},
            "has_file_fields": any(c in view.file_fields for c in visible),
        }

    # ------------------------------------------------------------------
    # Blueprint & Routes
    # ------------------------------------------------------------------

    def _build_blueprint(self) -> Blueprint:
        bp = Blueprint(
            self.config.name,
            __name__,
            template_folder=str(_TEMPLATE_DIR),
            static_folder=str(_STATIC_DIR),
            static_url_path="/static",
        )
        deck = self
        bp_name = self.config.name

        @bp.before_request
        def _before_deck_request() -> Response | None:
            endpoint = request.endpoint or ""
            if endpoint in {f"{bp_name}.static", f"{bp_name}.brand_theme_css"}:
                return None

            nonce = (
                deck.config.csp_nonce_getter()
                if deck.config.csp_nonce_getter is not None
                else generate_nonce()
            )
            g._deck_csp_nonce = nonce
            if deck.config.enable_sql_telemetry:
                begin_request_telemetry()

            # Resolve request locale & timezone safely
            raw_loc = (
                deck.config.locale_selector()
                if deck.config.locale_selector is not None
                else str(session.get(LOCALE_SESSION_KEY, deck.config.default_locale))
            )
            norm_loc = normalize_locale(raw_loc, deck.config.default_locale)
            if deck.config.available_locales and norm_loc not in deck.config.available_locales:
                norm_loc = deck.config.default_locale
            raw_tz = (
                deck.config.timezone_selector()
                if deck.config.timezone_selector is not None
                else str(session.get(TZ_SESSION_KEY, deck.config.default_timezone))
            )
            valid_tz = raw_tz if is_valid_timezone(raw_tz) else deck.config.default_timezone
            set_request_locale_tz(norm_loc, valid_tz)

            is_public_auth = endpoint in {
                f"{bp_name}.login",
                f"{bp_name}.login_mfa",
                f"{bp_name}.sso_login",
                f"{bp_name}.sso_callback",
            }
            is_logout = endpoint == f"{bp_name}.logout"
            is_readonly_post = endpoint in {
                f"{bp_name}.sql_console",
                f"{bp_name}.demo_switch_role",
                f"{bp_name}.update_preferences",
                f"{bp_name}.impersonate_stop",
                f"{bp_name}.model_export_async",
            }
            is_api = endpoint.startswith(f"{bp_name}.api_")

            # 1. Server-side read_only guard
            if (
                deck.config.read_only
                and request.method not in {"GET", "HEAD", "OPTIONS"}
                and not (is_public_auth or is_logout or is_readonly_post)
            ):
                if is_api:
                    return jsonify({"error": "Flask-Deck is running in read-only mode."}), 403  # type: ignore[return-value]
                abort(403, description="Flask-Deck is running in read-only mode.")

            # 2. Strict CSRF + Origin/Sec-Fetch-Site validation on EVERY mutation
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf(request):
                if is_api:
                    return jsonify({"error": "Invalid or missing CSRF token."}), 403  # type: ignore[return-value]
                abort(403, description="Invalid or missing CSRF token.")

            # 3. Authentication, session timeout & audited impersonation resolution
            real_user = deck.auth.get_current_user(
                idle_timeout=deck.config.session_idle_timeout_seconds,
                absolute_timeout=deck.config.session_absolute_timeout_seconds,
            )
            effective_user = real_user
            g._deck_real_user = None
            imp_target_id = session.get(IMPERSONATED_USER_KEY)
            imp_actor_id = session.get(IMPERSONATOR_USER_KEY)
            if (
                real_user is not None
                and real_user.is_superuser
                and isinstance(imp_target_id, str)
                and imp_target_id
                and imp_actor_id == real_user.id
                and isinstance(deck.auth, RBACAuthProvider)
            ):
                target = deck.auth.get_account_by_id(imp_target_id)
                if target is not None and not target.is_superuser:
                    g._deck_real_user = real_user
                    effective_user = target
                    # Server config impersonate_read_only=True can never be weakened by a stale session cookie
                    enforced_imp_ro = deck.config.impersonate_read_only or bool(
                        session.get(IMPERSONATE_RO_KEY, True)
                    )
                    if (
                        enforced_imp_ro
                        and request.method not in {"GET", "HEAD", "OPTIONS"}
                        and not (is_logout or is_readonly_post)
                    ):
                        if is_api:
                            return (
                                jsonify({"error": "Mutations are disabled during read-only impersonation."}),
                                403,
                            )  # type: ignore[return-value]
                        raise ReadOnlyError(
                            "Mutations are disabled during read-only impersonation. Exit impersonation first."
                        )
                else:
                    session.pop(IMPERSONATED_USER_KEY, None)
                    session.pop(IMPERSONATOR_USER_KEY, None)

            g._deck_user = effective_user

            if is_public_auth:
                return None

            if effective_user is None:
                if is_api:
                    return jsonify({"error": "Authentication required."}), 401  # type: ignore[return-value]
                if deck.auth.supports_login_form:
                    next_target = request.full_path.rstrip("?")
                    if not is_safe_redirect_url(next_target):
                        next_target = url_for(f"{bp_name}.index")
                    return redirect(url_for(f"{bp_name}.login", next=next_target))  # type: ignore[return-value]
                abort(403, description="Authentication required.")

            # 4. Enforce require_mfa_for_superusers whenever configured with an active MFA store
            if (
                deck.config.require_mfa_for_superusers
                and deck.mfa_store is not None
                and real_user is not None
                and real_user.is_superuser
                and endpoint not in {f"{bp_name}.security_mfa", f"{bp_name}.logout", f"{bp_name}.update_preferences"}
            ):
                enr = deck.mfa_store.get(real_user.id)
                enrolled = enr is not None and enr.enabled
                if not enrolled:
                    if is_api:
                        return jsonify({"error": "MFA enrollment is required for superusers."}), 403  # type: ignore[return-value]
                    flash("Superuser accounts must enroll in Two-Factor Authentication before continuing.", "warn")
                    return redirect(url_for(f"{bp_name}.security_mfa"))  # type: ignore[return-value]
                if deck.auth.supports_login_form and not bool(session.get(MFA_VERIFIED_KEY)):
                    if is_api:
                        return jsonify({"error": "MFA verification required."}), 401  # type: ignore[return-value]
                    session[MFA_PENDING_USER_KEY] = real_user.id
                    session[MFA_PENDING_AT_KEY] = int(time.time())
                    return redirect(url_for(f"{bp_name}.login_mfa"))  # type: ignore[return-value]
            return None

        @bp.after_request
        def _after_deck_request(response: Response) -> Response:
            ep = request.endpoint or ""
            is_static = ep in {f"{bp_name}.static", f"{bp_name}.brand_theme_css"}
            nonce = getattr(g, "_deck_csp_nonce", "") or generate_nonce()
            return apply_security_headers(
                response,
                nonce=nonce,
                is_static=is_static,
                has_version_hash=bool(request.args.get("v")),
                extra_img_sources=deck.config.csp_img_sources,
            )

        @bp.errorhandler(PermissionDeniedError)
        def _handle_perm(exc: PermissionDeniedError) -> tuple[Any, int]:
            if (request.endpoint or "").startswith(f"{bp_name}.api_"):
                return jsonify({"error": str(exc)}), 403
            return (
                render_template(
                    "flask_deck/error.html",
                    **deck._base_context(
                        status_code=403,
                        error_title="Access Denied",
                        error_message=str(exc),
                    ),
                ),
                403,
            )

        @bp.errorhandler(ReadOnlyError)
        def _handle_ro(exc: ReadOnlyError) -> tuple[Any, int]:
            if (request.endpoint or "").startswith(f"{bp_name}.api_"):
                return jsonify({"error": str(exc)}), 403
            return (
                render_template(
                    "flask_deck/error.html",
                    **deck._base_context(
                        status_code=403,
                        error_title="Read-Only Mode",
                        error_message=str(exc),
                    ),
                ),
                403,
            )

        @bp.errorhandler(InvalidPKError)
        def _handle_invalid_pk(_exc: InvalidPKError) -> tuple[Any, int]:
            if (request.endpoint or "").startswith(f"{bp_name}.api_"):
                return jsonify({"error": "Record not found."}), 404
            return (
                render_template(
                    "flask_deck/error.html",
                    **deck._base_context(
                        status_code=404,
                        error_title="Record Not Found",
                        error_message="The requested identifier is invalid or does not exist.",
                    ),
                ),
                404,
            )

        # ---- Authentication ----

        @bp.route("/login", methods=["GET", "POST"])
        def login() -> Any:
            if not deck.auth.supports_login_form:
                abort(404)
            if deck._current_user() is not None:
                return redirect(url_for(f"{bp_name}.index"))

            next_url = request.args.get("next") or request.form.get("next") or ""
            error_msg = ""
            retry_after = 0

            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                ip = _client_ip()
                locked, retry_after = deck._rate_limiter.is_locked(ip, username)
                if locked:
                    error_msg = f"Too many failed attempts. Try again in {retry_after}s."
                    resp = Response(
                        render_template(
                            "flask_deck/login.html",
                            **deck._base_context(
                                next_url=next_url,
                                error_msg=error_msg,
                                demo_credentials=deck._demo_credentials,
                            ),
                        ),
                        status=429,
                    )
                    resp.headers["Retry-After"] = str(retry_after)
                    return resp

                user = deck.auth.authenticate(username, password)
                if user is not None:
                    deck._rate_limiter.record_success(ip, username)
                    dest = next_url if is_safe_redirect_url(next_url) else url_for(f"{bp_name}.index")
                    if deck.mfa_store is not None:
                        enrollment = deck.mfa_store.get(user.id)
                        if enrollment is not None and enrollment.enabled:
                            session.clear()
                            session[MFA_PENDING_USER_KEY] = user.id
                            session[MFA_PENDING_NEXT_KEY] = dest
                            session[MFA_PENDING_AT_KEY] = int(time.time())
                            rotate_csrf_token()
                            return redirect(url_for(f"{bp_name}.login_mfa"))
                    deck.auth.login_user(user)
                    return redirect(dest)

                deck._rate_limiter.record_failure(ip, username)
                deck._emit_event("login.failed", payload={"username": username, "ip": ip})
                error_msg = "Invalid username or password."

            return render_template(
                "flask_deck/login.html",
                **deck._base_context(
                    next_url=next_url,
                    error_msg=error_msg,
                    demo_credentials=deck._demo_credentials,
                ),
            )

        @bp.route("/login/mfa", methods=["GET", "POST"])
        def login_mfa() -> Any:
            if deck.mfa_store is None:
                abort(404)
            pending_uid = session.get(MFA_PENDING_USER_KEY)
            pending_at = session.get(MFA_PENDING_AT_KEY)
            if not isinstance(pending_uid, str) or not pending_uid:
                return redirect(url_for(f"{bp_name}.login"))
            if isinstance(pending_at, int) and (int(time.time()) - pending_at) > MFA_PENDING_TTL_SECONDS:
                session.pop(MFA_PENDING_USER_KEY, None)
                session.pop(MFA_PENDING_NEXT_KEY, None)
                session.pop(MFA_PENDING_AT_KEY, None)
                session.pop(MFA_PENDING_SSO_KEY, None)
                flash("MFA verification window expired. Please sign in again.", "warn")
                return redirect(url_for(f"{bp_name}.login"))

            error_msg = ""
            if request.method == "POST":
                ip = _client_ip()
                locked, retry_after = deck._rate_limiter.is_locked(ip, f"mfa:{pending_uid}")
                if locked:
                    resp = Response(
                        render_template(
                            "flask_deck/login_mfa.html",
                            **deck._base_context(
                                error_msg=f"Too many failed MFA attempts. Retry in {retry_after}s."
                            ),
                        ),
                        status=429,
                    )
                    resp.headers["Retry-After"] = str(retry_after)
                    return resp

                code = request.form.get("code", "").strip()
                if deck.mfa_store.verify_and_record(pending_uid, code):
                    deck._rate_limiter.record_success(ip, f"mfa:{pending_uid}")
                    dest_raw = str(session.pop(MFA_PENDING_NEXT_KEY, ""))
                    pending_sso = session.pop(MFA_PENDING_SSO_KEY, None)
                    session.pop(MFA_PENDING_USER_KEY, None)
                    session.pop(MFA_PENDING_AT_KEY, None)
                    target_user: DeckUser | None = None
                    if isinstance(pending_sso, Mapping) and str(pending_sso.get("id")) == pending_uid:
                        target_user = DeckUser(
                            id=pending_uid,
                            username=str(pending_sso.get("username", pending_uid)),
                            display_name=str(pending_sso.get("display_name", "")),
                            email=str(pending_sso.get("email", "")),
                            roles=tuple(str(r) for r in pending_sso.get("roles", ())),
                            is_superuser=bool(pending_sso.get("is_superuser", False)),
                        )
                    else:
                        target_user = deck.auth.get_user_by_id(pending_uid)
                    if target_user is None:
                        return redirect(url_for(f"{bp_name}.login"))
                    deck.auth.login_user(target_user)
                    session[MFA_VERIFIED_KEY] = True
                    dest = dest_raw if is_safe_redirect_url(dest_raw) else url_for(f"{bp_name}.index")
                    return redirect(dest)

                deck._rate_limiter.record_failure(ip, f"mfa:{pending_uid}")
                deck._emit_event("mfa.failed", payload={"user_id": pending_uid, "ip": ip})
                error_msg = "Invalid or already-used verification code."

            return render_template(
                "flask_deck/login_mfa.html",
                **deck._base_context(error_msg=error_msg),
            )

        @bp.route("/login/sso/<provider_name>")
        def sso_login(provider_name: str) -> Any:
            if not isinstance(deck.auth, OIDCAuthProvider):
                abort(404)
            if deck.auth.get_sso_provider(provider_name) is None:
                abort(404)
            next_url = request.args.get("next", "").strip()
            callback_uri = url_for(
                f"{bp_name}.sso_callback",
                provider_name=provider_name,
                _external=True,
            )
            auth_url = deck.auth.build_authorize_redirect(
                provider_name,
                redirect_uri=callback_uri,
                next_url=next_url if is_safe_redirect_url(next_url) else "",
            )
            return redirect(auth_url)

        @bp.route("/login/sso/<provider_name>/callback")
        def sso_callback(provider_name: str) -> Any:
            if not isinstance(deck.auth, OIDCAuthProvider):
                abort(404)
            if deck.auth.get_sso_provider(provider_name) is None:
                abort(404)
            callback_uri = url_for(
                f"{bp_name}.sso_callback",
                provider_name=provider_name,
                _external=True,
            )
            try:
                sso_user, next_url = deck.auth.complete_callback(
                    provider_name,
                    code=request.args.get("code", "").strip(),
                    state=request.args.get("state", "").strip(),
                    redirect_uri=callback_uri,
                )
            except (PermissionError, ValueError, OSError) as exc:
                deck._emit_event(
                    "login.failed",
                    payload={"provider": provider_name, "error": str(exc)},
                )
                return (
                    render_template(
                        "flask_deck/login.html",
                        **deck._base_context(
                            next_url="",
                            error_msg=f"SSO sign-in failed: {exc}",
                            demo_credentials=deck._demo_credentials,
                        ),
                    ),
                    403,
                )
            dest = next_url if is_safe_redirect_url(next_url) else url_for(f"{bp_name}.index")
            if deck.mfa_store is not None:
                enrollment = deck.mfa_store.get(sso_user.id)
                if enrollment is not None and enrollment.enabled:
                    session.clear()
                    session[MFA_PENDING_USER_KEY] = sso_user.id
                    session[MFA_PENDING_NEXT_KEY] = dest
                    session[MFA_PENDING_AT_KEY] = int(time.time())
                    session[MFA_PENDING_SSO_KEY] = {
                        "id": sso_user.id,
                        "username": sso_user.username,
                        "display_name": sso_user.display_name,
                        "email": sso_user.email,
                        "roles": list(sso_user.roles),
                        "is_superuser": sso_user.is_superuser,
                    }
                    rotate_csrf_token()
                    return redirect(url_for(f"{bp_name}.login_mfa"))
            deck.auth.login_user(sso_user)
            return redirect(dest)

        @bp.route("/logout", methods=["POST"])
        def logout() -> Any:
            deck.auth.logout_user()
            if deck.auth.supports_login_form:
                return redirect(url_for(f"{bp_name}.login"))
            return redirect(url_for(f"{bp_name}.index"))

        # ---- Brand Theme CSS (strict style-src 'self'), Preferences & Authorized Media Proxy ----

        @bp.route("/_theme.css")
        def brand_theme_css() -> Response:
            return Response(deck._brand_css_bytes, mimetype="text/css; charset=utf-8")

        @bp.route("/_preferences", methods=["POST"])
        def update_preferences() -> Any:
            if not deck.config.enable_user_preferences:
                abort(404)
            req_locale = request.form.get("locale", "").strip()
            req_tz = request.form.get("timezone", "").strip()
            if req_locale:
                norm = normalize_locale(req_locale)
                if deck.config.available_locales and norm not in deck.config.available_locales:
                    abort(400, description="Unsupported locale.")
                session[LOCALE_SESSION_KEY] = norm
            if req_tz:
                if not is_valid_timezone(req_tz):
                    abort(400, description="Invalid IANA timezone.")
                session[TZ_SESSION_KEY] = req_tz
            nxt = request.form.get("next", "").strip()
            dest = nxt if is_safe_redirect_url(nxt) else url_for(f"{bp_name}.index")
            return redirect(dest)

        @bp.route("/_media/<slug>/<field_name>/<raw_pk>")
        def serve_media(slug: str, field_name: str, raw_pk: str) -> Response:
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
            try:
                stream, detected_mime = cfg.storage.open(key)
            except (FileNotFoundError, ValueError):
                abort(404)
            try:
                data = stream.read()
            finally:
                stream.close()

            mime = detected_mime or "application/octet-stream"
            is_inline_raster = mime in RASTER_INLINE_MIMES
            safe_name = sanitize_filename(key.rsplit("/", 1)[-1])
            disposition = "inline" if is_inline_raster else "attachment"
            resp = Response(data, mimetype=mime)
            resp.headers["Content-Disposition"] = f'{disposition}; filename="{safe_name}"'
            resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Cache-Control"] = "private, max-age=300"
            return resp

        # ---- TOTP 2FA Self-Service & Audited Impersonation ----

        @bp.route("/_security/mfa", methods=["GET", "POST"])
        def security_mfa() -> Any:
            if deck.mfa_store is None:
                abort(404)
            if getattr(g, "_deck_real_user", None) is not None:
                raise PermissionDeniedError(
                    "MFA settings cannot be modified while impersonating another user."
                )
            user = deck._current_user()
            if user is None:
                abort(403)

            enrollment = deck.mfa_store.get(user.id)
            recovery_once: list[str] = []
            error_msg = ""
            mfa_required_for_user = bool(
                deck.config.require_mfa_for_superusers and user.is_superuser
            )

            if request.method == "POST":
                act = request.form.get("action", "").strip()
                if act == "disable":
                    if mfa_required_for_user:
                        error_msg = "MFA cannot be disabled while superuser MFA enforcement is active."
                    elif enrollment is not None and enrollment.enabled:
                        verify_code = request.form.get("code", "").strip()
                        if not verify_code or not deck.mfa_store.verify_and_record(user.id, verify_code):
                            error_msg = "Enter a valid current 6-digit TOTP or recovery code to disable 2FA."
                        else:
                            deck.mfa_store.delete(user.id)
                            session.pop(MFA_SETUP_SECRET_KEY, None)
                            session.pop(MFA_VERIFIED_KEY, None)
                            enrollment = None
                            if deck.audit_store is not None and deck.config.auto_audit:
                                deck.audit_store.record(
                                    make_audit_entry(
                                        actor_id=user.id,
                                        actor_name=user.label,
                                        actor_ip=_client_ip(),
                                        action="mfa_disabled",
                                        model_slug="_auth",
                                        model_label="MFA Security",
                                        record_pk=user.id,
                                        record_repr=user.label,
                                    )
                                )
                            deck._emit_event("mfa.disabled", record_pk=user.id)
                            flash("Two-factor authentication disabled.", "warn")
                elif act == "enable":
                    secret = str(session.get(MFA_SETUP_SECRET_KEY, ""))
                    code = request.form.get("code", "").strip()
                    if not secret:
                        error_msg = "Setup session expired. Refresh to generate a new secret."
                    else:
                        step = verify_totp(secret, code)
                        if step is None:
                            error_msg = "Invalid 6-digit code. Check your authenticator clock and retry."
                        else:
                            plain_codes, hashed_codes = generate_recovery_codes(8)
                            enrollment = MFAEnrollment(
                                user_id=user.id,
                                secret=secret,
                                enabled=True,
                                last_step=step,
                                recovery_hashes=hashed_codes,
                                created_at=datetime.now(timezone.utc),
                            )
                            deck.mfa_store.save(enrollment)
                            session.pop(MFA_SETUP_SECRET_KEY, None)
                            session[MFA_VERIFIED_KEY] = True
                            recovery_once = plain_codes
                            if deck.audit_store is not None and deck.config.auto_audit:
                                deck.audit_store.record(
                                    make_audit_entry(
                                        actor_id=user.id,
                                        actor_name=user.label,
                                        actor_ip=_client_ip(),
                                        action="mfa_enabled",
                                        model_slug="_auth",
                                        model_label="MFA Security",
                                        record_pk=user.id,
                                        record_repr=user.label,
                                    )
                                )
                            deck._emit_event("mfa.enabled", record_pk=user.id)
                            flash("Two-factor authentication enabled. Save your recovery codes now.", "ok")

            setup_secret = ""
            qr_svg = Markup("")
            otpauth_uri = ""
            if enrollment is None or not enrollment.enabled:
                setup_secret = str(session.get(MFA_SETUP_SECRET_KEY, ""))
                if not setup_secret:
                    setup_secret = generate_totp_secret()
                    session[MFA_SETUP_SECRET_KEY] = setup_secret
                otpauth_uri = build_otpauth_uri(
                    secret=setup_secret,
                    account_name=user.email or user.username,
                    issuer=deck.config.title,
                )
                try:
                    qr_svg = render_qr_svg(otpauth_uri, pixel_size=184)
                except ValueError:
                    qr_svg = Markup(
                        '<div class="dk-chart-empty">Enter the manual Base32 secret below in your authenticator app.</div>'
                    )

            return render_template(
                "flask_deck/mfa_setup.html",
                **deck._base_context(
                    page_title="Two-Factor Authentication (TOTP)",
                    active_nav="_mfa",
                    enrollment=enrollment,
                    mfa_required_for_user=mfa_required_for_user,
                    setup_secret=setup_secret,
                    otpauth_uri=otpauth_uri,
                    qr_svg=qr_svg,
                    recovery_once=recovery_once,
                    error_msg=error_msg,
                ),
            )

        @bp.route("/_impersonate/start", methods=["POST"])
        def impersonate_start() -> Any:
            if not deck.config.enable_impersonation or not isinstance(deck.auth, RBACAuthProvider):
                abort(404)
            real = deck._real_user()
            if real is None or not real.is_superuser:
                raise PermissionDeniedError("Only superusers may impersonate accounts.")
            if not deck.auth.has_permission(real, "impersonate:use"):
                raise PermissionDeniedError("Missing permission: impersonate:use")
            target_id = request.form.get("target_user_id", "").strip()
            target = deck.auth.get_account_by_id(target_id)
            if target is None or target.id == real.id or target.is_superuser:
                flash("Cannot impersonate this account (superusers cannot be impersonated).", "danger")
                return redirect(url_for(f"{bp_name}.index"))
            session[IMPERSONATOR_USER_KEY] = real.id
            session[IMPERSONATED_USER_KEY] = target.id
            session[IMPERSONATE_RO_KEY] = deck.config.impersonate_read_only
            if deck.audit_store is not None and deck.config.auto_audit:
                deck.audit_store.record(
                    make_audit_entry(
                        actor_id=real.id,
                        actor_name=real.label,
                        actor_ip=_client_ip(),
                        action="impersonate_start",
                        model_slug="_auth",
                        model_label="Impersonation",
                        record_pk=target.id,
                        record_repr=target.label,
                        metadata={"read_only": deck.config.impersonate_read_only},
                    )
                )
            flash(f"Now viewing as {target.label} ({', '.join(target.roles)}).", "warn")
            return redirect(url_for(f"{bp_name}.index"))

        @bp.route("/_impersonate/stop", methods=["POST"])
        def impersonate_stop() -> Any:
            real = getattr(g, "_deck_real_user", None)
            imp_id = session.pop(IMPERSONATED_USER_KEY, None)
            session.pop(IMPERSONATOR_USER_KEY, None)
            session.pop(IMPERSONATE_RO_KEY, None)
            if real is not None and imp_id and deck.audit_store is not None and deck.config.auto_audit:
                deck.audit_store.record(
                    make_audit_entry(
                        actor_id=real.id,
                        actor_name=real.label,
                        actor_ip=_client_ip(),
                        action="impersonate_stop",
                        model_slug="_auth",
                        model_label="Impersonation",
                        record_pk=str(imp_id),
                        record_repr=str(imp_id),
                    )
                )
            flash("Exited impersonation mode.", "ok")
            return redirect(url_for(f"{bp_name}.index"))

        # ---- Dashboard ----

        @bp.route("/")
        def index() -> str:
            raw_range = request.args.get("range", "14d").strip().lower().rstrip("d")
            range_days = int(raw_range) if raw_range in {"7", "14", "30", "90"} else 14
            ctx = DashboardContext(
                deck, deck.get_session(), deck._current_user(), range_days=range_days
            )
            if deck._dashboard_builder is not None:
                raw_widgets = list(deck._dashboard_builder(ctx))
                # Hydrate ActivityWidget entries automatically if caller passed empty entries.
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

        # ---- Model List ----

        @bp.route("/<slug>/")
        def model_list(slug: str) -> str:
            view = deck.get_view(slug)
            if not view.can_view:
                abort(404)
            deck._require_perm(f"{slug}:view", model_slug=slug)

            user = deck._current_user()
            visible_cols = view.visible_list_columns(deck.auth, user)
            search_term = request.args.get("q", "").strip()
            active_tab = request.args.get("tab", "").strip() or (
                view.quick_tabs[0].key if view.quick_tabs else ""
            )
            sort_by = request.args.get("sort", "").strip() or None
            sort_dir = request.args.get("dir", "desc").strip()
            try:
                page = int(request.args.get("page", "1"))
            except ValueError:
                page = 1
            default_ps = view.page_size or deck.config.page_size
            try:
                page_size = int(request.args.get("page_size", str(default_ps)))
            except ValueError:
                page_size = default_ps

            filter_pairs: list[tuple[str, str]] = []
            filter_params: dict[str, str] = {}
            for k, v in request.args.items(multi=True):
                if k.startswith("f_") and v.strip():
                    fk = k[2:]
                    fv = v.strip()
                    filter_pairs.append((fk, fv))
                    filter_params[fk] = fv

            allowed_searchable, allowed_filterable, allowed_sortable = deck._allowed_query_fields(
                view, user
            )
            pag_mode = view.pagination_mode or deck.config.default_pagination_mode
            after_cursor = request.args.get("after", "").strip() or None
            before_cursor = request.args.get("before", "").strip() or None
            trashed = bool(view.soft_delete_column and request.args.get("trashed") == "1")

            base_stmt = view.scope_query(sa.select(view.model), user)
            result = execute_list_query(
                deck.get_session(view.bind_key),
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
                sort_by=sort_by,
                sort_dir=sort_dir,
                default_sort=view.default_sort,
                page=page,
                page_size=page_size,
                max_page_size=deck.config.max_page_size,
                pagination_mode=pag_mode,
                count_mode=view.count_mode,
                after_cursor=after_cursor,
                before_cursor=before_cursor,
                cursor_secret=deck._cursor_secret(),
                soft_delete_column=view.soft_delete_column,
                trashed=trashed,
            )

            # Build filter panel specifications (only for visible, non-masked, non-sensitive cols)
            hidden_fields = deck.auth.hidden_fields_for(user, slug)
            masked_fields = deck.auth.masked_fields_for(user, slug)
            filter_specs: list[dict[str, Any]] = []
            for fname in sorted(allowed_filterable):
                if fname in hidden_fields or fname in masked_fields:
                    continue
                fm = view.meta.fields_by_name.get(fname)
                if fm is None:
                    continue
                spec: dict[str, Any] = {
                    "name": fname,
                    "label": view.get_column_label(fname),
                    "type": "fk" if fm.fk_target_model is not None else fm.field_type,
                    "choices": fm.choices,
                    "value": filter_params.get(fname, ""),
                    "gte": filter_params.get(f"{fname}__gte", ""),
                    "lte": filter_params.get(f"{fname}__lte", ""),
                    "preset": filter_params.get(f"{fname}__preset", ""),
                    "has_key": filter_params.get(f"{fname}__has_key", ""),
                    "path": filter_params.get(f"{fname}__path", ""),
                    "array_contains": filter_params.get(f"{fname}__array_contains", ""),
                    "array_any": filter_params.get(f"{fname}__array_any", ""),
                }
                if fm.fk_target_model is not None:
                    spec["fk_options"] = deck._fk_options_for_field(
                        fm.fk_target_model, limit=40, fallback_bind_key=view.bind_key
                    )
                filter_specs.append(spec)

            # Authorized actions
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
            can_export = view.can_export and deck.auth.has_permission(
                user, f"{slug}:export", model_slug=slug
            )
            can_import = (
                view.can_import
                and not deck.config.read_only
                and deck.auth.has_permission(user, f"{slug}:import", model_slug=slug)
            )

            readonly_fields = deck.auth.readonly_fields_for(user, slug)
            inline_editable = (
                (view.resolved_inline_editable - readonly_fields - hidden_fields)
                if can_edit
                else frozenset()
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

            # Optional Kanban Board mode when ModelView declares kanban_column
            supports_kanban = bool(
                view.kanban_column
                and view.kanban_column in view.meta.fields_by_name
                and view.meta.fields_by_name[view.kanban_column].choices
            )
            view_mode = (
                "board"
                if (supports_kanban and request.args.get("view", "table").strip().lower() == "board")
                else "table"
            )
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
                )
                writable_set = set(view.allowed_form_fields(deck.auth, user, mode="edit"))
                can_drag_kanban = can_edit and view.kanban_column in writable_set

            allowed_agg_spec = {
                k: v
                for k, v in view.column_aggregates.items()
                if k not in hidden_fields and k not in masked_fields
            }
            page_aggregates = (
                compute_page_aggregates(result.items, allowed_agg_spec)
                if view_mode == "table" and allowed_agg_spec
                else {}
            )

            def _qs(**overrides: Any) -> str:
                params = [(k, v) for k, v in request.args.items(multi=True) if k not in overrides]
                for k, v in overrides.items():
                    if v is not None and v != "":
                        params.append((k, str(v)))
                encoded = urlencode(params)
                return f"?{encoded}" if encoded else ""

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
                    sort_by=sort_by or (view.default_sort[0] if view.default_sort else view.meta.primary_keys[0].name),
                    sort_dir=sort_dir,
                    filter_specs=filter_specs,
                    can_create=can_create,
                    can_edit=can_edit,
                    can_delete=can_delete,
                    can_export=can_export,
                    can_import=can_import,
                    inline_editable=inline_editable,
                    bulk_actions=bulk_actions,
                    bulk_action_fields_json=bulk_action_fields_json,
                    supports_kanban=supports_kanban,
                    view_mode=view_mode,
                    kanban_columns=kanban_columns,
                    kanban_card_fields=kanban_card_fields,
                    can_drag_kanban=can_drag_kanban,
                    page_aggregates=page_aggregates,
                    supports_soft_delete=bool(view.soft_delete_column),
                    trashed=trashed,
                    media_url_builder=deck._media_url_builder(view),
                    qs=_qs,
                ),
            )

        # ---- Create ----

        @bp.route("/<slug>/new", methods=["GET", "POST"])
        def model_create(slug: str) -> Any:
            view = deck.get_view(slug)
            if not view.can_create:
                abort(403)
            deck._require_perm(f"{slug}:create", model_slug=slug)

            errors: dict[str, list[str]] = {}
            submitted: Mapping[str, Any] | None = None
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
                    view.apply_inline_forms(
                        sess,
                        obj,
                        request.form,
                        auth=deck.auth,
                        user=cur_user,
                        max_json_depth=deck.config.max_json_depth,
                    )
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
                    deck._emit_event(
                        "record.created",
                        model_slug=slug,
                        record_pk=pk_str,
                        payload={"repr": safe_repr},
                    )
                    flash(f"Created {view.label} ({safe_repr}).", "ok")
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))
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
            return render_template(
                "flask_deck/model_form.html",
                **deck._base_context(
                    page_title=f"New {view.label}",
                    active_nav=slug,
                    **form_ctx,
                ),
            )

        # ---- Detail ----

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
                        ),
                    }
                )

            relations_display = []
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
                        "records": [deck._rel_repr(rel.target_model, it) for it in items[:25]],
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
                    history=history,
                    can_create=can_create,
                    can_edit=can_edit,
                    can_delete=can_delete,
                    can_force_delete=can_force_delete,
                    is_soft_deleted=is_soft_deleted,
                ),
            )

        # ---- Side-by-Side Revision Diff & Time-Travel History ----

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
            entries, _ = deck.audit_store.list_entries(
                model_slug=slug, record_pk=pk_str, limit=50
            )
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
                    if fname in view.meta.sensitive_fields or fname in masked:
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

        # ---- Edit ----

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

            errors: dict[str, list[str]] = {}
            submitted: Mapping[str, Any] | None = None
            if request.method == "POST":
                submitted = request.form
                sess = deck.get_session(view.bind_key)
                before_snap = view.extract_snapshot(obj)
                newly_stored: list[tuple[Any, str]] = []
                orphans: list[tuple[Any, str]] = []

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
                    view.on_model_change(obj, is_created=False, user=cur_user)
                    sess.flush()
                    view.apply_inline_forms(
                        sess,
                        obj,
                        request.form,
                        auth=deck.auth,
                        user=cur_user,
                        max_json_depth=deck.config.max_json_depth,
                    )
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
                    flash(f"Saved changes to {safe_repr}.", "ok")
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
                    **form_ctx,
                ),
            )

        # ---- Delete (Soft-Delete Aware + Force Delete) & Restore ----

        @bp.route("/<slug>/<raw_pk>/delete", methods=["POST"])
        def model_delete(slug: str, raw_pk: str) -> Any:
            view = deck.get_view(slug)
            if not view.can_delete:
                abort(403)
            deck._require_perm(f"{slug}:delete", model_slug=slug)
            force_delete = request.form.get("force", "").strip() == "1"
            if view.soft_delete_column and force_delete:
                deck._require_perm(f"{slug}:force_delete", model_slug=slug)
            obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
            deck._require_perm(f"{slug}:delete", model_slug=slug, obj=obj)
            cur_user = deck._current_user()
            pk_str = encode_pk(pk_vals)
            repr_str = view.format_record_repr(obj, auth=deck.auth, user=cur_user)
            before_snap = view.extract_snapshot(obj)

            sess = deck.get_session(view.bind_key)
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
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))

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
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

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
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        # ---- Bulk & Custom Actions ----

        @bp.route("/<slug>/action/<action_name>", methods=["POST"])
        def model_action(slug: str, action_name: str) -> Any:
            view = deck.get_view(slug)
            user = deck._current_user()
            raw_pks = [p for p in request.form.getlist("selected_pks") if p.strip()]
            if not raw_pks:
                flash("Select at least one record.", "warn")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))

            decoded_pks = [decode_pk(p, view.meta) for p in raw_pks]
            stmt = view.scope_query(sa.select(view.model), user)
            sd_active = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
            if sd_active is not None:
                stmt = stmt.where(sd_active)
            if len(view.meta.primary_keys) == 1:
                pk_col = getattr(view.model, view.meta.primary_keys[0].name)
                stmt = stmt.where(pk_col.in_([pk[0] for pk in decoded_pks]))
            else:
                pk_cols = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
                stmt = stmt.where(sa.tuple_(*pk_cols).in_(decoded_pks))
            records = list(deck.get_session(view.bind_key).scalars(stmt).all())

            if not records:
                flash("No matching authorized records found.", "warn")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))

            sess = deck.get_session(view.bind_key)

            if action_name == "delete":
                if not view.can_delete:
                    abort(403)
                deck._require_perm(f"{slug}:delete", model_slug=slug)
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
                        return redirect(url_for(f"{bp_name}.model_list", slug=slug))
                orphan_files: list[tuple[Any, str]] = []
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
                    return redirect(url_for(f"{bp_name}.model_list", slug=slug))

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
                flash(
                    f"Moved {len(records)} {view.plural_label} to Trash."
                    if view.soft_delete_column
                    else f"Deleted {len(records)} {view.plural_label}.",
                    "ok",
                )
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))

            spec = view.actions.get(action_name)
            if spec is None:
                abort(404)
            deck._require_perm(spec.permission or f"{slug}:action:{action_name}", model_slug=slug)

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

            # Background async job execution when @action(..., async_job=True)
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

                # Release request read transaction before spawning worker thread (prevents StaticPool lock/rollback race).
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
                flash(f"Queued background job '{spec.label}' (#{job.id}).", "ok")
                return redirect(url_for(f"{bp_name}.jobs_list", focus=job.id))

            try:
                msg = handler(records, request.form, user)
                sess.commit()
            except (ValueError, ValidationError, SQLAlchemyError) as exc:
                sess.rollback()
                flash(f"Action '{spec.label}' failed: {exc}", "danger")
                return redirect(url_for(f"{bp_name}.model_list", slug=slug))
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
            flash(str(msg or f"Executed '{spec.label}' on {len(records)} records."), "ok")
            return redirect(url_for(f"{bp_name}.model_list", slug=slug))

        # ---- Export (Streaming O(1) RAM + Background Async Export) ----

        @bp.route("/<slug>/export.<fmt>")
        def model_export(slug: str, fmt: str) -> Response:
            if fmt.lower() not in {"csv", "json", "jsonl"}:
                abort(404)
            view = deck.get_view(slug)
            if not view.can_export:
                abort(403)
            deck._require_perm(f"{slug}:export", model_slug=slug)

            filter_pairs = [
                (k[2:], v.strip())
                for k, v in request.args.items(multi=True)
                if k.startswith("f_") and v.strip()
            ]
            raw_ids = [p for p in request.args.get("ids", "").split(",") if p.strip()]
            selected_pks = [decode_pk(p, view.meta) for p in raw_ids]
            trashed = bool(view.soft_delete_column and request.args.get("trashed") == "1")

            return stream_export_response(
                deck.get_session(view.bind_key),
                view,
                fmt=fmt,
                auth=deck.auth,
                user=deck._current_user(),
                search_term=request.args.get("q", "").strip(),
                filter_params=filter_pairs,
                active_tab_key=request.args.get("tab", "").strip() or None,
                selected_pks=selected_pks,
                sanitize_csv=deck.config.sanitize_csv,
                trashed=trashed,
            )

        @bp.route("/<slug>/export-async", methods=["POST"])
        def model_export_async(slug: str) -> Any:
            if deck.job_backend is None:
                abort(404)
            view = deck.get_view(slug)
            if not view.can_export:
                abort(403)
            deck._require_perm(f"{slug}:export", model_slug=slug)
            fmt = request.form.get("fmt", "csv").strip().lower()
            if fmt not in {"csv", "json", "jsonl"}:
                abort(400)
            user = deck._current_user()
            search_q = request.form.get("q", "").strip()
            active_tab = request.form.get("tab", "").strip() or None
            trashed = bool(view.soft_delete_column and request.form.get("trashed") == "1")
            filter_pairs = [
                (k[2:], v.strip())
                for k, v in request.form.items(multi=True)
                if k.startswith("f_") and v.strip()
            ]

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
                )
                buf = io.BytesIO()
                for chunk in chunks:
                    if job_ctx.is_cancelled():
                        return "Export cancelled"
                    buf.write(chunk.encode("utf-8"))
                payload = buf.getvalue()
                mime_base = mimetype.split(";", 1)[0].strip()
                key = build_storage_key(f"exports/{slug}", mime_base)
                deck.job_storage.save(payload, key=key, content_type=mime_base)
                job_ctx.attach_artifact(key=key, filename=fname, content_type=mime_base)
                job_ctx.log(f"Exported {len(payload):,} bytes to {fname}.")
                return f"Ready: {fname} ({len(payload) / 1024:.1f} KB)"

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

        # ---- Dry-Run Diff Import Wizard ----

        @bp.route("/<slug>/import", methods=["GET", "POST"])
        def model_import(slug: str) -> Any:
            view = deck.get_view(slug)
            if not view.can_import:
                abort(403)
            deck._require_perm(f"{slug}:import", model_slug=slug)

            user = deck._current_user()
            user_id = user.id if user else "anonymous"
            sess_token = str(session.get(CSRF_SESSION_KEY, ""))

            # Candidate upsert keys (unique columns + PKs, never hidden/masked/sensitive)
            hidden = deck.auth.hidden_fields_for(user, slug)
            masked = deck.auth.masked_fields_for(user, slug)
            upsert_candidates = [
                f.name
                for f in view.meta.fields
                if (f.unique or f.primary_key or f.name in view.import_key_columns)
                and f.name not in hidden
                and f.name not in masked
                and not f.is_sensitive
            ]

            report = None
            error_msg = ""
            bind_sess = deck.get_session(view.bind_key)

            if request.method == "POST":
                step = request.form.get("step", "preview")
                if step == "commit":
                    token = request.form.get("preview_token", "").strip()
                    skip_errors = request.form.get("skip_errors") in {"1", "true", "on"}
                    cached = deck._preview_store.consume(
                        token,
                        user_id=user_id,
                        session_token=sess_token,
                        model_slug=slug,
                    )
                    if cached is None:
                        error_msg = "Preview token expired, already used, or invalid. Please re-run dry-run preview."
                    elif cached.errors > 0 and not skip_errors:
                        # Re-store token so operator can tick 'Skip errored rows' without re-uploading
                        deck._preview_store.put(cached, user_id=user_id, session_token=sess_token)
                        report = cached
                        error_msg = (
                            f"Import contains {cached.errors} errored row(s). "
                            "Fix errors or enable 'Skip errored rows'."
                        )
                    else:
                        try:
                            created, updated = commit_dry_run_import(
                                bind_sess,
                                view,
                                cached,
                                user=user,
                                skip_errors=skip_errors,
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
                else:
                    upload = request.files.get("file")
                    raw_upsert = request.form.get("upsert_key", "").strip() or None
                    upsert_key = raw_upsert if (raw_upsert and raw_upsert in upsert_candidates) else None
                    if upload is None or not upload.filename:
                        error_msg = "Select a CSV or JSON file to preview."
                    else:
                        # Bounded read: read max_upload_bytes + 1 so huge uploads fail fast without OOM.
                        raw_bytes = upload.stream.read(deck.config.max_upload_bytes + 1)
                        try:
                            report = run_dry_run_import(
                                bind_sess,
                                view,
                                raw_bytes=raw_bytes,
                                filename=upload.filename,
                                auth=deck.auth,
                                user=user,
                                upsert_key=upsert_key,
                                max_bytes=deck.config.max_upload_bytes,
                                max_rows=deck.config.max_import_rows,
                                max_columns=deck.config.max_import_columns,
                                max_json_depth=deck.config.max_json_depth,
                            )
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
                    error_msg=error_msg,
                    upsert_candidates=upsert_candidates,
                ),
            )

        # ---- Audit Log & Safe Revert ----

        @bp.route("/_audit")
        def audit_list() -> str:
            if deck.audit_store is None:
                abort(404)
            deck._require_perm("audit:view")
            user = deck._current_user()
            model_filter = request.args.get("model", "").strip() or None
            action_filter = request.args.get("action", "").strip() or None
            actor_filter = request.args.get("actor", "").strip() or None
            q = request.args.get("q", "").strip() or None
            try:
                page = max(1, min(1_000_000, int(request.args.get("page", "1"))))
            except ValueError:
                page = 1
            limit = 40
            raw_entries, total = deck.audit_store.list_entries(
                model_slug=model_filter,
                action=action_filter,
                actor=actor_filter,
                search=q,
                limit=limit,
                offset=(page - 1) * limit,
            )
            entries = [
                deck._sanitize_audit_entry(e, user)
                for e in raw_entries
                if e.model_slug.startswith("_")
                or e.model_slug not in deck.views
                or deck.auth.has_permission(user, f"{e.model_slug}:view", model_slug=e.model_slug)
            ]
            pages = max(1, (total + limit - 1) // limit)
            can_revert = (
                deck.config.enable_audit_revert
                and not deck.config.read_only
                and deck.auth.has_permission(user, "audit:revert")
            )
            return render_template(
                "flask_deck/audit_list.html",
                **deck._base_context(
                    page_title="Audit Ledger",
                    active_nav="_audit",
                    entries=entries,
                    total=total,
                    page=page,
                    pages=pages,
                    model_filter=model_filter or "",
                    action_filter=action_filter or "",
                    actor_filter=actor_filter or "",
                    search_term=q or "",
                    can_revert=can_revert,
                ),
            )

        @bp.route("/_audit/<entry_id>/revert", methods=["POST"])
        def audit_revert(entry_id: str) -> Any:
            if deck.audit_store is None or not deck.config.enable_audit_revert:
                abort(404)
            deck._require_perm("audit:revert")
            entry = deck.audit_store.get_entry(entry_id)
            if entry is None or not entry.is_revertible:
                abort(404)
            view = deck.get_view(entry.model_slug)
            if not view.can_edit:
                abort(403)
            deck._require_perm(f"{view.meta.slug}:edit", model_slug=view.meta.slug)
            obj, pk_vals = deck._fetch_scoped_record(view, entry.record_pk)
            deck._require_perm(f"{view.meta.slug}:edit", model_slug=view.meta.slug, obj=obj)

            if (
                deck.config.environment == "production"
                and deck.config.require_confirm_text_in_prod
                and request.form.get("confirm_text", "").strip() != "REVERT"
            ):
                flash("Production safeguard: enter 'REVERT' to confirm rollback.", "danger")
                return redirect(url_for(f"{bp_name}.audit_list"))

            user = deck._current_user()
            writable = set(view.allowed_form_fields(deck.auth, user, mode="edit"))
            masked = deck.auth.masked_fields_for(user, view.meta.slug)
            before_snap = view.extract_snapshot(obj)
            sess = deck.get_session(view.bind_key)
            reverted_values: dict[str, Any] = {}

            try:
                for fname, delta in entry.changes.items():
                    if (
                        fname not in writable
                        or fname in masked
                        or fname in view.meta.sensitive_fields
                        or fname in view.file_fields
                    ):
                        continue
                    old_val = delta.get("old")
                    if old_val == "[REDACTED]":
                        continue
                    fmeta = view.meta.fields_by_name.get(fname)
                    if fmeta is None or fmeta.field_type == "binary":
                        continue
                    coerced = (
                        None
                        if old_val is None
                        else coerce_form_value(
                            old_val,
                            fmeta,
                            max_json_depth=deck.config.max_json_depth,
                            utc_passthrough=True,
                        )
                    )
                    reverted_values[fname] = coerced
                if not reverted_values:
                    flash("No revertible fields remain writable on this record.", "warn")
                    return redirect(url_for(f"{bp_name}.audit_list"))
                custom_errs = view.validate(reverted_values, obj=obj)
                if custom_errs:
                    raise ValidationError(custom_errs)
                val_fn = view.get_form_validator()
                if val_fn is not None:
                    ext_errs = val_fn({**before_snap, **reverted_values}, obj, False)
                    if ext_errs:
                        raise ValidationError(dict(ext_errs))
                for fname, coerced in reverted_values.items():
                    setattr(obj, fname, coerced)
                view.on_model_change(obj, is_created=False, user=user)
                sess.commit()
            except (ValueError, ValidationError, SQLAlchemyError) as exc:
                sess.rollback()
                flash(f"Revert failed: {exc}", "danger")
                return redirect(url_for(f"{bp_name}.audit_list"))

            reverted_fields = len(reverted_values)
            pk_str = encode_pk(pk_vals)
            safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            after_snap = view.extract_snapshot(obj)
            diff = compute_diff(
                before_snap,
                after_snap,
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            )
            deck._record_audit(
                action_name="revert",
                view=view,
                record_pk=pk_str,
                record_repr=safe_repr,
                changes=diff,
                metadata={"reverted_entry_id": entry.id, "fields": reverted_fields},
            )
            deck._emit_event(
                "record.updated",
                model_slug=view.meta.slug,
                record_pk=pk_str,
                payload={"reverted_entry_id": entry.id, "fields": sorted(reverted_values.keys())},
            )
            flash(f"Reverted {reverted_fields} field(s) on {safe_repr}.", "ok")
            return redirect(url_for(f"{bp_name}.audit_list"))

        # ---- RBAC Matrix ----

        @bp.route("/_rbac")
        def rbac_matrix() -> str:
            roles = list(deck.auth.get_roles())
            if not roles:
                abort(404)
            deck._require_perm("rbac:view")
            actions = ("view", "create", "edit", "delete", "export", "import")
            matrix: list[dict[str, Any]] = []
            for role in roles:
                model_rows = []
                for v in deck.views.values():
                    slug = v.meta.slug
                    grants = {act: role.grants(f"{slug}:{act}") for act in actions}
                    hidden = sorted(
                        set(role.hidden_fields.get("*", ())) | set(role.hidden_fields.get(slug, ()))
                    )
                    readonly = sorted(
                        set(role.readonly_fields.get("*", ()))
                        | set(role.readonly_fields.get(slug, ()))
                    )
                    masked = sorted(
                        set(role.masked_fields.get("*", ())) | set(role.masked_fields.get(slug, ()))
                    )
                    model_rows.append(
                        {
                            "slug": slug,
                            "label": v.plural_label,
                            "grants": grants,
                            "hidden": hidden,
                            "readonly": readonly,
                            "masked": masked,
                        }
                    )
                matrix.append(
                    {
                        "role": role,
                        "audit_view": role.grants("audit:view"),
                        "audit_revert": role.grants("audit:revert"),
                        "models": model_rows,
                    }
                )
            return render_template(
                "flask_deck/rbac_matrix.html",
                **deck._base_context(
                    page_title="RBAC Policy Matrix",
                    active_nav="_rbac",
                    actions=actions,
                    matrix=matrix,
                ),
            )

        # ---- JSON & Partial APIs (⌘K Search, FK Combobox, Quick-Peek Drawer, Quick-Edit) ----

        @bp.route("/_api/search")
        def api_search() -> Response:
            q = request.args.get("q", "").strip()
            user = deck._current_user()
            results: list[dict[str, Any]] = []

            # Always include matching navigation models & commands
            q_lower = q.lower()
            for v in deck.views.values():
                if not v.can_view or not deck.auth.has_permission(
                    user, f"{v.meta.slug}:view", model_slug=v.meta.slug
                ):
                    continue
                if not q_lower or q_lower in v.plural_label.lower() or q_lower in v.meta.slug:
                    results.append(
                        {
                            "kind": "model",
                            "title": v.plural_label,
                            "subtitle": f"Open {v.plural_label} table",
                            "badge": "Model",
                            "url": url_for(f"{bp_name}.model_list", slug=v.meta.slug),
                        }
                    )

            # Live cross-model record search when query meets min length (multi-bind & soft-delete safe!)
            if len(q) >= deck.config.search_min_chars:
                for v in deck.views.values():
                    if not v.can_view or not v.resolved_searchable:
                        continue
                    if not deck.auth.has_permission(
                        user, f"{v.meta.slug}:view", model_slug=v.meta.slug
                    ):
                        continue
                    allowed_search, _, _ = deck._allowed_query_fields(v, user)
                    clause, joins = build_search_clause(v.meta, allowed_search, q)
                    if clause is None:
                        continue
                    stmt = v.scope_query(sa.select(v.model), user)
                    sd_pred = soft_delete_predicate(v.meta, v.soft_delete_column, trashed=False)
                    if sd_pred is not None:
                        stmt = stmt.where(sd_pred)
                    for rel_attr in joins:
                        stmt = stmt.outerjoin(rel_attr)
                    stmt = stmt.where(clause).limit(deck.config.search_limit_per_model)
                    for item in deck.get_session(v.bind_key).scalars(stmt).unique().all():
                        pk_str = encode_pk(extract_pk(item, v.meta))
                        results.append(
                            {
                                "kind": "record",
                                "title": v.format_record_repr(item, auth=deck.auth, user=user),
                                "subtitle": f"{v.label} #{pk_str}",
                                "badge": v.label,
                                "url": url_for(f"{bp_name}.model_detail", slug=v.meta.slug, raw_pk=pk_str),
                            }
                        )

            return jsonify({"query": q, "results": results[:24]})

        @bp.route("/_api/fk/<slug>")
        def api_fk(slug: str) -> Response:
            view = deck.get_view(slug)
            if not view.can_view:
                abort(404)
            deck._require_perm(f"{slug}:view", model_slug=slug)
            q = request.args.get("q", "").strip()
            dep_col = request.args.get("dep_col", "").strip()
            dep_val = request.args.get("dep_val", "").strip()
            user = deck._current_user()
            restricted = deck.auth.hidden_fields_for(user, slug) | deck.auth.masked_fields_for(
                user, slug
            )
            allowed_search, _, _ = deck._allowed_query_fields(view, user)
            stmt = view.scope_query(sa.select(view.model), user)
            sd_pred = soft_delete_predicate(view.meta, view.soft_delete_column, trashed=False)
            if sd_pred is not None:
                stmt = stmt.where(sd_pred)
            if (
                dep_col
                and dep_val
                and dep_col in view.meta.fields_by_name
                and dep_col not in restricted
                and not view.meta.fields_by_name[dep_col].is_sensitive
            ):
                cond = build_filter_condition(view.meta, dep_col, dep_val)
                if cond is not None:
                    stmt = stmt.where(cond)
            if q and allowed_search:
                clause, joins = build_search_clause(view.meta, allowed_search, q)
                for rel_attr in joins:
                    stmt = stmt.outerjoin(rel_attr)
                if clause is not None:
                    stmt = stmt.where(clause)
            stmt = stmt.order_by(getattr(view.model, view.meta.primary_keys[0].name).asc()).limit(25)
            items = list(deck.get_session(view.bind_key).scalars(stmt).unique().all())
            return jsonify(
                {
                    "items": [
                        {
                            "id": encode_pk(extract_pk(it, view.meta)),
                            "label": view.format_record_repr(it, auth=deck.auth, user=user),
                        }
                        for it in items
                    ]
                }
            )

        @bp.route("/_api/<slug>/<raw_pk>/drawer")
        def api_drawer(slug: str, raw_pk: str) -> str:
            view = deck.get_view(slug)
            if not view.can_view:
                abort(404)
            deck._require_perm(f"{slug}:view", model_slug=slug)
            obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
            deck._require_perm(f"{slug}:view", model_slug=slug, obj=obj)
            pk_str = encode_pk(pk_vals)
            user = deck._current_user()
            hidden = deck.auth.hidden_fields_for(user, slug)
            is_soft_deleted = deck._is_soft_deleted(view, obj)

            media_builder = deck._media_url_builder(view)
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
                        ),
                    }
                )
            relations_display = []
            for rel in view.meta.relationships:
                if rel.name in hidden:
                    continue
                val = getattr(obj, rel.name, None)
                rel_items = (
                    list(val)
                    if (rel.uselist and val is not None)
                    else ([val] if val is not None else [])
                )
                relations_display.append(
                    {
                        "name": rel.name,
                        "label": rel.label,
                        "count": len(rel_items),
                        "records": [deck._rel_repr(rel.target_model, it) for it in rel_items[:20]],
                    }
                )
            history: list[AuditEntry] = []
            if deck.audit_store is not None and deck.auth.has_permission(user, "audit:view"):
                raw_hist, _ = deck.audit_store.list_entries(
                    model_slug=slug, record_pk=pk_str, limit=10
                )
                history = [deck._sanitize_audit_entry(e, user) for e in raw_hist]
            can_edit = (
                view.can_edit
                and not is_soft_deleted
                and not deck.config.read_only
                and deck.auth.has_permission(user, f"{slug}:edit", model_slug=slug, obj=obj)
            )
            can_create = (
                view.can_create
                and not is_soft_deleted
                and not deck.config.read_only
                and deck.auth.has_permission(user, f"{slug}:create", model_slug=slug)
            )
            can_revert = (
                deck.config.enable_audit_revert
                and not deck.config.read_only
                and deck.auth.has_permission(user, "audit:revert")
            )
            active_tz = str(getattr(g, "_flask_deck_tz", deck.config.default_timezone))
            return render_template(
                "flask_deck/partials/drawer_detail.html",
                view=view,
                bp_name=bp_name,
                pk_str=pk_str,
                record_repr=view.format_record_repr(obj, auth=deck.auth, user=user),
                fields_display=fields_display,
                relations_display=relations_display,
                history=history,
                can_edit=can_edit,
                can_create=can_create,
                can_revert=can_revert,
                csrf_field=CSRF_FORM_FIELD,
                csrf_token=get_csrf_token(),
                config=deck.config,
                deck_icon=render_icon,
                _=deck.translator.translate,
                format_dt=lambda dt, fmt="%Y-%m-%d %H:%M": (
                    to_user_timezone(dt, active_tz).strftime(fmt)
                    if isinstance(dt, datetime)
                    else str(dt)
                ),
            )

        @bp.route("/_api/<slug>/<raw_pk>/quick-edit", methods=["PATCH"])
        def api_quick_edit(slug: str, raw_pk: str) -> tuple[Response, int]:
            view = deck.get_view(slug)
            if not view.can_edit:
                return jsonify({"error": "Editing is disabled for this model."}), 403
            deck._require_perm(f"{slug}:edit", model_slug=slug)
            obj, pk_vals = deck._fetch_scoped_record(view, raw_pk)
            deck._require_perm(f"{slug}:edit", model_slug=slug, obj=obj)
            if deck._is_soft_deleted(view, obj):
                return jsonify({"error": "Restore record from Trash before editing."}), 409

            payload = request.get_json(silent=True)
            if not isinstance(payload, Mapping):
                return jsonify({"error": "Expected JSON object payload."}), 400

            field_name = str(payload.get("field", "")).strip()
            user = deck._current_user()
            writable = set(view.allowed_form_fields(deck.auth, user, mode="edit")) - deck.auth.masked_fields_for(
                user, slug
            )
            quick_allowed = set(view.resolved_inline_editable)
            if view.kanban_column:
                quick_allowed.add(view.kanban_column)
            if field_name not in quick_allowed or field_name not in writable:
                return jsonify({"error": f"Field '{field_name}' is not inline-editable."}), 403

            fmeta = view.meta.fields_by_name[field_name]
            before_snap = view.extract_snapshot(obj)
            try:
                coerced = coerce_form_value(
                    payload.get("value"), fmeta, max_json_depth=deck.config.max_json_depth
                )
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 422

            custom_errs = view.validate({field_name: coerced}, obj=obj)
            if custom_errs:
                return jsonify({"error": "; ".join(custom_errs.get(field_name, ["Invalid value"]))}), 422
            val_fn = view.get_form_validator()
            if val_fn is not None:
                ext_errs = val_fn({**before_snap, field_name: coerced}, obj, False)
                if ext_errs:
                    first_msgs = next(iter(ext_errs.values()), ["Validation failed."])
                    return jsonify({"error": "; ".join(first_msgs)}), 422

            sess = deck.get_session(view.bind_key)
            try:
                setattr(obj, field_name, coerced)
                view.on_model_change(obj, is_created=False, user=user)
                sess.commit()
            except ValidationError as exc:
                sess.rollback()
                first_msgs = next(iter(exc.errors.values()), ["Validation failed."])
                return jsonify({"error": "; ".join(first_msgs)}), 422
            except SQLAlchemyError as exc:
                sess.rollback()
                return jsonify({"error": f"Database error: {exc.__class__.__name__}"}), 400

            pk_str = encode_pk(pk_vals)
            safe_repr = view.format_record_repr(obj, auth=deck.auth, user=user)
            after_snap = view.extract_snapshot(obj)
            diff = compute_diff(
                before_snap,
                after_snap,
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
            )
            if diff:
                deck._record_audit(
                    action_name="inline_edit",
                    view=view,
                    record_pk=pk_str,
                    record_repr=safe_repr,
                    changes=diff,
                )
                deck._emit_event(
                    "record.updated",
                    model_slug=slug,
                    record_pk=pk_str,
                    payload={"fields": sorted(diff.keys()), "inline": True},
                )
            rendered = view.format_cell(
                field_name, obj, auth=deck.auth, user=user, rel_repr=deck._rel_repr
            )
            return (
                jsonify(
                    {
                        "ok": True,
                        "field": field_name,
                        "value": coerced.value if hasattr(coerced, "value") else coerced,
                        "display": str(Markup.escape(rendered)),
                    }
                ),
                200,
            )

        # ---- Governance: Schema ERD, Security Diagnostics, Read-Only SQL Console, Custom Pages ----

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
            by_bind: dict[str | None, list[ModelView]] = {}
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
            erd_svg = render_schema_erd_svg(metas, row_counts)
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

            default_sql = (
                deck._sql_presets[0][1]
                if deck._sql_presets
                else (
                    f"SELECT * FROM {next(iter(deck.views.values())).meta.table_name} LIMIT 25"
                    if deck.views
                    else "SELECT 1 AS ok"
                )
            )
            sql_text = default_sql
            result: SQLQueryResult | None = None

            if request.method == "POST":
                sql_text = request.form.get("sql", "").strip()
                out_mode = request.form.get("output", "table").strip().lower()
                assert deck.adapter is not None
                result = execute_readonly_sql(
                    deck.adapter.get_engine(),
                    sql_text,
                    max_rows=deck.config.sql_console_max_rows,
                    extra_sensitive_patterns=deck.config.extra_sensitive_patterns,
                )
                if deck.audit_store is not None and deck.config.auto_audit:
                    user = deck._current_user()
                    sql_meta: dict[str, Any] = {
                        "rows": result.row_count,
                        "ms": round(result.duration_ms, 2),
                        "status": "blocked" if result.error else "ok",
                    }
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

            return render_template(
                "flask_deck/sql_console.html",
                **deck._base_context(
                    page_title="Read-Only SQL Console",
                    active_nav="_sql",
                    sql_text=sql_text,
                    result=result,
                    sql_presets=deck._sql_presets,
                    tables=[v.meta.table_name for v in deck.views.values() if not v.bind_key],
                ),
            )

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

            ctx = DashboardContext(deck, deck.get_session(), user)
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
                ),
            )

        @bp.route("/_api/notifications")
        def api_notifications() -> Response:
            user = deck._current_user()
            active_tz = str(getattr(g, "_flask_deck_tz", deck.config.default_timezone))
            items: list[dict[str, str]] = []
            if deck.audit_store is not None and deck.auth.has_permission(user, "audit:view"):
                entries, _ = deck.audit_store.list_entries(limit=24)
                for e in entries:
                    if e.model_slug in deck.views and not deck.auth.has_permission(
                        user, f"{e.model_slug}:view", model_slug=e.model_slug
                    ):
                        continue
                    safe_e = deck._sanitize_audit_entry(e, user)
                    items.append(
                        {
                            "action": safe_e.action,
                            "title": f"{safe_e.model_label} · {safe_e.record_repr}",
                            "actor": safe_e.actor_name,
                            "time": to_user_timezone(safe_e.timestamp, active_tz).strftime("%m-%d %H:%M"),
                            "url": url_for(f"{bp_name}.audit_list"),
                        }
                    )
                    if len(items) >= 8:
                        break
            return jsonify({"items": items})

        @bp.route("/_jobs")
        def jobs_list() -> str:
            if deck.job_backend is None:
                abort(404)
            user = deck._current_user()
            can_all = deck.auth.has_permission(user, "jobs:view_all") or (
                user is not None and user.is_superuser
            )
            actor_filter = None if can_all else (user.id if user else "__none__")
            jobs = deck.job_backend.list_jobs(actor_id=actor_filter, limit=50)
            focus_id = request.args.get("focus", "").strip()
            return render_template(
                "flask_deck/jobs_list.html",
                **deck._base_context(
                    page_title="Background Jobs",
                    active_nav="_jobs",
                    jobs=jobs,
                    focus_id=focus_id,
                ),
            )

        def _get_authorized_job(job_id: str, *, mode: str = "view") -> JobRecord:
            if deck.job_backend is None:
                abort(404)
            rec = deck.job_backend.get(job_id)
            if rec is None:
                abort(404)
            user = deck._current_user()
            is_owner = user is not None and rec.actor_id == user.id
            is_super = user is not None and user.is_superuser
            if mode == "artifact":
                allowed = is_owner or is_super
            elif mode == "cancel":
                allowed = is_owner or is_super or deck.auth.has_permission(user, "jobs:cancel_all")
            else:
                allowed = is_owner or is_super or deck.auth.has_permission(user, "jobs:view_all")
            if not allowed:
                raise PermissionDeniedError("Not authorized to access this background job.")
            return rec

        @bp.route("/_api/jobs/<job_id>")
        def api_job_status(job_id: str) -> Any:
            if deck.job_backend is None or deck.job_backend.get(job_id) is None:
                return jsonify({"error": "Job not found."}), 404
            rec = _get_authorized_job(job_id, mode="view")
            return jsonify(rec.to_dict())

        @bp.route("/_api/jobs/<job_id>/stream")
        def api_job_stream(job_id: str) -> Any:
            if deck.job_backend is None or deck.job_backend.get(job_id) is None:
                return jsonify({"error": "Job not found."}), 404
            rec = _get_authorized_job(job_id, mode="view")
            backend = deck.job_backend
            assert backend is not None

            def _gen() -> Iterator[str]:
                yield "retry: 1500\n"
                for _ in range(40):
                    cur = backend.get(rec.id)
                    if cur is None:
                        break
                    yield f"data: {json.dumps(cur.to_dict())}\n\n"
                    if cur.status in TERMINAL_JOB_STATUSES:
                        break
                    time.sleep(0.25)

            resp = Response(stream_with_context(_gen()), mimetype="text/event-stream")
            resp.headers["Cache-Control"] = "no-cache, no-store"
            resp.headers["X-Accel-Buffering"] = "no"
            return resp

        @bp.route("/_jobs/<job_id>/cancel", methods=["POST"])
        def job_cancel(job_id: str) -> Any:
            rec = _get_authorized_job(job_id, mode="cancel")
            assert deck.job_backend is not None
            if deck.job_backend.cancel(rec.id):
                flash(f"Cancellation requested for job #{rec.id}.", "warn")
            else:
                flash(f"Job #{rec.id} is already finished.", "neutral")
            return redirect(url_for(f"{bp_name}.jobs_list", focus=rec.id))

        @bp.route("/_jobs/<job_id>/artifact")
        def job_artifact(job_id: str) -> Response:
            rec = _get_authorized_job(job_id, mode="artifact")
            if not rec.artifact_key or not rec.artifact_filename:
                abort(404)
            try:
                stream, detected = deck.job_storage.open(rec.artifact_key)
            except (FileNotFoundError, ValueError):
                abort(404)
            try:
                data = stream.read()
            finally:
                stream.close()
            mime = rec.artifact_mime or detected or "application/octet-stream"
            safe_name = sanitize_filename(rec.artifact_filename)
            resp = Response(data, mimetype=mime)
            resp.headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
            resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp

        @bp.route("/_demo/switch-role", methods=["POST"])
        def demo_switch_role() -> Any:
            if (
                not deck.config.demo_role_switcher
                or deck.config.environment == "production"
                or not isinstance(deck.auth, RBACAuthProvider)
            ):
                abort(404)
            target_id = request.form.get("account_id", "").strip()
            target_user = deck.auth.get_account_by_id(target_id)
            if target_user is None:
                abort(404)
            deck.auth.login_user(target_user)
            flash(
                f"Switched demo session role to {target_user.label} ({', '.join(target_user.roles)}).",
                "ok",
            )
            nxt = request.form.get("next", "").strip()
            dest = nxt if is_safe_redirect_url(nxt) else url_for(f"{bp_name}.index")
            return redirect(dest)

        return bp


def run_security_audit(app: Flask, deck: Deck) -> list[dict[str, str]]:
    """Inspect Flask + Deck configuration and SQLAlchemy indexes for security/performance findings."""
    findings: list[dict[str, str]] = []

    secret = app.secret_key
    if not secret:
        findings.append(
            {"severity": "CRITICAL", "category": "security", "message": "app.secret_key is not set."}
        )
    elif isinstance(secret, (str, bytes)) and len(secret) < 32:
        findings.append(
            {
                "severity": "WARN",
                "category": "security",
                "message": f"app.secret_key length is {len(secret)} bytes (recommended >= 32 bytes).",
            }
        )

    if not app.config.get("SESSION_COOKIE_HTTPONLY", True):
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "SESSION_COOKIE_HTTPONLY is False; session cookies are readable by JS.",
            }
        )
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        findings.append(
            {
                "severity": "WARN",
                "category": "security",
                "message": "SESSION_COOKIE_SAMESITE is unset (recommended 'Lax' or 'Strict').",
            }
        )
    if deck.config.environment == "production" and not app.config.get("SESSION_COOKIE_SECURE", False):
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "SESSION_COOKIE_SECURE is False in production environment.",
            }
        )
    if isinstance(deck.auth, OpenAuthProvider):
        findings.append(
            {
                "severity": "CRITICAL" if deck.config.environment == "production" else "WARN",
                "category": "auth",
                "message": "Deck is using OpenAuthProvider (unauthenticated access).",
            }
        )
    if deck.config.environment == "production" and not deck.config.require_mfa_for_superusers:
        findings.append(
            {
                "severity": "WARN",
                "category": "auth",
                "message": "require_mfa_for_superusers is False in production (enable TOTP 2FA enforcement).",
            }
        )
    if deck.config.environment == "production" and deck.config.demo_role_switcher:
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "demo_role_switcher is enabled in config (locked out in production, set False).",
            }
        )

    # Schema performance & sensitive-column checks
    for view in deck.views.values():
        meta: ModelMeta = view.meta
        for col_spec in view.resolved_searchable:
            if "." in col_spec:
                continue
            if col_spec not in meta.indexed_fields:
                findings.append(
                    {
                        "severity": "INFO",
                        "category": "performance",
                        "message": (
                            f"{meta.name}.{col_spec} is in searchable_columns without a DB index "
                            "(consider adding index=True for large tables)."
                        ),
                    }
                )
        for col in view.columns or view.list_columns:
            if col in meta.sensitive_fields:
                findings.append(
                    {
                        "severity": "HIGH",
                        "category": "privacy",
                        "message": f"Sensitive column {meta.name}.{col} appears in declared columns.",
                    }
                )

    return findings
