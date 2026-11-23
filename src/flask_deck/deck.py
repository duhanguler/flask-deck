from __future__ import annotations

import enum
import hashlib
import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    flash,
    g,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from werkzeug.datastructures import MultiDict

from flask_deck._version import SHORT_VERSION, __version__
from flask_deck.adapters.sqlalchemy import (
    ORMAdapter,
    decode_pk,
    encode_pk,
    extract_pk,
    resolve_adapter,
)
from flask_deck.api_keys import (
    APIKeyRecord,
    APIKeyStore,
    InMemoryAPIKeyStore,
    SQLAlchemyAPIKeyStore,
    api_key_allows,
    api_key_to_user,
)
from flask_deck.approvals import (
    ApprovalRequest,
    ApprovalStore,
    InMemoryApprovalStore,
    SQLAlchemyApprovalStore,
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
    DashboardBuilder,
    DashboardContext,
    Widget,
)
from flask_deck.diagnostics import run_security_audit
from flask_deck.events import (
    DeckEvent,
    DeckEventBus,
    EventListener,
    InMemoryWebhookDeliveryStore,
    SQLAlchemyWebhookDeliveryStore,
    WebhookDeliveryStore,
    WebhookSink,
)
from flask_deck.exceptions import (
    InvalidPKError,
    PermissionDeniedError,
    ReadOnlyError,
    SecurityConfigurationError,
)
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
from flask_deck.importer import ImportPreviewStore, PreviewStore, SQLAlchemyPreviewStore
from flask_deck.jobs import (
    JobBackend,
    JobCallable,
    JobContext,
    JobRecord,
    ScheduledJobSpec,
    SQLAlchemyJobBackend,
    ThreadPoolJobBackend,
)
from flask_deck.mfa import (
    MFA_PENDING_AT_KEY,
    MFA_PENDING_USER_KEY,
    MFA_VERIFIED_KEY,
    InMemoryMFAStore,
    MFAStore,
    SQLAlchemyMFAStore,
)
from flask_deck.model_view import ModelView
from flask_deck.passkeys import (
    InMemoryPasskeyStore,
    PasskeyStore,
    SQLAlchemyPasskeyStore,
    is_webauthn_available,
)
from flask_deck.query import (
    apply_list_load_options,
    attach_sql_telemetry,
    begin_request_telemetry,
    estimate_table_rows,
    get_request_telemetry,
    soft_delete_predicate,
)
from flask_deck.routes import register_all_routes
from flask_deck.saved_views import (
    InMemoryRecordNoteStore,
    InMemorySavedViewStore,
    RecordNoteStore,
    SavedViewStore,
    SQLAlchemyRecordNoteStore,
    SQLAlchemySavedViewStore,
)
from flask_deck.security import (
    CSRF_FORM_FIELD,
    LoginRateLimiter,
    RateLimitStore,
    SQLAlchemyRateLimitStore,
    apply_security_headers,
    check_origin_headers,
    generate_nonce,
    get_csrf_token,
    is_safe_redirect_url,
    is_sensitive_field,
    rotate_csrf_token,
    validate_csrf,
)
from flask_deck.sessions import (
    DECK_SID_SESSION_KEY,
    InMemorySessionStore,
    SessionStore,
    SQLAlchemySessionStore,
)
from flask_deck.sql_console import (
    InMemorySavedQueryStore,
    SavedQueryStore,
    SQLAlchemySavedQueryStore,
)
from flask_deck.sso import OIDCAuthProvider
from flask_deck.storage import (
    MemoryFileStorage,
    StorageBackend,
)
from flask_deck.widgets import FormWidget

IMPERSONATOR_USER_KEY = "_deck_impersonator_id"
IMPERSONATED_USER_KEY = "_deck_impersonated_id"
IMPERSONATE_RO_KEY = "_deck_impersonate_ro"
MFA_SETUP_SECRET_KEY = "_deck_mfa_setup_secret"
MFA_PENDING_TTL_SECONDS = 300
_RESERVED_MODEL_SLUGS: frozenset[str] = frozenset(
    {
        "login",
        "logout",
        "static",
        "_approvals",
        "_audit",
        "_rbac",
        "_schema",
        "_diagnostics",
        "_sql",
        "_jobs",
        "_webhooks",
        "_page",
        "_api",
        "_media",
        "_theme.css",
        "_preferences",
        "_security",
        "_impersonate",
        "_demo",
        "_mcp",
    }
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
        session_store: SessionStore | bool | None = None,
        passkey_store: PasskeyStore | bool | None = None,
        approval_store: ApprovalStore | bool | None = None,
        saved_view_store: SavedViewStore | bool | None = None,
        note_store: RecordNoteStore | bool | None = None,
        api_key_store: APIKeyStore | bool | None = None,
        saved_query_store: SavedQueryStore | bool | None = None,
        translator: Translator | None = None,
        job_backend: JobBackend | None = None,
        job_storage: StorageBackend | None = None,
        preview_store: PreviewStore | None = None,
        rate_limit_store: RateLimitStore | None = None,
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
        self._session_store_arg: SessionStore | bool | None = session_store
        self.session_store: SessionStore | None = (
            session_store if isinstance(session_store, SessionStore) else None
        )
        self._passkey_store_arg: PasskeyStore | bool | None = passkey_store
        self.passkey_store: PasskeyStore | None = (
            passkey_store if isinstance(passkey_store, PasskeyStore) else None
        )
        self._approval_store_arg: ApprovalStore | bool | None = approval_store
        self.approval_store: ApprovalStore | None = (
            approval_store if isinstance(approval_store, ApprovalStore) else None
        )
        self._saved_view_store_arg: SavedViewStore | bool | None = saved_view_store
        self.saved_view_store: SavedViewStore | None = (
            saved_view_store if isinstance(saved_view_store, SavedViewStore) else None
        )
        self._note_store_arg: RecordNoteStore | bool | None = note_store
        self.note_store: RecordNoteStore | None = (
            note_store if isinstance(note_store, RecordNoteStore) else None
        )
        self._api_key_store_arg: APIKeyStore | bool | None = api_key_store
        self.api_key_store: APIKeyStore | None = (
            api_key_store if isinstance(api_key_store, APIKeyStore) else None
        )
        self._saved_query_store_arg: SavedQueryStore | bool | None = saved_query_store
        self.saved_query_store: SavedQueryStore | None = (
            saved_query_store if isinstance(saved_query_store, SavedQueryStore) else None
        )
        self._api_rate_lock = threading.Lock()
        self._api_rate_windows: dict[str, deque[float]] = {}
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
        self._webhook_sinks: list[WebhookSink] = []
        self.webhook_delivery_store: WebhookDeliveryStore | None = None
        self._brand_css_bytes, self._brand_css_hash = render_brand_css(self.config.brand)
        self.adapter: ORMAdapter | None = None
        self.app: Flask | None = None
        self.blueprint: Blueprint | None = None
        self.views: dict[str, ModelView] = {}
        self._views_by_model: dict[type[Any], ModelView] = {}
        self.custom_pages: dict[str, PageSpec] = {}
        self.scheduled_jobs: dict[str, ScheduledJobSpec] = {}
        self._dashboard_builder: DashboardBuilder | None = None
        self._explicit_rate_limiter = rate_limit_store
        self._rate_limiter: RateLimitStore = rate_limit_store or LoginRateLimiter(
            max_attempts=self.config.login_rate_limit_attempts,
            window_seconds=self.config.login_rate_limit_window_seconds,
            lockout_seconds=self.config.login_rate_limit_lockout_seconds,
        )
        self._explicit_preview_store = preview_store
        self._preview_store: PreviewStore = preview_store or ImportPreviewStore(
            ttl_seconds=self.config.import_preview_ttl_seconds,
            max_entries=self.config.import_preview_max_entries,
        )
        self._staged_imports: dict[str, tuple[float, str, str, str, str, bytes]] = {}
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
        shutdown_fn = getattr(self.job_backend, "shutdown", None)
        if callable(shutdown_fn):
            shutdown_fn(wait=False, cancel_futures=True)
        for sink in self._webhook_sinks:
            sink.close()
        if self.adapter is not None:
            self.adapter.dispose()
        for store in (
            self.audit_store,
            self.mfa_store,
            self.session_store,
            self.passkey_store,
            self.approval_store,
            self.saved_view_store,
            self.note_store,
            self.api_key_store,
            self.saved_query_store,
            self.job_backend,
            self.webhook_delivery_store,
            self._preview_store,
            self._rate_limiter,
        ):
            eng = getattr(store, "_engine", None)
            if isinstance(eng, Engine):
                eng.dispose()

    def __enter__(self) -> Deck:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

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
                    self.mfa_store = SQLAlchemyMFAStore(
                        self.adapter.get_engine(),
                        encryption_key=self.config.encryption_key,
                        encryption_fallback_keys=self.config.encryption_fallback_keys,
                    )
            else:
                self.mfa_store = InMemoryMFAStore(
                    encryption_key=self.config.encryption_key,
                    encryption_fallback_keys=self.config.encryption_fallback_keys,
                )

        if self._session_store_arg is False:
            self.session_store = None
        elif self.session_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.session_store = SQLAlchemySessionStore(self.adapter.get_engine())
            else:
                self.session_store = InMemorySessionStore()

        if self._passkey_store_arg is False:
            self.passkey_store = None
        elif self.passkey_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.passkey_store = SQLAlchemyPasskeyStore(self.adapter.get_engine())
            else:
                self.passkey_store = InMemoryPasskeyStore()

        if self._approval_store_arg is False:
            self.approval_store = None
        elif self.approval_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.approval_store = SQLAlchemyApprovalStore(self.adapter.get_engine())
            else:
                self.approval_store = InMemoryApprovalStore()

        if self._saved_view_store_arg is False:
            self.saved_view_store = None
        elif self.saved_view_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.saved_view_store = SQLAlchemySavedViewStore(self.adapter.get_engine())
            else:
                self.saved_view_store = InMemorySavedViewStore()

        if self._note_store_arg is False:
            self.note_store = None
        elif self.note_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.note_store = SQLAlchemyRecordNoteStore(self.adapter.get_engine())
            else:
                self.note_store = InMemoryRecordNoteStore()

        if self._api_key_store_arg is False:
            self.api_key_store = None
        elif self.api_key_store is None and (
            self._api_key_store_arg is True
            or self.config.enable_rest_api
            or self.config.enable_mcp
        ):
            if not self.config.read_only:
                with app.app_context():
                    self.api_key_store = SQLAlchemyAPIKeyStore(self.adapter.get_engine())
            else:
                self.api_key_store = InMemoryAPIKeyStore()

        if self._saved_query_store_arg is False:
            self.saved_query_store = None
        elif self.saved_query_store is None and (
            self._saved_query_store_arg is True or self.config.enable_sql_console
        ):
            if not self.config.read_only:
                with app.app_context():
                    self.saved_query_store = SQLAlchemySavedQueryStore(self.adapter.get_engine())
            else:
                self.saved_query_store = InMemorySavedQueryStore()

        if self.webhook_delivery_store is None:
            if not self.config.read_only:
                with app.app_context():
                    self.webhook_delivery_store = SQLAlchemyWebhookDeliveryStore(
                        self.adapter.get_engine()
                    )
            else:
                self.webhook_delivery_store = InMemoryWebhookDeliveryStore()
        for sink in self._webhook_sinks:
            sink.set_delivery_store(self.webhook_delivery_store)

        if not self.config.read_only:
            with app.app_context():
                eng_primary = self.adapter.get_engine()
                if self._explicit_preview_store is None:
                    self._preview_store = SQLAlchemyPreviewStore(
                        eng_primary,
                        ttl_seconds=self.config.import_preview_ttl_seconds,
                        max_entries=self.config.import_preview_max_entries,
                    )
                if self._explicit_rate_limiter is None:
                    self._rate_limiter = SQLAlchemyRateLimitStore(
                        eng_primary,
                        max_attempts=self.config.login_rate_limit_attempts,
                        window_seconds=self.config.login_rate_limit_window_seconds,
                        lockout_seconds=self.config.login_rate_limit_lockout_seconds,
                    )

        if self.config.enable_sql_telemetry:
            with app.app_context():
                for eng in self.adapter.get_engines().values():
                    attach_sql_telemetry(eng)

        self._asset_hashes = {
            "css/deck.css": _file_hash(_STATIC_DIR / "css" / "deck.css"),
            "js/deck.js": _file_hash(_STATIC_DIR / "js" / "deck.js"),
            "js/deck-grid.js": _file_hash(_STATIC_DIR / "js" / "deck-grid.js"),
            "js/deck-form.js": _file_hash(_STATIC_DIR / "js" / "deck-form.js"),
            "js/deck-ops.js": _file_hash(_STATIC_DIR / "js" / "deck-ops.js"),
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
        if self.webhook_delivery_store is not None:
            sink.set_delivery_store(self.webhook_delivery_store)
        self._webhook_sinks.append(sink)
        self.events.subscribe("*", sink)
        return self

    def scheduled_job(
        self,
        name: str,
        *,
        schedule: str = "0 * * * *",
        label: str | None = None,
        description: str = "",
        permission: str | None = None,
    ) -> Callable[[JobCallable], JobCallable]:
        """Decorator registering a scheduled/triggerable background operational job."""
        clean_name = name.strip().lower()
        if not clean_name:
            raise ValueError("Scheduled job name cannot be empty")

        def decorator(fn: JobCallable) -> JobCallable:
            self.scheduled_jobs[clean_name] = ScheduledJobSpec(
                name=clean_name,
                label=label or clean_name.replace("_", " ").replace("-", " ").title(),
                schedule=schedule.strip(),
                fn=fn,
                description=description.strip(),
                permission=permission,
            )
            return fn

        return decorator

    def _resolve_scheduled_callable(self, job_name: str) -> JobCallable | None:
        prefix = "scheduled:"
        if job_name.startswith(prefix):
            spec = self.scheduled_jobs.get(job_name[len(prefix) :])
            return spec.fn if spec is not None else None
        spec = self.scheduled_jobs.get(job_name)
        return spec.fn if spec is not None else None

    def run_scheduled_job(self, name: str, *, user: DeckUser | None = None) -> JobRecord:
        """Submit a registered scheduled job onto Deck's job backend and record audit."""
        if self.job_backend is None:
            raise RuntimeError("Background jobs are disabled on this Deck instance")
        spec = self.scheduled_jobs.get(name)
        if spec is None:
            raise KeyError(f"Unknown scheduled job: {name!r}")
        if isinstance(self.job_backend, SQLAlchemyJobBackend):
            self.job_backend.set_callable_resolver(self._resolve_scheduled_callable)
        rec = self.job_backend.submit(
            name=f"scheduled:{spec.name}",
            label=spec.label,
            actor_id=user.id if user else "scheduler",
            actor_name=user.label if user else "Scheduler",
            model_slug=spec.model_slug,
            fn=spec.fn,
            app=self.app,
        )
        if self.audit_store is not None and self.config.auto_audit:
            actor = user
            self.audit_store.record(
                make_audit_entry(
                    actor_id=actor.id if actor else "scheduler",
                    actor_name=actor.label if actor else "Scheduler",
                    actor_ip=_client_ip() if has_request_context() else "127.0.0.1",
                    action="scheduled_job",
                    model_slug=spec.model_slug,
                    model_label="Scheduled Job",
                    record_pk=rec.id,
                    record_repr=spec.label,
                    metadata={"scheduled_job": spec.name, "job_id": rec.id},
                )
            )
        return rec

    def run_scheduled_job_sync(self, name: str) -> JobRecord:
        """Execute a registered scheduled job synchronously (CLI cron runner)."""
        import threading

        spec = self.scheduled_jobs.get(name)
        if spec is None:
            raise KeyError(f"Unknown scheduled job: {name!r}")
        if self.job_backend is not None:
            rec = self.job_backend.submit(
                name=f"scheduled:{spec.name}",
                label=spec.label,
                actor_id="cli",
                actor_name="CLI Scheduler",
                model_slug=spec.model_slug,
                fn=spec.fn,
                app=self.app,
            )
            # Wait cleanly up to 30s for terminal status
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                snap = self.job_backend.get(rec.id)
                if snap is not None and snap.status in {"succeeded", "failed", "cancelled"}:
                    return snap
                time.sleep(0.05)
            return self.job_backend.get(rec.id) or rec
        rec = JobRecord(
            id="sync",
            name=spec.name,
            label=spec.label,
            actor_id="cli",
            actor_name="CLI Scheduler",
            model_slug=spec.model_slug,
        )
        ev = threading.Event()
        backend = ThreadPoolJobBackend(max_workers=1)
        try:
            ctx = JobContext(backend, "sync", ev)
            msg = spec.fn(ctx)
            rec.status = "succeeded"
            rec.progress = 100
            rec.message = msg or "Completed"
        except Exception as exc:
            rec.status = "failed"
            rec.error = str(exc)
            rec.message = f"Failed: {exc}"
        finally:
            backend.shutdown(wait=False, cancel_futures=True)
        return rec

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

    def _rel_url_builder(self, user: DeckUser | None) -> Callable[[type[Any], Any], str | None]:
        """Build safe detail links for related objects if viewer has permission on target model."""
        bp_name = self.config.name

        def _build(target_model: type[Any], item: Any) -> str | None:
            if item is None:
                return None
            target_view = self._views_by_model.get(target_model)
            if target_view is None or not target_view.can_view:
                return None
            t_slug = target_view.meta.slug
            if not self.auth.has_permission(user, f"{t_slug}:view", model_slug=t_slug):
                return None
            try:
                pk_vals = extract_pk(item, target_view.meta)
                return url_for(f"{bp_name}.model_detail", slug=t_slug, raw_pk=encode_pk(pk_vals))
            except Exception:
                return None

        return _build

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

    def _is_dotted_field_allowed(
        self, view: ModelView, col_spec: str, user: DeckUser | None, restricted: frozenset[str]
    ) -> bool:
        if "." not in col_spec:
            return col_spec not in restricted
        rel_name, target_col = col_spec.split(".", 1)
        if rel_name in restricted or is_sensitive_field(
            target_col, self.config.extra_sensitive_patterns
        ):
            return False
        rel_meta = view.meta.relationships_by_name.get(rel_name)
        if rel_meta is None or rel_meta.direction != "MANYTOONE":
            return False
        t_view = self._views_by_model.get(rel_meta.target_model)
        if t_view is not None:
            t_restricted = self.auth.hidden_fields_for(
                user, t_view.meta.slug
            ) | self.auth.masked_fields_for(user, t_view.meta.slug)
            if target_col in t_restricted or target_col in t_view.meta.sensitive_fields:
                return False
        else:
            from flask_deck.introspection import introspect_model

            t_meta = introspect_model(rel_meta.target_model)
            if target_col not in t_meta.fields_by_name or target_col in t_meta.sensitive_fields:
                return False
        return True

    def _allowed_query_fields(
        self, view: ModelView, user: DeckUser | None
    ) -> tuple[tuple[str, ...], frozenset[str], frozenset[str]]:
        """Filter searchable, filterable, and sortable columns by viewer's hidden/masked RBAC rules."""
        restricted = self.auth.hidden_fields_for(user, view.meta.slug) | self.auth.masked_fields_for(
            user, view.meta.slug
        )
        searchable = tuple(
            col_spec
            for col_spec in view.resolved_searchable
            if self._is_dotted_field_allowed(view, col_spec, user, restricted)
        )
        filterable = frozenset(
            col_spec
            for col_spec in view.resolved_filterable
            if self._is_dotted_field_allowed(view, col_spec, user, restricted)
        )
        return (
            searchable,
            filterable,
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

    def _has_perm(
        self,
        user: DeckUser | None,
        permission: str,
        *,
        model_slug: str | None = None,
        obj: Any = None,
    ) -> bool:
        if not self.auth.has_permission(user, permission, model_slug=model_slug, obj=obj):
            return False
        key_rec: APIKeyRecord | None = getattr(g, "_deck_api_key", None)
        return key_rec is None or api_key_allows(key_rec, permission)

    def _require_perm(self, permission: str, *, model_slug: str | None = None, obj: Any = None) -> None:
        user = self._current_user()
        if not self._has_perm(user, permission, model_slug=model_slug, obj=obj):
            raise PermissionDeniedError(f"Missing permission: {permission}")

    def _check_api_rate_limit(self, key_bucket: str) -> tuple[bool, int]:
        max_reqs = max(1, int(self.config.api_rate_limit_max))
        window = max(1, int(self.config.api_rate_limit_window_seconds))
        now = time.monotonic()
        cutoff = now - window
        with self._api_rate_lock:
            dq = self._api_rate_windows.get(key_bucket)
            if dq is None:
                if len(self._api_rate_windows) >= 4096:
                    self._api_rate_windows.clear()
                dq = deque()
                self._api_rate_windows[key_bucket] = dq
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_reqs:
                retry_after = max(1, int(window - (now - dq[0])))
                return False, retry_after
            dq.append(now)
            return True, 0

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
        actor: DeckUser | None = None,
    ) -> AuditEntry | None:
        if self.audit_store is None or not self.config.auto_audit:
            return None
        user = actor if actor is not None else self._current_user()
        meta = dict(metadata or {})
        real = getattr(g, "_deck_real_user", None)
        if actor is None and real is not None and (user is None or real.id != user.id):
            meta["impersonated_by"] = real.id
            meta["impersonated_by_name"] = real.label
        entry = make_audit_entry(
            actor_id=user.id if user else "system",
            actor_name=user.label if user else "System",
            actor_ip=_client_ip() if has_request_context() else "127.0.0.1",
            action=action_name,
            model_slug=view.meta.slug,
            model_label=view.label,
            record_pk=record_pk,
            record_repr=record_repr,
            changes=changes,
            metadata=meta,
        )
        return self.audit_store.record(entry)

    def _record_inline_audits(
        self,
        *,
        view: ModelView,
        parent_pk: str,
        inline_diffs: Sequence[Mapping[str, Any]],
        actor: DeckUser | None = None,
        extra_meta: Mapping[str, Any] | None = None,
    ) -> None:
        """Record field-level audit entries for inline child row changes."""
        if not inline_diffs:
            return
        for item in inline_diffs:
            op = str(item.get("op", "edit"))
            act_name = f"inline_{op}" if op in {"create", "edit", "delete"} else "inline_edit"
            meta = dict(extra_meta or {})
            meta["inline_model"] = str(item.get("inline_slug", ""))
            meta["inline_label"] = str(item.get("inline_label", ""))
            meta["inline_pk"] = str(item.get("child_pk", ""))
            self._record_audit(
                action_name=act_name,
                view=view,
                record_pk=parent_pk,
                record_repr=f"{item.get('inline_label', 'Inline')} #{item.get('child_pk', '')}",
                changes=dict(item.get("changes") or {}),
                metadata=meta,
                actor=actor,
            )

    @staticmethod
    def _items_to_multidict(raw_items: Sequence[Any]) -> MultiDict[str, str]:
        pairs: list[tuple[str, str]] = []
        for entry in raw_items:
            k = str(entry[0])
            val = entry[1]
            if isinstance(val, (list, tuple)):
                for item in val:
                    pairs.append((k, str(item)))
            else:
                pairs.append((k, str(val)))
        return MultiDict(pairs)

    def _execute_approved_request(
        self,
        req: ApprovalRequest,
        *,
        reviewer: DeckUser,
    ) -> str:
        """Execute a previously validated ApprovalRequest and write dual-actor audit."""
        view = self.get_view(req.model_slug)
        sess = self.get_session(view.bind_key)
        requester = self.auth.get_user_by_id(req.requester_id)
        if requester is None:
            raw_roles = req.payload.get("_actor_roles") or ()
            requester = DeckUser(
                id=req.requester_id,
                username=req.requester_name or req.requester_id,
                display_name=req.requester_name or req.requester_id,
                roles=tuple(str(r) for r in raw_roles),
                is_superuser=bool(req.payload.get("_actor_superuser", False)),
            )

        dual_meta: dict[str, Any] = {
            "approval_id": req.id,
            "approved_by": reviewer.id,
            "approved_by_name": reviewer.label,
            "actor_type": req.actor_type,
        }
        if req.reason:
            dual_meta["reason"] = req.reason

        if req.operation == "create":
            raw_items = req.payload.get("form_items")
            if raw_items is not None:
                form_md = self._items_to_multidict(raw_items)
            else:
                vals = req.payload.get("values") or {}
                form_md = MultiDict([(str(k), str(v)) for k, v in vals.items()])
            obj = view.model()
            view.apply_form_data(
                sess,
                obj,
                form_md,
                auth=self.auth,
                user=requester,
                mode="create",
                max_json_depth=self.config.max_json_depth,
                m2m_getter=form_md.getlist,
            )
            view.on_model_change(obj, is_created=True, user=requester)
            sess.add(obj)
            sess.flush()
            inline_diffs = view.apply_inline_forms(
                sess,
                obj,
                form_md,
                auth=self.auth,
                user=requester,
                max_json_depth=self.config.max_json_depth,
            )
            sess.commit()
            pk_str = encode_pk(extract_pk(obj, view.meta))
            safe_repr = view.format_record_repr(obj, auth=self.auth, user=requester)
            diff = compute_diff(
                {},
                view.extract_snapshot(obj),
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=self.config.extra_sensitive_patterns,
            )
            self._record_audit(
                action_name="create",
                view=view,
                record_pk=pk_str,
                record_repr=safe_repr,
                changes=diff,
                metadata=dual_meta,
                actor=requester,
            )
            self._record_inline_audits(
                view=view,
                parent_pk=pk_str,
                inline_diffs=inline_diffs,
                actor=requester,
                extra_meta=dual_meta,
            )
            self._emit_event(
                "record.created",
                model_slug=req.model_slug,
                record_pk=pk_str,
                payload={"repr": safe_repr, "approval_id": req.id},
                actor=requester,
            )
            self._emit_event(
                "approval.approved",
                model_slug=req.model_slug,
                record_pk=pk_str,
                payload={"approval_id": req.id, "operation": "create", "reviewer_id": reviewer.id},
                actor=reviewer,
            )
            return pk_str

        if req.operation == "edit":
            pk_vals = decode_pk(req.record_pk, view.meta)
            stmt = view.scope_query(sa.select(view.model), requester)
            for pk_f, val in zip(view.meta.primary_keys, pk_vals, strict=True):
                stmt = stmt.where(getattr(view.model, pk_f.name) == val)
            obj = sess.scalars(stmt).unique().first()
            if obj is None:
                raise ValueError(f"Record {req.record_pk} no longer exists.")
            before_snap = view.extract_snapshot(obj)
            raw_items = req.payload.get("form_items")
            if raw_items is not None:
                form_md = self._items_to_multidict(raw_items)
            else:
                vals = req.payload.get("values") or {}
                form_md = MultiDict([(str(k), str(v)) for k, v in vals.items()])
            view.apply_form_data(
                sess,
                obj,
                form_md,
                auth=self.auth,
                user=requester,
                mode="edit",
                max_json_depth=self.config.max_json_depth,
                m2m_getter=form_md.getlist,
            )
            if view.version_column:
                vf = view.meta.fields_by_name.get(view.version_column)
                if vf is not None and vf.field_type == "integer":
                    setattr(obj, view.version_column, int(getattr(obj, view.version_column) or 0) + 1)
            view.on_model_change(obj, is_created=False, user=requester)
            sess.flush()
            inline_diffs = view.apply_inline_forms(
                sess,
                obj,
                form_md,
                auth=self.auth,
                user=requester,
                max_json_depth=self.config.max_json_depth,
            )
            sess.commit()
            safe_repr = view.format_record_repr(obj, auth=self.auth, user=requester)
            diff = compute_diff(
                before_snap,
                view.extract_snapshot(obj),
                sensitive_fields=view.meta.sensitive_fields,
                extra_sensitive_patterns=self.config.extra_sensitive_patterns,
            )
            self._record_audit(
                action_name="update",
                view=view,
                record_pk=req.record_pk,
                record_repr=safe_repr,
                changes=diff,
                metadata=dual_meta,
                actor=requester,
            )
            self._record_inline_audits(
                view=view,
                parent_pk=req.record_pk,
                inline_diffs=inline_diffs,
                actor=requester,
                extra_meta=dual_meta,
            )
            self._emit_event(
                "record.updated",
                model_slug=req.model_slug,
                record_pk=req.record_pk,
                payload={"fields": sorted(diff.keys()), "approval_id": req.id},
                actor=requester,
            )
            self._emit_event(
                "approval.approved",
                model_slug=req.model_slug,
                record_pk=req.record_pk,
                payload={"approval_id": req.id, "operation": "edit", "reviewer_id": reviewer.id},
                actor=reviewer,
            )
            return req.record_pk

        if req.operation == "delete":
            pk_vals = decode_pk(req.record_pk, view.meta)
            stmt = view.scope_query(sa.select(view.model), requester)
            for pk_f, val in zip(view.meta.primary_keys, pk_vals, strict=True):
                stmt = stmt.where(getattr(view.model, pk_f.name) == val)
            obj = sess.scalars(stmt).unique().first()
            if obj is None:
                raise ValueError(f"Record {req.record_pk} no longer exists.")
            force = bool(req.payload.get("force", False))
            before_snap = view.extract_snapshot(obj)
            safe_repr = view.format_record_repr(obj, auth=self.auth, user=requester)
            if view.soft_delete_column and not force:
                fmeta = view.meta.fields_by_name.get(view.soft_delete_column)
                if fmeta is not None:
                    view.on_model_delete(obj, user=requester)
                    setattr(
                        obj,
                        view.soft_delete_column,
                        True if fmeta.field_type == "boolean" else datetime.now(timezone.utc),
                    )
                    sess.commit()
                    after_snap = view.extract_snapshot(obj)
                    self._record_audit(
                        action_name="soft_delete",
                        view=view,
                        record_pk=req.record_pk,
                        record_repr=safe_repr,
                        changes=compute_diff(
                            before_snap,
                            after_snap,
                            sensitive_fields=view.meta.sensitive_fields,
                            extra_sensitive_patterns=self.config.extra_sensitive_patterns,
                        ),
                        metadata=dual_meta,
                        actor=requester,
                    )
                    self._emit_event(
                        "record.deleted",
                        model_slug=req.model_slug,
                        record_pk=req.record_pk,
                        payload={"soft": True, "approval_id": req.id},
                        actor=requester,
                    )
                    self._emit_event(
                        "approval.approved",
                        model_slug=req.model_slug,
                        record_pk=req.record_pk,
                        payload={"approval_id": req.id, "operation": "delete", "reviewer_id": reviewer.id},
                        actor=reviewer,
                    )
                    return req.record_pk

            orphan_files = self._collect_orphan_files(view, obj)
            view.on_model_delete(obj, user=requester)
            sess.delete(obj)
            sess.commit()
            self._delete_orphan_files_best_effort(orphan_files)
            self._record_audit(
                action_name="delete",
                view=view,
                record_pk=req.record_pk,
                record_repr=safe_repr,
                changes=compute_diff(
                    before_snap,
                    {},
                    sensitive_fields=view.meta.sensitive_fields,
                    extra_sensitive_patterns=self.config.extra_sensitive_patterns,
                ),
                metadata=dual_meta,
                actor=requester,
            )
            self._emit_event(
                "record.deleted",
                model_slug=req.model_slug,
                record_pk=req.record_pk,
                payload={"soft": False, "approval_id": req.id},
                actor=requester,
            )
            self._emit_event(
                "approval.approved",
                model_slug=req.model_slug,
                record_pk=req.record_pk,
                payload={"approval_id": req.id, "operation": "delete", "reviewer_id": reviewer.id},
                actor=reviewer,
            )
            return req.record_pk

        # action
        action_name = str(req.payload.get("action_name", ""))
        spec = view.actions.get(action_name)
        if spec is None:
            raise ValueError(f"Unknown action {action_name!r} on model {req.model_slug!r}.")
        raw_pks = [str(p) for p in req.payload.get("pks", [])]
        decoded = [decode_pk(p, view.meta) for p in raw_pks]
        stmt = view.scope_query(sa.select(view.model), requester)
        if len(view.meta.primary_keys) == 1:
            pk_col = getattr(view.model, view.meta.primary_keys[0].name)
            stmt = stmt.where(pk_col.in_([p[0] for p in decoded]))
        else:
            pk_cols = [getattr(view.model, pk.name) for pk in view.meta.primary_keys]
            stmt = stmt.where(sa.tuple_(*pk_cols).in_(decoded))
        records = list(sess.scalars(stmt).all())
        raw_items = req.payload.get("form_items") or []
        form_md = self._items_to_multidict(raw_items)
        if not raw_items and isinstance(req.payload.get("params"), Mapping):
            form_md = MultiDict([(str(k), str(v)) for k, v in req.payload["params"].items()])
        handler = getattr(view, spec.handler_name)
        msg = handler(records, form_md, requester)
        sess.commit()
        dual_meta["action"] = action_name
        dual_meta["count"] = len(records)
        self._record_audit(
            action_name="bulk_action",
            view=view,
            record_pk=req.record_pk,
            record_repr=msg or f"{spec.label} ({len(records)})",
            metadata=dual_meta,
            actor=requester,
        )
        self._emit_event(
            "action.executed",
            model_slug=req.model_slug,
            record_pk=req.record_pk,
            payload={"action": action_name, "count": len(records), "approval_id": req.id},
            actor=requester,
        )
        self._emit_event(
            "approval.approved",
            model_slug=req.model_slug,
            record_pk=req.record_pk,
            payload={"approval_id": req.id, "operation": "action", "reviewer_id": reviewer.id},
            actor=reviewer,
        )
        return str(msg or f"Executed approved action '{spec.label}'")

    def _excluded_audit_models(self, user: DeckUser | None) -> frozenset[str]:
        """Return model_slug values that the viewer is NOT authorized to inspect in Audit Ledger."""
        excluded = {
            slug
            for slug in self.views
            if not self.auth.has_permission(user, f"{slug}:view", model_slug=slug)
        }
        can_sql_audit = (
            (user is not None and user.is_superuser)
            or self.auth.has_permission(user, "sql:query")
            or self.auth.has_permission(user, "sql:view")
        )
        if not can_sql_audit:
            excluded.add("_sql")
        return frozenset(excluded)

    def _user_has_field_restrictions(self, user: DeckUser | None) -> bool:
        """Return True if viewer has hidden/masked field rules on any model (blocks raw changes_json search)."""
        if user is not None and user.is_superuser:
            return False
        for slug in self.views:
            if not self.auth.has_permission(user, f"{slug}:view", model_slug=slug):
                continue
            if self.auth.hidden_fields_for(user, slug) or self.auth.masked_fields_for(user, slug):
                return True
        return False

    def _sidebar_groups(self) -> list[dict[str, Any]]:
        """Build grouped sidebar navigation while honoring each view's count_mode."""
        user = self._current_user()
        authorized: list[ModelView] = [
            v
            for v in self.views.values()
            if v.can_view and self.auth.has_permission(user, f"{v.meta.slug}:view", model_slug=v.meta.slug)
        ]

        counts: dict[str, int | None] = {}
        by_bind: dict[str | None, list[ModelView]] = {}
        for v in authorized:
            if v.count_mode == "none":
                counts[v.meta.slug] = None
                continue
            if v.count_mode == "estimated":
                scoped_probe = v.scope_query(sa.select(v.model), user)
                if not scoped_probe._where_criteria:
                    est = estimate_table_rows(self.get_session(v.bind_key), v.meta)
                    if est is not None:
                        counts[v.meta.slug] = est
                        continue
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
                    "count": counts.get(v.meta.slug),
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
        can_webhooks = (
            self.config.enable_webhooks_ui
            and self.webhook_delivery_store is not None
            and (
                self.auth.has_permission(user, "webhooks:view")
                or (user is not None and user.is_superuser)
            )
        )
        can_mfa = self.mfa_store is not None and user is not None and self.auth.supports_login_form
        can_approvals = self.approval_store is not None and (
            self.auth.has_permission(user, "approvals:view")
            or self.auth.has_permission(user, "approvals:review")
            or (user is not None and user.is_superuser)
        )
        can_review_approvals = self.approval_store is not None and (
            self.auth.has_permission(user, "approvals:review")
            or (user is not None and user.is_superuser)
        )
        pending_approvals_count = (
            self.approval_store.pending_count()
            if can_approvals and self.approval_store is not None
            else 0
        )
        can_manage_sessions = (
            self.session_store is not None and user is not None and self.auth.supports_login_form
        )
        can_manage_passkeys = (
            self.passkey_store is not None and user is not None and self.auth.supports_login_form
        )
        can_manage_api_keys = bool(
            self.api_key_store is not None
            and user is not None
            and (user.is_superuser or self.auth.has_permission(user, "api_keys:manage"))
        )
        passkey_login_enabled = (
            self.passkey_store is not None
            and is_webauthn_available()
            and self.auth.supports_login_form
        )
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
        ):
            impersonate_targets = tuple(
                acc
                for acc in self.auth.get_impersonatable_users(user)
                if acc.id != user.id and not acc.is_superuser
            )

        active_locale = self.translator.get_locale()
        active_tz = str(getattr(g, "_flask_deck_tz", self.config.default_timezone))
        text_dir = "rtl" if self.translator.is_rtl(active_locale) else "ltr"

        ctx: dict[str, Any] = {
            "deck": self,
            "deck_version": __version__,
            "deck_version_short": SHORT_VERSION,
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
            "can_view_webhooks": can_webhooks,
            "can_view_approvals": can_approvals,
            "can_review_approvals": can_review_approvals,
            "pending_approvals_count": pending_approvals_count,
            "can_manage_mfa": can_mfa,
            "can_manage_sessions": can_manage_sessions,
            "can_manage_passkeys": can_manage_passkeys,
            "can_manage_api_keys": can_manage_api_keys,
            "passkey_login_enabled": passkey_login_enabled,
            "show_password_form": self.auth.supports_password_login,
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
            "rel_url_builder": self._rel_url_builder(user),
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
                is_req = not fmeta.nullable and not fmeta.has_default and not fmeta.autoincrement
                custom_widget_html: Any = None
                widget_full = False
                widget_name = widget_override if isinstance(widget_override, str) else ""
                if isinstance(widget_override, FormWidget):
                    widget_name = "custom_widget"
                    widget_full = widget_override.full_width
                    custom_widget_html = widget_override.render(
                        name=col_name,
                        field_id=f"fld_{col_name}",
                        value=raw_val,
                        readonly=is_ro,
                        required=is_req,
                        label=view.get_column_label(col_name),
                    )
                kind = (
                    "file"
                    if file_cfg is not None
                    else ("fk" if fmeta.fk_target_model is not None else fmeta.field_type)
                )
                field_specs[col_name] = {
                    "kind": kind,
                    "widget": widget_name,
                    "custom_widget_html": custom_widget_html,
                    "widget_full": widget_full,
                    "file_kind": file_cfg.kind if file_cfg is not None else "",
                    "file_accept": ",".join(sorted(file_cfg.resolved_allowed_mimes()))
                    if file_cfg is not None
                    else "",
                    "media_url": media_url,
                    "show_when_json": show_when_json,
                    "dependent_json": dependent_json,
                    "name": col_name,
                    "label": view.get_column_label(col_name),
                    "required": is_req,
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
                    "widget": "",
                    "custom_widget_html": None,
                    "widget_full": False,
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
                order_col_name = (
                    inline.order_by
                    if inline.order_by and inline.order_by in inline.meta.fields_by_name
                    else inline.meta.primary_keys[0].name
                )
                existing_rows = list(
                    self.get_session(view.bind_key)
                    .scalars(
                        sa.select(inline.model)
                        .where(getattr(inline.model, fk_col) == parent_pk)
                        .order_by(getattr(inline.model, order_col_name).asc())
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
            "occ_version": view.compute_version_token(obj, auth=self.auth, user=user)
            if obj is not None
            else "",
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
                f"{bp_name}.passkey_login_options",
                f"{bp_name}.passkey_login_verify",
            }
            is_logout = endpoint == f"{bp_name}.logout"
            is_readonly_post = endpoint in {
                f"{bp_name}.sql_console",
                f"{bp_name}.demo_switch_role",
                f"{bp_name}.update_preferences",
                f"{bp_name}.impersonate_stop",
                f"{bp_name}.model_export_async",
                f"{bp_name}.mcp_endpoint",
            }
            is_bearer_api = endpoint.startswith(f"{bp_name}.rest_v1_") or (
                endpoint == f"{bp_name}.mcp_endpoint"
            )
            is_api = endpoint.startswith(f"{bp_name}.api_") or is_bearer_api

            # 1. Server-side read_only guard
            if (
                deck.config.read_only
                and request.method not in {"GET", "HEAD", "OPTIONS"}
                and not (is_public_auth or is_logout or is_readonly_post)
            ):
                if is_api:
                    return jsonify({"error": "Flask-Deck is running in read-only mode."}), 403  # type: ignore[return-value]
                abort(403, description="Flask-Deck is running in read-only mode.")

            # 1b. Bearer API Key Authentication & Origin/Rate-Limit checks for REST v1 and MCP
            g._deck_api_key = None
            if is_bearer_api:
                if endpoint == f"{bp_name}.mcp_endpoint":
                    origin = (request.headers.get("Origin") or "").strip()
                    if origin:
                        parsed_orig = urlsplit(origin)
                        if parsed_orig.netloc and parsed_orig.netloc != request.host:
                            return (
                                jsonify({"error": "Cross-origin MCP request rejected."}),
                                403,
                            )  # type: ignore[return-value]
                auth_hdr = (request.headers.get("Authorization") or "").strip()
                if not auth_hdr.lower().startswith("bearer "):
                    return (
                        jsonify({"error": "Missing or malformed Authorization: Bearer token."}),
                        401,
                    )  # type: ignore[return-value]
                raw_token = auth_hdr[7:].strip()
                if deck.api_key_store is None:
                    return jsonify({"error": "API keys are disabled."}), 503  # type: ignore[return-value]
                key_rec = deck.api_key_store.verify_token(raw_token, client_ip=_client_ip())
                if key_rec is None:
                    return (
                        jsonify({"error": "Invalid, expired, revoked, or IP-blocked API key."}),
                        401,
                    )  # type: ignore[return-value]
                allowed_rl, retry_after = deck._check_api_rate_limit(
                    f"api:{key_rec.id}:{_client_ip()}"
                )
                if not allowed_rl:
                    rl_resp = jsonify({"error": "API rate limit exceeded."})
                    rl_resp.status_code = 429
                    rl_resp.headers["Retry-After"] = str(retry_after)
                    return rl_resp
                g._deck_api_key = key_rec
                g._deck_real_user = None
                g._deck_user = api_key_to_user(key_rec)
                return None

            # 2. Strict CSRF + Origin/Sec-Fetch-Site validation on EVERY cookie mutation
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf(request):
                if is_api:
                    return jsonify({"error": "Invalid or missing CSRF token."}), 403  # type: ignore[return-value]
                if endpoint == f"{bp_name}.login" and check_origin_headers(request):
                    rotate_csrf_token()
                    return Response(
                        render_template(
                            "flask_deck/login.html",
                            **deck._base_context(
                                next_url=request.form.get("next", ""),
                                error_msg="Session refreshed — please click Sign in again.",
                                demo_credentials=deck._demo_credentials,
                            ),
                        ),
                        status=400,
                    )
                abort(403, description="Invalid or missing CSRF token.")

            # 3. Authentication, session timeout & audited impersonation resolution
            real_user = deck.auth.get_current_user(
                idle_timeout=deck.config.session_idle_timeout_seconds,
                absolute_timeout=deck.config.session_absolute_timeout_seconds,
            )
            if real_user is not None and deck.session_store is not None:
                sid = session.get(DECK_SID_SESSION_KEY)
                if isinstance(sid, str) and sid:
                    if not deck.session_store.is_active(sid):
                        deck.auth.logout_user()
                        real_user = None
                    else:
                        now_ts = int(time.time())
                        last_touch = session.get("_deck_sid_touch")
                        if not isinstance(last_touch, int) or (now_ts - last_touch) >= 60:
                            deck.session_store.touch(sid)
                            session["_deck_sid_touch"] = now_ts
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
            ):
                target = deck.auth.get_user_by_id(imp_target_id)
                if (
                    target is not None
                    and not target.is_superuser
                    and any(
                        u.id == target.id for u in deck.auth.get_impersonatable_users(real_user)
                    )
                ):
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

        def _is_json_api_ep() -> bool:
            ep = request.endpoint or ""
            return (
                ep.startswith(f"{bp_name}.api_")
                or ep.startswith(f"{bp_name}.rest_v1_")
                or ep == f"{bp_name}.mcp_endpoint"
            )

        @bp.errorhandler(PermissionDeniedError)
        def _handle_perm(exc: PermissionDeniedError) -> tuple[Any, int]:
            if _is_json_api_ep():
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
            if _is_json_api_ep():
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
            if _is_json_api_ep():
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


        register_all_routes(bp, self)
        return bp


__all__ = ["Deck", "PageSpec", "run_security_audit"]
