from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from flask_deck.branding import BrandConfig
from flask_deck.security import is_valid_csp_img_source

EnvironmentName = Literal["development", "staging", "production"]
ThemeName = Literal["dark", "light", "system"]
PaginationMode = Literal["offset", "cursor"]


@dataclass(frozen=True, slots=True)
class DeckConfig:
    """Immutable runtime configuration for a Deck instance."""

    title: str = "Flask-Deck"
    subtitle: str = "Operations Workbench"
    url_prefix: str = "/admin"
    name: str = "deck"
    environment: EnvironmentName = "development"
    default_theme: ThemeName = "dark"
    read_only: bool = False
    allow_insecure_open: bool = False
    page_size: int = 25
    max_page_size: int = 200
    default_pagination_mode: PaginationMode = "offset"
    max_upload_bytes: int = 5 * 1024 * 1024  # 5 MiB
    max_import_rows: int = 5000
    max_import_columns: int = 100
    max_json_depth: int = 12
    import_preview_ttl_seconds: int = 900  # 15 minutes
    import_preview_max_entries: int = 64
    sanitize_csv: bool = True
    auto_audit: bool = True
    enable_audit_revert: bool = True
    enable_sql_telemetry: bool = True
    session_idle_timeout_seconds: int = 1800  # 30 minutes
    session_absolute_timeout_seconds: int = 43200  # 12 hours
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 300
    login_rate_limit_lockout_seconds: int = 300
    require_confirm_text_in_prod: bool = True
    search_min_chars: int = 2
    search_limit_per_model: int = 5
    enable_sql_console: bool = False
    sql_console_max_rows: int = 200
    demo_role_switcher: bool = False
    # v0.3.0 Enterprise capabilities
    brand: BrandConfig = field(default_factory=BrandConfig)
    default_locale: str = "en"
    available_locales: tuple[str, ...] = ("en", "tr", "de", "ar")
    default_timezone: str = "UTC"
    enable_user_preferences: bool = True
    locale_selector: Callable[[], str] | None = None
    timezone_selector: Callable[[], str] | None = None
    require_mfa_for_superusers: bool = False
    enable_impersonation: bool = True
    impersonate_read_only: bool = True
    enable_jobs: bool = True
    csp_img_sources: tuple[str, ...] = ()
    csp_nonce_getter: Callable[[], str] | None = None
    extra_sensitive_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.page_size < 1 or self.page_size > self.max_page_size:
            raise ValueError("page_size must be between 1 and max_page_size")
        if self.max_page_size < 1 or self.max_page_size > 1000:
            raise ValueError("max_page_size must be between 1 and 1000")
        if self.max_upload_bytes < 1024:
            raise ValueError("max_upload_bytes must be at least 1024 bytes")
        if self.max_import_rows < 1:
            raise ValueError("max_import_rows must be positive")
        if not self.url_prefix.startswith("/"):
            raise ValueError("url_prefix must start with '/'")
        for src in self.csp_img_sources:
            if not is_valid_csp_img_source(src):
                raise ValueError(f"Unsafe csp_img_sources token: {src!r}")
