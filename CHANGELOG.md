# Changelog

All notable changes to `flask-deck` are documented in this file.

## [0.6.0] - 2026-11-24

### Added
- **Search, Filters & Query Engine 2.0 (`query.py`, `filters.py`):**
  - Tokenized multi-term AND search with quoted phrase support (`tokenize_search_query`), ReDoS-safe O(N) parsing, and configurable `max_search_tokens` / `max_search_length` caps.
  - Django-style search prefix modifiers (`^startswith`, `=exact`, `@fulltext`, default contains) via `parse_search_column_spec` and 1–2 hop relational search across MANYTOONE (`.has()`) and ONETOMANY / MANYTOMANY (`.any()` SQL `EXISTS`) with RBAC hidden/masked/sensitive checks at every hop.
  - Custom `ModelView.get_search_results(stmt, term, user)` hook, `list_select_related` (dotted eager-load chains up to 3 hops), and `scope_query` `.join()`/`.options()` preservation across list, aggregate, kanban, calendar, and tree queries.
  - Built-in `EmptyFieldListFilter` and `RelatedOnlyFieldListFilter`, nullable boolean/FK `(None)` (`__null__`) filter options & facets, expanded date filter presets (`year`, `no_date`, `has_date`), numbered `page_window` pagination, and `show_full_result_count`.
- **Dynamic `ModelView` Hooks, `VirtualField`, Hybrid Batch Edit & Actions 2.0 (`model_view.py`, `routes/crud.py`):**
  - Per-request/per-record dynamic authoring hooks: `get_readonly_fields`, `get_fieldsets`, `get_inlines`, `get_list_display`, `get_actions`, `can_view_record`, `can_edit_record`, `can_delete_record`, `formfield_for_foreignkey`, `formfield_for_manytomany`, `get_changeform_initial_data`, `save_related`, and `validate_batch`.
  - Declarative `VirtualField` via `ModelView.extra_form_fields` coerced into an isolated `virtual_data` dict (never `setattr`'d onto ORM models, preventing mass assignment).
  - Form & list ergonomics: `list_display_links`, `formfield_overrides`, `radio_fields` (`horizontal`/`vertical`), `save_as_continue`, `save_on_top`, `raw_id_fields`, and `Today`/`Now` date/time shortcuts.
  - Hybrid inline table editing (`inline_edit_mode = "instant" | "batch"`): atomic `POST /<slug>/batch-edit` commits with `validate_batch()`, full rollback on any row failure, and per-row audit diffs.
  - `Response`-returning `@action` support (CSV/PDF/JSON downloads with automatic audit + `X-Content-Type-Options: nosniff` + `Cache-Control: private, no-store`), site-level `deck.add_action()` / `deck.disable_action()` / `ModelView.disabled_actions`, and same-model multi-view proxy registration (`is_primary_view`).
- **Rich Inlines 2.0 & Related Controls (`model_view.py`, `routes/api.py`, `routes/ops.py`):**
  - Inline `readonly_fields`, `@display` computed columns, `field_widgets`, `file_fields` (with magic-byte validation, rollback/orphan cleanup, and RBAC/scope-guarded `/_media/<slug>/_inline/<inline_slug>/<field>/<pk>`), `collapsible`/`collapsed`, `extra_on_edit`, `validate_rows()`, composite PK support, and child `scope_query`/soft-delete IDOR isolation.
  - Paginated `/_api/fk/<slug>` (`page`/`has_more` with `"Load more…"`), searchable paginated FK Lookup Drawer (`/_api/<slug>/lookup`), and FK Related Delete (`×` via `/_api/<slug>/<pk>/quick-delete` with Cascade Delete Impact preview).
- **Extensibility, Template/Media Overrides & Startup Checks (`checks.py`, `deck.py`, `diagnostics.py`):**
  - Startup `ModelViewChecks` (`DECK-E001`..`DECK-E012`, `DECK-W001`..`DECK-W002`) — warns in dev/testing and surfaces in `/_diagnostics` & `flask deck audit`; fails fast with `ConfigurationError` in `production` or when `DeckConfig(strict_view_checks=True)`.
  - Path-traversal-safe per-view template overrides (`list_template`, `form_template`, `detail_template`, `history_template`), same-origin `ViewMedia` / `extra_css` / `extra_js` / widget `media_css` & `media_js`, 4 new `BrandConfig.template_slots` (`form_above`, `form_below`, `detail_above`, `detail_below`), and `ModelView.get_urls()` inheriting all Deck security middleware and default RBAC guards.
  - `DeckConfig(site_url=..., empty_value_display=..., sidebar_order=...)`, `ModelView.nav_order`, `@deck.context_processor` (with protected key tamper guard), and clickable `/_category/<cat_slug>` Category Index pages.
- **IAM 2.0, Password Policy, Opt-In Forgot Password, CLI & Full `jsi18n` (`auth.py`, `iam.py`, `routes/iam.py`, `routes/auth.py`, `cli.py`, `i18n.py`):**
  - Targeted SQL queries + per-request caching on `SQLAlchemyAuthProvider` hot paths (eliminating full-table user scans), SQL search/filter/pagination on `/_security/users`, bulk activate/deactivate with last-active-superuser protection, and per-user `direct_permissions` (`_flask_deck_user_permissions`).
  - Pluggable password validators (`MinimumLengthValidator`, `CommonPasswordValidator`, `NumericPasswordValidator`, `UserAttributeSimilarityValidator`, `ComplexityValidator`) with `strict_password_policy=True` option.
  - Opt-in Forgot Password (`Deck(..., password_reset_notifier=callable)`) with SHA-256 hashed single-use 15-minute tokens, anti-enumeration constant-time responses, rate limiting, and full session revocation on reset.
  - CLI `flask deck createsuperuser` and `flask deck changepassword <username>` commands.
  - Expanded EN/TR/DE/AR catalogs and strict-CSP `jsi18n` (`<meta name="deck-i18n">` + `window.__deck.t()`).

### Security & Bug Fixes
- **SQL Console Lexer & Redaction Hardening (`sql_console.py`):** Dialect-aware comment/literal parser closing `\'` SQLite/PG desyncs, nested `/* /* */`, MySQL `/*!`, PG `E'...'`, and PG `#` operator bypasses; parenthesized `(SELECT ...)` redaction; blocked internal IAM/preview/webhook tables from queries and schema browsing; multi-series grouped bar chart rendering.
- **IAM, Impersonation & Record RBAC Guards (`routes/iam.py`, `routes/auth.py`, `routes/api.py`, `routes/ops.py`, `deck.py`):** Blocked wildcard/glob privilege escalation (`**`, `*:*`, `iam:*`, privileged group assignment/edits/deletes) for delegated non-superuser `iam:manage` users; blocked impersonation on password, session, passkey, and API-key endpoints; atomic `is_active` checks on password-reset consumption and deactivated API-key owners; enforced `can_view_record`/`can_edit_record`/soft-delete on notes, media proxy, inline media, and exporter prefix searches; hardened `render_safe_markdown` against `/\evil.com` and URL attribute injection.
- **Data Integrity & ORM Edge Cases (`model_view.py`, `rest_api.py`, `mcp_server.py`, `routes/crud.py`, `routes/governance.py`, `query.py`, `filters.py`, `cascade.py`, `audit.py`):** Preserved existing M2M links in quick-edit drawer; prevented REST/MCP `PATCH` from wiping untouched nullable booleans or shifting naive UTC datetimes; marked inline child audit entries non-revertible and hardened `audit_revert` with dynamic readonly, FK scope, and version bump; fixed composite integer PK creation/import, `EmptyFieldListFilter` on `sa.Enum`, self-referential/multi-FK dotted filter/sort via `aliased()`, `lazy="dynamic"`/`write_only` relationships, non-PK unique FKs and cycle deduplication in cascade analysis, and inline `validate_rows()`/`max_rows` bypass prevention.
- **UI/CSS Polish (`deck.css`, `model_list.html`, `model_form.html`, `sessions.html`, `login.html`, `i18n.py`):** Fixed quick-tabs vertical clipping when filters open, single-row audit date toolbar alignment, tree view wrapped-line indentation, wide FK inputs in 2-column fieldsets, 100% EN/TR/DE/AR template i18n coverage, and demo saved-view/SQL query fixes.

## [0.5.0] - 2026-11-23

### Added
- **Django Admin Parity & Precision Operations (`v0.5.0`):**
  - Declarative `@display` columns, collapsible/horizontal `Fieldset` grids, strict `readonly_fields`, `prepopulated_fields`, `view_on_site`, `field_help_texts`, Slide-Over Related Drawer (`+`/`✏️`/`👁️`), adaptive M2M (`pills`/`dual`/`async`), stacked & tabular inlines (`min_num`/`extra`/`show_change_link`), `save_as`, `preserve_filters`, and `⌘S` dirty-form guards.
  - Single-query SARGable `date_hierarchy`, `ListFilter` / `RangeListFilter` / `PredicateListFilter`, lazy & QuickTab-folded facets (`show_facets="auto"`), `Shift+Click` multi-column sort, `page_size=all`, O(tables) **Cascade Delete Impact Analyzer**, and HMAC-signed cross-page `select_across`.
  - Optional DB-backed 4-Level RBAC IAM (`SQLAlchemyAuthProvider`, `/_security/users`, `/_security/groups`, `/_security/password`) and Vercel Demo Safe Mode.

## [0.4.0] - 2026-11-23

### Added
- **Security Hardening & Multi-Worker Scale (`v0.4.0`):**
  - Encrypted TOTP MFA secrets & recovery codes at rest via `SecretCipher` (`flask-deck[crypto]` / HKDF + HMAC-SHA256 fallback).
  - Multi-worker SQLAlchemy stores (`SQLAlchemyMFAStore`, `SQLAlchemySessionStore`, `SQLAlchemyPasskeyStore`, `SQLAlchemyApprovalStore`, `SQLAlchemySavedViewStore`, `SQLAlchemyRecordNoteStore`, `SQLAlchemyAPIKeyStore`, `SQLAlchemySavedQueryStore`, `SQLAlchemyPreviewStore`, `SQLAlchemyRateLimitStore`, `SQLAlchemyJobBackend`, `SQLAlchemyWebhookDeliveryStore`) + `RedisPreviewStore` / `RedisRateLimitStore` (`flask-deck[redis]`).
  - Passkeys / WebAuthn (`flask-deck[webauthn]`), Server-Side Active Sessions Registry & Remote Revocation (`/_security/sessions`), and Hash-Chained Tamper-Evident Audit Ledger (`hash_chain=True`, `verify_chain()`).
- **Governance & Collaborative Operations:**
  - Declarative **Four-Eyes Approval Workflows (`approval_required`)** across creates, edits, deletes, bulk actions, REST API mutations (`202 Accepted`), and AI-agent MCP proposals (`/_approvals`).
  - Field-level **Optimistic Concurrency Control (OCC)** with 3-way conflict resolution UI & REST `ETag` / `If-Match` `409 Conflict` enforcement.
  - Server-backed Personal / Team / Role-Default **Saved Views** and Markdown-subset **Operational Record Notes**.
- **Headless REST API v1 & HITL MCP Server:**
  - Scoped SHA-256 **API Keys** (`dk_live_...`) with IP CIDR allowlists & sliding-window `429 Retry-After` rate limiting (`/_security/api-keys`).
  - OpenAPI 3.1.0 **REST API v1 (`/_api/v1/...`)** with cursor/offset pagination, RBAC field scoping/masking, partial PATCH safety, and Maker-Checker approvals.
  - JSON-RPC 2.0 **Model Context Protocol (MCP) Server** (`POST /_mcp` & `flask deck mcp` stdio) with savepoint-validated HITL proposals and origin-rebinding protection.
- **Workspace 2.0 & SQL Workbench 2.0 / Self-Service BI:**
  - Multi-viewswitcher: **Calendar** (`calendar_date_field`), **Gallery** (`gallery_image_field`), and cycle-safe **Tree Hierarchy** (`tree_parent_field`).
  - Universal inline table editing across scalars (`string`, `integer`, `float`, `decimal`, `date`, `boolean`, `enum`), `row_action=True`, clickable FK chips, and **1-to-N Related Sub-Tables** on record detail.
  - Whole-dataset formatter-aware **Summary Aggregates (`aggregate_scope="all"`)**, dotted MANYTOONE filters (`org.tier`), `__in` / `__not_in` / dialect-aware `__fts` search, multi-bind SQL Schema Browser, `EXPLAIN` plan mode, pure-SVG Bar/Line charts, Saved BI Queries pinned to `/`, and SQL `GROUP BY` time-range trends (`7d/14d/30d/90d`).
- **Import/Export 2.0, ORM Introspection 2.0 & Developer CLI:**
  - Interactive **Column Mapping Wizard**, downloadable formula-safe **Failed Rows CSV**, async background import commits (`max_sync_import_rows`), and optional lazy **XLSX** import/export (`flask-deck[excel]`).
  - ORM **Introspection 2.0** (`TypeDecorator` unwrapping, `column_property`, `hybrid_property`, Joined-Table Inheritance), strict-CSP **`widgets.py`** (`CodeWidget`, `MarkdownWidget`, `ColorWidget`, `TagInputWidget`, `SliderWidget`, `JSONSchemaWidget`), interactive **SVG ERD** clickable links + zoom controls, **`flask deck scaffold`**, **`flask deck audit --format json|sarif`** (SARIF 2.1.0), and zero-dependency **`flask-lens`** diagnostics auto-detection.

## [0.3.0] - 2026-11-21

### Added
- **Pillar 1 — First-Class Media, File Uploads & Object Storage (`storage.py`):**
  - Pluggable `StorageBackend` protocol with `LocalFileStorage` (path-traversal-proof atomic writes), `S3StorageBackend` (AWS S3 / Cloudflare R2 / MinIO with lazy optional `boto3`), and `MemoryFileStorage`.
  - Pure-Python magic-byte MIME validation (blocking SVG XSS by default) and PNG/JPEG/GIF/WebP header decompression-bomb protection (`max_image_pixels`) with zero Pillow dependency.
  - Declarative `ModelView.file_fields` (`FileFieldConfig`) with drag-and-drop upload dropzone, instant DataURL image preview, atomic replace/delete cleanup, `ImageFormatter` + click-to-open **Image Lightbox Modal**, `FileFormatter`, and RBAC + `scope_query`-guarded `/_media/<slug>/<field>/<pk>` streaming proxy (`X-Content-Type-Options: nosniff`, `Content-Disposition: attachment`).
- **Pillar 2 — Enterprise i18n, Native RTL & Per-User Timezones (`i18n.py`):**
  - `Translator` protocol with built-in zero-dependency `DictTranslator` (`en`, `tr`, `de`, `ar` RTL catalogs) and optional `BabelTranslator` (`flask-deck[babel]`).
  - Native CSS Logical Properties (`margin-inline`, `padding-inline`, `inset-inline`, `border-inline`) powering seamless `dir="rtl"` right-to-left layouts without a second stylesheet.
  - Stdlib `zoneinfo.ZoneInfo` UTC ↔ user-timezone conversion (`DateTimeFormatter`, locale/TZ-aware `CurrencyFormatter` & `RelativeTimeFormatter`) + interactive Topbar Locale & Timezone switcher (`/_preferences`).
- **Pillar 3 — Strict-CSP Brand Customization & Safe Extension Slots (`branding.py`):**
  - `BrandConfig` supporting preset (`cobalt`, `emerald`, `amber`, `crimson`, `slate`, `monochrome`) or validated `#RRGGBB` custom accents with automatic WCAG 2.1 contrast calculation, custom `logo_url`/`logo_dark_url`/`favicon_url`, login page title/subtitle/notice, same-origin `extra_css`/`extra_js`, and 7 allowlisted `template_slots`.
  - Dynamic brand variables served via external `/_theme.css` (SHA-256 cached, `style-src 'self'`) — preserving **0 `'unsafe-inline'`** and **0 `<style>` tags**.
- **Pillar 4 — Enterprise Auth: Built-In Pure-Python TOTP 2FA, OIDC/OAuth2 SSO & Audited Impersonation (`mfa.py`, `sso.py`):**
  - RFC 6238 TOTP (`generate_totp_secret`, `compute_totp`, `verify_totp`) with per-user timestep replay prevention, PBKDF2 single-use recovery codes, `InMemoryMFAStore` / `SQLAlchemyMFAStore`, and a **pure-Python ISO/IEC 18004 QR Code → Strict-CSP SVG encoder** (`/_security/mfa`, `/login/mfa`).
  - `OIDCAuthProvider` with PKCE `S256`, `state`/`nonce` CSRF protection, `allowed_domains`, and IdP group-to-role mapping (`/login/sso/<provider>`).
  - Superuser **User Impersonation** (`/_impersonate/start` & `/stop`) with full session audit attribution (`impersonated_by`), immutable audit trail, and persistent amber topbar banner.
- **Pillar 5 — Scale-Out Query Engine & PostgreSQL Native Power (`query.py`, `adapters/sqlalchemy.py`):**
  - **HMAC-SHA256 Signed Keyset Cursor Pagination** (`pagination_mode="cursor"`, `LIMIT N+1`, opaque `after`/`before` cursors) eliminating `OFFSET` scan degradation on multi-million-row tables.
  - `count_mode="estimated"` (`pg_class.reltuples` O(1) count on PostgreSQL) and `count_mode="none"`.
  - Multi-database / multi-bind SQLAlchemy support (`binds={"analytics": engine}`) with per-`ModelView` `bind_key`.
  - Dialect-aware **PostgreSQL `JSONB` & `ARRAY` native filtering** (`?`, `->>`, `#>>`, `@>`, `&&` on Postgres; `json_type`/`json_extract` fallback on SQLite) + structured multi-operator filter rule builder (`eq`, `neq`, `contains`, `gt`, `gte`, `lt`, `lte`, `is_null`, `not_null`, `has_key`, `contains_any`).
- **Pillar 6 — Intelligent Dynamic Forms & Validation (`model_view.py`, `model_form.html`):**
  - **Conditional Field Visibility (`field_conditions`)** (`data-show-when` zero-latency DOM toggling + server-side validation awareness).
  - **Cascading Dependent Foreign Keys (`dependent_fields`)** filtering `/_api/fk/<slug>` choices dynamically by parent field (`dep_col`/`dep_val`).
  - **Multi-Step Form Wizard (`form_layout="wizard"`)** with numbered stepper navigation, client validation per step, and automatic error-step focus.
  - Native **`ARRAY` Tag-Chip Editor** (`sa.ARRAY` introspection + interactive chips) and pluggable **`form_validator` + `pydantic_validator(Schema)`** adapter (`flask-deck[pydantic]`).
- **Pillar 7 — Record Lifecycle: Soft-Delete Trash & Side-by-Side Revision Diffs (`model_view.py`, `deck.py`, `record_history.html`):**
  - Declarative `soft_delete_column` with automatic active-list filtering, single-pass `CASE` Trash tab counter, `?trashed=1` Trash view, one-click **Restore** (`/<slug>/<pk>/restore`), and confirmed **Force Delete** (`force=1`).
  - Per-record **Side-by-Side Revision History & Visual Diff** (`/<slug>/<pk>/history`) comparing `Before`, `After`, and `Current Live` values with one-click Safe Revert.
- **Pillar 8 — Background Jobs, Real-Time SSE Streaming & SSRF-Safe Webhooks (`jobs.py`, `events.py`, `jobs_list.html`):**
  - Pluggable `JobBackend` protocol with `ThreadPoolJobBackend` (Flask `app_context` propagation, bounded log ring, cooperative cancellation, downloadable file artifacts).
  - `@action(..., async_job=True)` for background bulk jobs, **Background CSV Export** (`/<slug>/export-async`), live `/_jobs` console with **Server-Sent Events (`/_api/jobs/<id>/stream`)** real-time progress bar & logs, cancel, and artifact download.
  - Typed `DeckEventBus` (`@deck.on("record.updated")`) and SSRF-hardened HMAC-SHA256 `WebhookSink` blocking loopback, RFC 1918 private, link-local, and cloud metadata IPs (`169.254.169.254`, `127.0.0.1`, `::1`).

## [0.2.0] - 2026-11-21

### Added
- **Data Workspace Upgrades (`ModelView` & Grid):**
  - **Kanban Board Mode (`?view=board`)**: Opt-in status-lane board via `kanban_column` with HTML5 drag-and-drop transitions, full CSRF + RBAC + `scope_query` + audit logging, plus Table / Board toggle pills.
  - **Table Summary Footer (`column_aggregates`)**: Page-scoped `sum`, `avg`, `min`, `max`, and `count` footer totals aligned with `tabular-nums` and formatted via column formatters.
  - **Saved Filter Presets (`saved_views`)**: Declarative 1-click saved view pills synchronized cleanly with URL query parameters.
  - **Parameterized Bulk Actions (`ActionField`)**: `@action(..., fields=(ActionField(...),))` renders a strict-CSP modal form (`text`, `textarea`, `select`, `number`, `checkbox`) for structured bulk workflows (e.g., refund reason, stock delta) with safe `form_data` coercion.
  - **Clone / Duplicate Record (`?clone=<pk>`)**: Pre-fills the Create form from an existing record while stripping PKs, unique fields, readonly/hidden/sensitive fields, and honoring `scope_query`.
  - **Grid Density Switcher & Linear-Style Keyboard Shortcuts**: `Compact / Normal` density toggle (`localStorage`), `j`/`k` row cursor, `Space` row select, `Enter` Quick Peek, `c` create, `g d` dashboard, `g a` audit, `?` shortcuts cheat sheet, and hover click-to-copy on `CodeFormatter(copyable=True)`.
- **Rich Form Inputs & Layouts:**
  - **Tabbed Forms & 2-Column Sections (`form_layout`)**: Clean multi-tab form navigation (auto-activates the first tab containing validation errors) and responsive 2-column section grids.
  - **Zero-Dependency Custom Input Widgets (`field_widgets`)**: `SegmentedControlWidget`, `SwitchWidget`, `TagInputWidget`, `SliderWidget`, `CodeEditorWidget` (with JSON format & syntax validation), and `MarkdownPreviewWidget` (strict-CSP safe preview).
- **Dashboard & Analytics Visualization Suite (100% Pure SSR SVG, Strict CSP):**
  - **`HeatmapWidget`**: 91-day GitHub-style activity calendar with 5-level intensity scale and interactive hover tooltips.
  - **`StatBarWidget`**: Horizontal ranked progress breakdown bars (e.g., top products by revenue).
  - **`GaugeWidget`**: Semi-circular radial SLA/utilization meter with semantic threshold coloring.
  - **`ChartWidget(kind="grouped_bar")`**: Multi-series side-by-side comparison bar charts with legend.
  - **`TimelineWidget`**: Chronological event feed with semantic status dots.
  - **`CalloutWidget`**: Dismissible/contextual `info`, `ok`, `warn`, and `danger` operational alerts.
  - **Dashboard Date Range Selector (`7d` / `30d` / `90d`)**: Passes `ctx.range_days` into dashboard builders and custom pages.
- **Built-In Operations & Developer Modules:**
  - **Interactive Schema ERD (`/admin/_schema`)**: Pure SVG topological entity-relationship graph inspecting SQLAlchemy models, PK/FK keys, cardinalities, indexes, and quick links to each model grid.
  - **Security & Performance Diagnostics (`/admin/_diagnostics`)**: Live browser view of the `flask deck audit` checks, session/CSP posture, SQLAlchemy engine telemetry, and unindexed `searchable_columns` warnings.
  - **Hardened Read-Only SQL Console (`/admin/_sql`)**: Superuser-gated opt-in (`enable_sql_console=True`) SQL workbench with multi-layer read-only AST/regex firewall (`SELECT`/`WITH`/`EXPLAIN` only), statement blocking, auto-`LIMIT`, automatic `[REDACTED]` masking on sensitive columns, and sanitized CSV export.
  - **Custom Pages SDK (`@deck.page(...)`)**: Build full custom operations pages (e.g., `/admin/_page/sla-capacity`) using the same widget grid, RBAC permission gating, sidebar navigation, and `⌘K` indexing.
- **3-Tab Quick Peek Drawer, Topbar Notification Bell & Demo Role Switcher:**
  - Quick Peek Drawer upgraded with **Overview**, **Relations** (lazy preview of related child records), and **Audit** tabs.
  - Topbar Activity Bell lazily loads recent audit events via `/admin/_api/notifications` without adding queries to normal page loads.
  - Bottom-left `SESSION ROLE` switcher for instant 1-click RBAC switching (`Admin` / `Support` / `Viewer`) in demos — strictly forbidden when `environment == "production"`.

## [0.1.0] - 2026-11-21

### Added
- **SQLAlchemy 2.0 & Flask-SQLAlchemy Dual Adapter**: Full support for `DeclarativeBase` + `Mapped[]`, composite primary keys, relationships, and request-scoped session management.
- **Carbon Dark & Swiss Light Precision Workbench UI**: Zero Node build, zero CDN, `<12 KB` gzipped CSS + vanilla ES6 JS, `44px` topbar, `228px` rail, `28px` live SQL telemetry status bar.
- **Global `⌘K` Command Palette**: Instant keyboard navigation across models, quick actions, and RBAC-scoped live cross-model record search.
- **Composable Dashboard & Pure SVG Charts**: Auto-generated fallback dashboard plus `KPIWidget`, `ChartWidget` (`area`, `bar`, `donut`), `TableWidget`, `ActivityWidget`, and `MarkdownWidget` with interactive hover tooltips and zero third-party chart JS.
- **Power Data Grid**: Single-pass `CASE` Quick Filter Tabs, faceted filters, URL-synced state, column visibility persistence, Slide-Over Quick Peek Drawer, Inline Quick-Edit, and Floating Bulk Action Dock with Type-to-Confirm safeguards.
- **Smart Forms & Relations**: Tabbed fieldsets, async searchable FK combobox, M2M tag multi-select, JSON editor, and inline One-to-Many child record management with parent-ownership IDOR protection.
- **Dry-Run Savepoint Import & Streaming Export**: `SAVEPOINT` + guaranteed `ROLLBACK` CSV/JSON import preview with visual field-level diffs, single-use user/session-bound preview tokens, `O(1)`-RAM streaming export, and CSV formula-injection neutralization.
- **Fail-Closed Auth & 4-Level RBAC**: `BasicAuthProvider`, `RBACAuthProvider`, `FlaskLoginAuthProvider`, explicit opt-in `OpenAuthProvider`, sliding-window login brute-force throttler, session fixation & timeout guards, field masking/read-only/hidden rules, multi-tenant `scope_query`, and `/admin/_rbac` visual matrix.
- **Field-Level Audit Log & Safe Revert**: `SQLAlchemyAuditStore` and bounded `InMemoryAuditStore` with automatic sensitive field redaction (`[REDACTED]`), visual diff timeline, per-record history, and one-click safe revert.
- **Hardened Security Middleware**: Strict per-request nonce CSP with zero `'unsafe-inline'`, double-layer CSRF + `Sec-Fetch-Site`, `no-store` caching on admin responses, and `flask deck audit` CLI security + index checker.
