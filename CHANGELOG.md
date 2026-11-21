# Changelog

All notable changes to `flask-deck` are documented in this file.

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
