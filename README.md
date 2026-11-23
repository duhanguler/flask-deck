<p align="center">
  <img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/banner.svg" alt="flask-deck — Precision Enterprise Admin Panel and Operations Workbench for Flask and SQLAlchemy 2.0" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/duhanguler/flask-deck/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/duhanguler/flask-deck/ci.yml?branch=main&style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://pypi.org/project/flask-deck/"><img src="https://img.shields.io/pypi/v/flask-deck?style=flat-square&color=0D7A52&logo=pypi&logoColor=white" alt="PyPI" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%20--%203.13-18181b?style=flat-square&logo=python&logoColor=white" alt="Python 3.10-3.13" />
  <img src="https://img.shields.io/badge/Flask-2.3%2B%20%7C%203.x-18181b?style=flat-square&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0%2B-18181b?style=flat-square&logo=sqlalchemy&logoColor=white" alt="SQLAlchemy 2.0+" />
  <img src="https://img.shields.io/badge/Assets-17.3%20KB%20core%20gz-18181b?style=flat-square" alt="17.3 KB core gzip" />
  <img src="https://img.shields.io/badge/CSP-Strict%20Nonce-18181b?style=flat-square" alt="Strict Nonce CSP" />
  <a href="https://github.com/duhanguler/flask-deck/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-18181b?style=flat-square" alt="MIT License" /></a>
</p>

# flask-deck

**A precision, fail-closed Enterprise & AI-Agent Operations Control Plane for Flask and SQLAlchemy 2.0** — engineered for teams that want the visual craft of **Django-Unfold / Filament / Linear** plus enterprise IAM (SSO, Passkeys, encrypted TOTP), four-eyes Maker-Checker approvals, hash-chained audit ledgers, headless REST API v1, HITL MCP agent tooling, media storage, i18n/RTL, and SQL BI charts on WSGI — without shipping Bootstrap, jQuery, Node build pipelines, or external CDNs.

- **Zero Node Build · Zero External CDN · `< 22 KB` Core / `< 32 KB` Route gzip budgets** (`9.81 KB` CSS + `7.46 KB` core JS = `17.26 KB` gzip core; modular grid/form/ops route totals `19.76–25.34 KB` gzip + pure SSR SVG visualizations & QR codes). Runs out of the box in air-gapped enterprise environments.
- **Carbon Dark, Swiss Light & Strict-CSP Brand Themes**: `1px` hairline grids, `tabular-nums`, CSS Logical Properties for native **RTL**, custom `#RRGGBB` brand accents served over external `/_theme.css` (auto WCAG 2.1 contrast, **0 `'unsafe-inline'`**), and 7 allowlisted extension slots.
- **Beyond Django Admin — Precision Operations & Control Plane (`v0.5.0`)**:
  1. **Declarative ModelView & Form Craft**: SQL-sortable `@display` columns, collapsible/horizontal `Fieldset` grids, strict `readonly_fields` mass-assignment barriers, `prepopulated_fields`, `view_on_site`, `field_help_texts`, Slide-Over Related Drawer (`+`/`✏️`/`👁️`) without losing parent edits, adaptive M2M (`pills` / `dual` / `async`), stacked & tabular rich inlines (`min_num` / `extra` / `show_change_link`), `save_as`, `save & continue`, `preserve_filters`, and dirty-form `⌘S` guards.
  2. **Query Intelligence & Safe Mass Operations**: Single-query SARGable `date_hierarchy`, declarative `ListFilter` / `RangeListFilter` / `PredicateListFilter`, lazy & QuickTab-folded faceted counts (`show_facets="auto"`), `Shift+Click` 3-level multi-column sort, inline FK quick-edit, `page_size=all`, O(tables) SQL **Cascade Delete Impact Analyzer**, and HMAC-signed cross-page **`select_across`** with automatic 200-row chunked background job offload.
  3. **Optional DB-Backed 4-Level RBAC IAM & Enterprise Governance**: `SQLAlchemyAuthProvider` (`/_security/users`, `/_security/groups`, `/_security/password`) with last-active-superuser protection and visual permission matrix, alongside encrypted TOTP 2FA (`SecretCipher`), WebAuthn **Passkeys**, PKCE OIDC SSO, Session Registry (`/_security/sessions`), Four-Eyes **Approval Workflows (`/_approvals`)**, 3-way **OCC**, Server-Side **Saved Views & Notes**, and Hash-Chained **Audit Ledger (`verify_chain()`)**.
  4. **Headless REST API v1, HITL MCP Server & BI SQL**: Scoped Bearer **API Keys** (`dk_live_...`, CIDR allowlist, sliding-window throttling), OpenAPI 3.1.0 `/_api/v1/...`, JSON-RPC 2.0 **MCP Server**, multi-mode **Table / Kanban / Calendar / Gallery / Tree** views, **DRY-RUN Savepoint CSV/JSON/XLSX Import**, multi-bind SQL BI Workbench, and `flask-lens` diagnostics.

---

### Try the Live Demo in 5 Seconds

```bash
uvx flask-deck demo
# or
pip install flask-deck && flask-deck demo
```

Open `http://127.0.0.1:5055/admin/` and explore the **`showcase`** control-plane seed (32 orgs, 48 users, 18 products with thumbnails, 120 orders across 90 days, 42 tickets, 22 infrastructure tree nodes, 36 hash-chained audit entries, pending AI-agent/human approvals, saved SQL BI queries, API keys, webhooks & jobs):
- **Live DB-Backed IAM & Role Switching**: Powered by `SQLAlchemyAuthProvider` — use the bottom-left **SESSION ROLE** switcher (`Admin` / `Support` with live email PII masking / `Viewer` read-only), manage DB users & visual permission groups on `/admin/_security/users` and `/admin/_security/groups`, or rotate passwords on `/admin/_security/password`.
- **Workspace & Query Intelligence**: Try `date_hierarchy` drilldowns, `RangeListFilter` / `ListFilter` with lazy facets, `Shift+Click` multi-column sorting, Slide-Over Related Drawer (`+`/`✏️`) inside `/admin/orders/`, and Cascade Delete Impact previews before deleting records.
- **Four-Eyes Approvals, Hash-Chained Audit & BI SQL**: Review pending AI-agent (`mcp-agent`) & human requests on `/admin/_approvals`, verify ledger integrity on `/admin/_audit`, or chart & pin BI queries on `/admin/_sql`.
- **IAM, Headless APIs, Jobs & Arabic RTL**: Visit `/admin/_security/mfa`, `/admin/_security/passkeys`, `/admin/_security/sessions`, `/admin/_security/api-keys`, `/admin/_webhooks`, `/admin/_jobs`, or switch to **العربية (AR)** + `Europe/Istanbul` in the topbar Globe popover.

#### Deploy Live Demo on Vercel

`flask-deck` includes a zero-config Vercel Flask entrypoint ([app.py](https://github.com/duhanguler/flask-deck/blob/main/app.py)) and [vercel.json](https://github.com/duhanguler/flask-deck/blob/main/vercel.json) scheduled reset configuration:
- **Daily `00:00` (`Europe/Istanbul`) Auto-Reset:** Vercel Schedules invokes `POST /api/cron/reset-demo` daily at `00:00 Europe/Istanbul` (protected by Bearer `CRON_SECRET`), and an in-process day-rollover guard automatically resets ephemeral/persistent demo state across midnight on the next request.
- **Optional Environment Variables:** `CRON_SECRET` (recommended on Vercel), `DATABASE_URL` / `FLASK_DECK_DEMO_DB_URI` (optional Postgres backing), `FLASK_DECK_SECRET_KEY`, `FLASK_DECK_DEMO_PROFILE` (`showcase` default or `standard`), `FLASK_DECK_AUTO_DAILY_RESET` (`1` default), `FLASK_DECK_RESET_TIMEZONE` (`Europe/Istanbul` default).

Optional extras (zero mandatory bloat in the base wheel):

```bash
pip install "flask-deck[s3]"          # boto3 for S3 / R2 / MinIO
pip install "flask-deck[babel]"       # Flask-Babel / Babel catalog integration
pip install "flask-deck[pydantic]"    # Pydantic v2 form validation adapter
pip install "flask-deck[excel]"       # openpyxl for .xlsx import & export
pip install "flask-deck[webauthn]"    # Passkeys / WebAuthn support
pip install "flask-deck[sso]"         # authlib for OIDC / OAuth2 SSO
pip install "flask-deck[redis]"       # Redis rate-limit & import preview stores
pip install "flask-deck[enterprise]"  # Full enterprise bundle
```

---

### Carbon Dark, Swiss Light & Enterprise Workbench Gallery

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/dashboard-dark.png" />
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/dashboard-light.png" />
    <img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/dashboard-dark.png" alt="flask-deck Carbon Dark & Swiss Light Dashboard Workbench" width="100%" />
  </picture>
</p>

<details>
  <summary>Explore All 18 Workbench &amp; Enterprise Views (Media Lightbox, 3-Step Wizard, Keyset Cursor &amp; Trash, TOTP QR, Side-by-Side Diff, Background SSE Jobs, Arabic RTL, Kanban, Heatmap, ERD, SQL Console &amp; More)</summary>
  <br />
  <p align="center"><strong>Products Media Grid &amp; Click-to-Open Image Lightbox (RBAC-Guarded <code>/_media</code> Proxy)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-products-lightbox-dark.png" alt="flask-deck Products Media Lightbox" width="100%" /></p>
  <p align="center"><strong>Multi-Step Form Wizard with Drag-and-Drop Image Upload &amp; Live DataURL Preview</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-wizard-dropzone-dark.png" alt="flask-deck 3-Step Form Wizard and Dropzone" width="100%" /></p>
  <p align="center"><strong>HMAC-Signed Keyset Cursor Pagination &amp; Soft-Delete Trash / One-Click Restore</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-cursor-trash-dark.png" alt="flask-deck Keyset Cursor Pagination and Trash Restore" width="100%" /></p>
  <p align="center"><strong>Built-In TOTP 2FA Enrollment with Pure-Python ISO/IEC 18004 SVG QR Code (Zero External Libs)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-mfa-qr-dark.png" alt="flask-deck TOTP 2FA Setup with Pure-Python SVG QR" width="100%" /></p>
  <p align="center"><strong>Per-Record Side-by-Side Revision Diff History &amp; Safe Revert (<code>/&lt;slug&gt;/&lt;pk&gt;/history</code>)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-revision-diff-dark.png" alt="flask-deck Side-by-Side Revision Diff" width="100%" /></p>
  <p align="center"><strong>Background Jobs Console with Live SSE Progress, Logs &amp; Artifact Download (<code>/_jobs</code>)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-jobs-sse-dark.png" alt="flask-deck Background Jobs and SSE Logs" width="100%" /></p>
  <p align="center"><strong>Native Arabic RTL (<code>dir="rtl"</code>) &amp; Per-User Timezone (<code>Europe/Istanbul</code>) via CSS Logical Properties</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/v03-rtl-arabic-dark.png" alt="flask-deck Arabic RTL Dashboard" width="100%" /></p>
  <p align="center"><strong>Swiss Light Theme (Range Switcher + Callout + Pure SVG Area &amp; Donut Charts)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/dashboard-light.png" alt="flask-deck Swiss Light Dashboard" width="100%" /></p>
  <p align="center"><strong>91-Day Activity Heatmap &amp; Ranked Stat Progress Bars (100% Pure SSR SVG)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/heatmap-dark.png" alt="flask-deck 91-Day Activity Heatmap and Stat Bars" width="100%" /></p>
  <p align="center"><strong>Drag-and-Drop Kanban Board Mode (CSRF + RBAC + Audit Logged Transitions)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/kanban-dark.png" alt="flask-deck Orders Kanban Board" width="100%" /></p>
  <p align="center"><strong>Tabbed Forms &amp; Zero-Dependency Rich Widgets (Segmented Pills, Toggle Switch, Tag Input, Code Editor)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/form-widgets-dark.png" alt="flask-deck Tabbed Form and Rich Widgets" width="100%" /></p>
  <p align="center"><strong>Interactive SQLAlchemy Schema ERD Inspector (<code>/admin/_schema</code>)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/schema-erd-dark.png" alt="flask-deck Pure SVG Schema ERD" width="100%" /></p>
  <p align="center"><strong>Hardened Read-Only SQL Console with Automatic <code>[REDACTED]</code> Secret Masking (<code>/admin/_sql</code>)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/sql-console-dark.png" alt="flask-deck Read-Only SQL Console with Redaction" width="100%" /></p>
  <p align="center"><strong>Custom <code>@deck.page</code> Operations View (Radial SLA Gauge + Grouped Bar + Timeline)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/sla-page-dark.png" alt="flask-deck Custom SLA and Capacity Page" width="100%" /></p>
  <p align="center"><strong>Global ⌘K Command Palette (RBAC-Scoped Cross-Model Live Search)</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/cmdk-dark.png" alt="flask-deck Command Palette" width="100%" /></p>
  <p align="center"><strong>Orders Grid + Quick Filter Tabs + 3-Tab Slide-Over Quick Peek Drawer</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/orders-drawer-dark.png" alt="flask-deck Slide-Over Quick Peek Drawer" width="100%" /></p>
  <p align="center"><strong>SAVEPOINT-Verified Dry-Run CSV/JSON Diff Import</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/import-diff-dark.png" alt="flask-deck Dry-Run Import Diff Preview" width="100%" /></p>
  <p align="center"><strong>Immutable Audit Ledger with Field-Level Diffs, Auto-Redaction &amp; Safe Revert</strong></p>
  <p align="center"><img src="https://raw.githubusercontent.com/duhanguler/flask-deck/main/docs/assets/audit-dark.png" alt="flask-deck Audit Diff Ledger" width="100%" /></p>
</details>

---

## 5-Line Quickstart

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_deck import BasicAuthProvider, BrandConfig, Deck

app = Flask(__name__)
app.config["SECRET_KEY"] = "replace-with-32-byte-random-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
db = SQLAlchemy(app)

deck = Deck(
    app,
    db,
    auth=BasicAuthProvider.from_plain_passwords({"admin": "change-me"}),
    title="Acme Ops",
    brand=BrandConfig(accent="cobalt", login_subtitle="Operations Control Plane"),
)
deck.register(Organization, User, Product, Order)
```

Using **pure SQLAlchemy 2.0** without `Flask-SQLAlchemy`? Pass `session_factory=SessionLocal, engine=engine` (and optional multi-DB `binds={"analytics": analytics_engine}`) directly — see [examples/pure_sqlalchemy_app.py](https://github.com/duhanguler/flask-deck/blob/main/examples/pure_sqlalchemy_app.py).

---

## Declarative `ModelView`: Media, Wizards, Cursor Pagination, Soft-Delete & Async Jobs

```python
from types import MappingProxyType
from flask_deck import (
    CodeFormatter,
    CurrencyFormatter,
    FileFieldConfig,
    FileFormatter,
    ImageFormatter,
    LocalFileStorage,
    ModelView,
    action,
)

uploads = LocalFileStorage("./uploads")


class ProductView(ModelView):
    model = Product
    icon = "package"
    category = "Catalog"
    columns = ("thumbnail_key", "sku", "name", "price_cents", "stock", "spec_key")
    filterable_columns = ("category", "is_active", "specs_json")

    # 3-Step Form Wizard + Secure File/Image Fields
    form_layout = "wizard"
    fieldsets = (
        ("Catalog Identity", ("sku", "name", "category", "is_active")),
        ("Pricing & Media", ("price_cents", "stock", "thumbnail_key", "spec_key")),
        ("Structured Metadata", ("specs_json",)),
    )
    file_fields = MappingProxyType({
        "thumbnail_key": FileFieldConfig(
            storage=uploads,
            kind="image",
            prefix="products/thumbnails",
            max_bytes=2 * 1024 * 1024,
        ),
        "spec_key": FileFieldConfig(
            storage=uploads,
            kind="file",
            prefix="products/specs",
            allowed_mimes=frozenset({"application/pdf"}),
            max_bytes=10 * 1024 * 1024,
        ),
    })
    column_formatters = MappingProxyType({
        "thumbnail_key": ImageFormatter(alt_prefix="Product"),
        "sku": CodeFormatter(copyable=True),
        "price_cents": CurrencyFormatter(currency="USD", divisor=100),
        "spec_key": FileFormatter(),
    })


class OrderView(ModelView):
    model = Order
    icon = "shopping-bag"
    category = "Commerce"
    columns = ("order_number", "organization", "customer", "status", "total_cents", "created_at")
    searchable_columns = ("order_number", "organization.name", "customer.email")
    filterable_columns = ("status", "organization_id", "total_cents", "created_at")
    inline_editable_columns = ("status",)
    inlines = (OrderItemInline,)

    # Opt-in Kanban Board + Page Summary Footer + Cascading FK + Conditional Visibility
    kanban_column = "status"
    kanban_card_fields = ("order_number", "organization", "total_cents")
    column_aggregates = MappingProxyType({"total_cents": "sum"})
    field_widgets = MappingProxyType({"status": "segmented", "notes": "markdown"})
    saved_views = (("High Value", "?f_total_cents__gte=100000"),)
    dependent_fields = MappingProxyType({"customer_id": ("organization_id", "organization_id")})
    field_conditions = MappingProxyType({"notes": ("status", "in", ("refunded", "cancelled"))})

    @action("sync_erp", label="Sync to ERP (Background Job)", icon="activity", async_job=True)
    def sync_erp(self, records, form_data, user, job_ctx):
        total = max(len(records), 1)
        for idx, order in enumerate(records, start=1):
            if job_ctx.is_cancelled():
                return "ERP sync cancelled."
            job_ctx.set_progress(int(idx * 100 / total), f"Synced {order.order_number}")
        return f"Synced {len(records)} order(s) to ERP."


class TicketView(ModelView):
    model = Ticket
    pagination_mode = "cursor"        # HMAC-signed keyset cursor (LIMIT N+1)
    count_mode = "estimated"          # O(1) pg_class.reltuples on PostgreSQL
    soft_delete_column = "deleted_at" # Automatic Trash tab, Restore & Force Delete
```

---

## Events, Webhooks & Custom Operations Pages

```python
from flask_deck import WebhookSink

# Typed in-process event bus
@deck.on("record.updated")
def on_record_updated(event):
    print(f"{event.actor_name} updated {event.model_slug}#{event.record_pk}")

# SSRF-hardened HMAC-SHA256 webhook sink (blocks loopback, RFC 1918, CGNAT & 169.254.169.254)
deck.add_webhook(
    WebhookSink(
        url="https://hooks.example.com/admin-events",
        secret="whsec_replace_me",
        events=frozenset({"record.created", "record.deleted", "action.executed"}),
    )
)
```

---

## Governance, Workspace 2.0 Views & AI-Agent Control Plane (`v0.4.0`)

```python
from flask_deck import (
    CodeWidget,
    ColorWidget,
    Deck,
    ModelView,
    SliderWidget,
    TagInputWidget,
)

class InfrastructureNodeView(ModelView):
    model = InfrastructureNode
    tree_parent_field = "parent_id"       # Cycle-safe Tree Hierarchy (?view=tree)
    tree_title_field = "name"
    calendar_date_field = "created_at"    # Opt-in Month Calendar (?view=calendar)
    gallery_image_field = "thumb_key"     # Opt-in Media Gallery (?view=gallery)
    aggregate_scope = "all"               # Whole-filtered dataset summary footer
    approval_required = ("edit", "delete")  # Four-Eyes Maker-Checker workflow
    field_widgets = {
        "accent_color": ColorWidget(),
        "health_pct": SliderWidget(min_value=0, max_value=100, unit="%"),
        "labels": TagInputWidget(),
        "topology_yaml": CodeWidget(language="yaml", rows=6),
    }

deck = Deck(
    app,
    db,
    auth=auth,
    enable_sql_console=True,
    enable_rest_api=True,      # OpenAPI 3.1.0 REST API at /admin/_api/v1/...
    enable_mcp=True,           # JSON-RPC 2.0 MCP Server at POST /admin/_mcp
    mcp_require_approval=True, # AI-agent writes validate via SAVEPOINT -> /_approvals
)
```

Run the local stdio MCP server for desktop AI clients with `flask --app yourapp deck mcp`.

---

## Beyond Django Admin: Query Intelligence, Cascade Safety & DB-Backed IAM (`v0.5.0`)

```python
from types import MappingProxyType
from flask_deck import (
    Deck,
    Fieldset,
    ModelView,
    RangeListFilter,
    SQLAlchemyAuthProvider,
    display,
)

class OrderView(ModelView):
    model = Order
    date_hierarchy = "created_at"        # 1-query Year -> Month -> Day SARGable drilldown
    show_facets = "auto"                 # Zero overhead when closed; batched when open
    save_as = True                       # Clone parent + inlines safely in one click
    readonly_fields = ("created_at",)    # Strictly rejected from POST mass assignment
    prepopulated_fields = MappingProxyType({"slug": ("name",)})
    view_on_site = "https://app.example.com/orders/{order_number}"
    custom_filters = (
        RangeListFilter(
            parameter_name="amount_tier",
            title="Amount Tier",
            column="total_cents",
            bands=(("mid", "$500-$2K", 50000, 200000), ("enterprise", "$2K+", 200000, None)),
        ),
    )
    fieldsets = (
        Fieldset("Order Summary", (("order_number", "status"), ("organization_id", "customer_id"))),
        Fieldset("Notes & Billing", ("total_cents", "notes"), collapsible=True),
    )

    @display(label="Est. Margin", ordering="total_cents")
    def est_margin(self, obj: Order) -> str:
        return f"${(obj.total_cents * 0.82) / 100:,.2f}"

# Optional DB-backed 4-level RBAC IAM with /_security/users, /_security/groups & /_security/password
auth = SQLAlchemyAuthProvider(engine)
deck = Deck(app, db, auth=auth, enable_sql_console=True, enable_rest_api=True, enable_mcp=True)
```

---

## Ecosystem Comparison

| Capability | **flask-deck `v0.5`** | `flask-admin` v2.2 | `flask-appbuilder` | `sqladmin` | `django-unfold` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Flask / WSGI Native** | **Yes** | Yes | Yes | No (ASGI) | No (Django) |
| **Pure SQLAlchemy 2.0 + Multi-Bind DBs** | **Yes** | Partial | No | Yes | N/A |
| **Zero Node Build & Zero CDN** | **Yes (`17.3 KB` core / ≤`25.3 KB` route gz)** | Partial | Partial | No | Partial |
| **Declarative `@display` (SQL Sort) & Collapsible `Fieldset`s** | **Yes** | Partial | Partial | No | Partial |
| **Slide-Over Related Drawer (`+`/`✏️`/`👁️`) & Dual/Async M2M** | **Yes (Strict-CSP)** | No | No | No | Popup only |
| **Single-Query `date_hierarchy`, `ListFilter` & Batched Facets** | **Yes** | No | No | No | Yes |
| **O(tables) SQL Cascade Delete Impact Tree & Signed `select_across`** | **Yes (Chunked async)** | No | No | No | Yes |
| **Optional DB-Backed IAM UI (`/users`, `/groups`, `/password`)** | **Yes** | Manual | Yes | No | Yes |
| **TOTP 2FA (Encrypted), Passkeys, OIDC SSO & Session Registry** | **Yes (Pure SVG QR + WebAuthn)** | No | OAuth only | No | Via plugins |
| **Four-Eyes Approvals & 3-Way OCC Locking** | **Yes (`ETag` / `If-Match`)** | No | No | No | No |
| **Headless REST API v1 + Scoped API Keys & HITL MCP Server** | **Yes (`OpenAPI 3.1.0` + `/_mcp`)** | No | Partial | No | DRF / Ninja |
| **Keyset Cursor Pagination + PG `JSONB`/`ARRAY` + BI SQL Charts** | **Yes (HMAC cursor + `__fts`)** | No | No | No | Partial |
| **Strict Nonce CSP (`0 unsafe-inline`)** | **Yes** | No | No | No | No |

---

## Performance Architecture & Benchmarks

Measured on Python 3.13 + SQLAlchemy + SQLite via `uv run python benchmarks/bench_deck.py`:

| Workload | Result | Engineering Mechanism |
| :--- | :--- | :--- |
| **Frontend Asset Payload** | **`17.26 KB` core gzip** (`9.81 KB` CSS + `7.46 KB` core JS) · **`19.76–25.34 KB`** per-route total | Modular vanilla ES6 (`deck.js` + route-scoped `deck-grid.js` / `deck-form.js` / `deck-ops.js`), zero icon fonts, zero chart or QR libraries; SHA-256 immutable caching (`?v=<hash>`). |
| **Offset List View (50 / 2,000 rows + FK + 4 Tabs)** | **`6.11 ms` p50 · `4` SQL queries** | Auto `joinedload`/`selectinload` (zero N+1), single-pass `CASE` Quick Tab & Trash aggregation, `defer()` heavy blobs, single-query sidebar counts. |
| **Keyset Cursor List (50 / 2,000 rows, `count=none`)** | **`5.86 ms` p50 · `4` SQL queries** | HMAC-signed opaque cursor (`LIMIT N+1`, no `OFFSET` table scan, zero `COUNT(*)` overhead). |
| **Enriched List View (`date_hierarchy` + `RangeListFilter` + Eager Facets)** | **`7.71 ms` p50 · `6` SQL queries** | SARGable `date_hierarchy` range predicate + shared conditional facets folded right into the single-pass QuickTab aggregation query. |
| **SQL Cascade Delete Impact Analyzer (Parent + 80 Children)** | **`1.80 ms` · `1` SQL query** | O(tables) BFS over `mapper.registry.mappers` running pure SQL `COUNT(*)` + authorized `LIMIT 5` samples without hydrating child tables. |
| **Streaming CSV Export (2,000 rows)** | **`71.4 ms` (`28,008 rows/s`) · `2,894 KiB` peak** | `session.scalars(stmt).yield_per(500)` + generator streaming (`O(1)` RAM) shared with Background CSV Jobs; CSV/XLSX formula neutralization. |
| **Dry-Run Savepoint Import (1,000 rows)** | **`181.8 ms` · `0` leaked mutations** | Chunked `IN (...)` batch preload (`batch_size=500`) + released `SAVEPOINT` validation + unconditional `finally: rollback()`; auto-async job above `max_sync_import_rows`. |

Every page footer displays live request telemetry (`SQLAlchemy 2.0 · 4 queries · 0.3 ms SQL · 8.1 ms`) measured via lightweight request-scoped SQLAlchemy event listeners.

---

## Security Architecture (OWASP Defense-in-Depth)

| Vector | Built-in Protection in `flask-deck` |
| :--- | :--- |
| **Unauthenticated Exposure** | **Fail-closed:** Refuses to mount when `app.debug is False` without an explicit `AuthProvider` or `SECRET_KEY` (`SecurityConfigurationError`). Demo role switcher is hard-blocked whenever `environment == "production"`. |
| **XSS & Script Injection** | Strict per-request nonce CSP (`default-src 'none'; script-src 'self' 'nonce-…'; style-src 'self'; frame-ancestors 'none'`), zero `'unsafe-inline'`, zero `<style>`, zero inline `style=` or `on*=`, zero untrusted `innerHTML`, validated `#RRGGBB` `/_theme.css`, safe allowlisted `template_slots`. |
| **File Upload & Media Attacks** | Pure-Python magic-byte MIME verification (SVG XSS blocked by default), PNG/JPEG/GIF/WebP header decompression-bomb guard (`max_image_pixels`), path-traversal-proof storage keys, RBAC + `scope_query` enforcement on `/_media`, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment`. |
| **Account Takeover & SSO** | `SecretCipher`-encrypted TOTP 2FA secrets & recovery codes at rest (HKDF + AES/Fernet or HMAC fallback), WebAuthn Passkeys, PKCE `S256` + `state`/`nonce` OIDC SSO with `allowed_domains`, server-side Session Registry (`/_security/sessions`) with remote revocation, sliding-window login rate limiter (`HTTP 429` + `Retry-After`), `session.clear()` fixation rotation, and audited superuser Impersonation (`impersonated_by`). |
| **CSRF, Replay & Clickjacking** | Cryptographic per-session token (`hmac.compare_digest`) + `Sec-Fetch-Site` / `Origin` enforcement on every cookie mutation (plus Origin-rebinding guard on `/_mcp`), optimistic concurrency control (`ETag` / `If-Match` `409 Conflict`), and `X-Frame-Options: DENY`. |
| **Governance, Agents & APIs** | Declarative four-eyes `approval_required` Maker-Checker queue across UI, REST API v1 (`202 Accepted`), and AI-Agent MCP proposals; SHA-256 hashed Bearer API keys (`dk_live_...`) with scoped permissions, CIDR allowlists, and sliding-window `429 Retry-After` throttling. |
| **Mass Assignment & Tampering** | Strict `allowed_form_fields()` allowlist rejecting tampered PK/computed/readonly/hidden/sensitive fields (including on `?clone=`); uniform `scope_query` everywhere; optional cryptographic SHA-256 hash-chained Audit Ledger (`hash_chain=True`, `verify_chain()`). |
| **SSRF & Data Exfiltration** | `WebhookSink` validates DNS & pinned target IPs (incl. DNS-rebinding & DLQ tracking), blocking loopback, RFC 1918 private, link-local, and cloud metadata endpoints (`169.254.169.254`, `127.0.0.1`, `::1`). Opt-in superuser `/_sql` console enforces multi-layer read-only SQL firewall + automatic `[REDACTED]` masking. |

### Built-In CLI & In-App Security Auditor

```bash
flask --app yourapp deck info
flask --app yourapp deck audit --format text   # text | json | sarif (SARIF 2.1.0)
flask --app yourapp deck scaffold             # Generate ModelView boilerplate from ORM metadata
flask --app yourapp deck mcp                  # Start stdio JSON-RPC 2.0 MCP server
flask --app yourapp deck jobs list            # Inspect / trigger @deck.scheduled_job tasks
```

Both `flask deck audit` and `/admin/_diagnostics` inspect `SECRET_KEY` entropy, session cookie flags (`HttpOnly`, `SameSite`, `Secure`), `OpenAuthProvider` misuse, MFA/encryption/impersonation posture, REST/MCP posture, SQL console posture, unindexed `searchable_columns`, and auto-detected `flask-lens` telemetry.

---

## Migrating from `flask-admin`

See the 1-to-1 migration guide in [docs/migration-from-flask-admin.md](https://github.com/duhanguler/flask-deck/blob/main/docs/migration-from-flask-admin.md).

## Development

```bash
git clone https://github.com/duhanguler/flask-deck.git
cd flask-deck
uv sync --extra dev
make check
```

## License

MIT © 2026 [Duhan Güler](https://github.com/duhanguler)
