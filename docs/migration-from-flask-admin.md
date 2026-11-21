# Migrating from Flask-Admin to Flask-Deck

`flask-deck` adopts familiar declarative `ModelView` ergonomics so migrating an existing `flask-admin` application takes minutes rather than days.

## Concept Mapping

| `flask-admin` | `flask-deck` | Notes |
| :--- | :--- | :--- |
| `Admin(app, name="App")` | `Deck(app, db, auth=..., title="App")` | Fail-closed in production; pass an `AuthProvider` (`BasicAuthProvider`, `RBACAuthProvider`, `FlaskLoginAuthProvider`). |
| `admin.add_view(ModelView(User, db.session))` | `deck.register(User)` or `deck.register(UserView)` | Works with both `Flask-SQLAlchemy` and pure SQLAlchemy 2.0 `sessionmaker`. |
| `column_list` | `columns` | Displayed relationships are automatically eager-loaded (`joinedload`/`selectinload`). |
| `column_exclude_list` | `exclude_columns` | Sensitive columns (`password_hash`, `api_token`, `secret`, etc.) are auto-excluded. |
| `column_searchable_list` | `searchable_columns` | Supports dotted relation paths like `"customer.email"` with escaped `LIKE` wildcards. |
| `column_filters` | `filterable_columns` + `quick_tabs` | Quick Tabs compute all badge counts in a single `CASE` SQL query. |
| `column_editable_list` | `inline_editable_columns` | Optimistic CSRF-protected `PATCH` quick-edit for `boolean` and `enum` fields. |
| `column_formatters` | `column_formatters` | Ships built-in `BadgeFormatter`, `CurrencyFormatter`, `RelativeTimeFormatter`, `ProgressBarFormatter`, `AvatarFormatter`, `CodeFormatter`, `LinkFormatter`. |
| `inline_models` | `inlines = (OrderItemInline,)` | Declarative `InlineModelView` with strict parent-ownership IDOR checks. |
| `form_args` / custom widgets | `form_layout` + `field_widgets` | Multi-tab form sections plus `SegmentedControlWidget`, `SwitchWidget`, `TagInputWidget`, `SliderWidget`, `CodeEditorWidget`, `MarkdownPreviewWidget`. |
| `BaseView` / `@expose` | `@deck.page("slug", title=...)` | Native custom pages using the Carbon/Swiss widget grid, RBAC permissions, sidebar nav, and `⌘K` search. |
| `is_accessible()` | `RBACAuthProvider` + `Role` | 4-level RBAC (model, action, field masking/read-only/hidden, row `scope_query`). |
| `can_export = True` | `can_export = True` | Streaming `O(1)`-RAM CSV/JSON/JSONL export with CSV formula-injection neutralization. |

## Before & After Example

### Before (`flask-admin`)

```python
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

class UserAdmin(ModelView):
    column_list = ["full_name", "email", "is_active"]
    column_searchable_list = ["full_name", "email"]
    column_filters = ["is_active"]
    can_export = True

admin = Admin(app, name="Ops", template_mode="bootstrap4")
admin.add_view(UserAdmin(User, db.session))
```

### After (`flask-deck`)

```python
from types import MappingProxyType
from flask_deck import (
    AvatarFormatter,
    BasicAuthProvider,
    BooleanIconFormatter,
    Deck,
    ModelView,
)

class UserView(ModelView):
    model = User
    columns = ("full_name", "email", "is_active")
    searchable_columns = ("full_name", "email")
    filterable_columns = ("is_active",)
    inline_editable_columns = ("is_active",)
    column_formatters = MappingProxyType({
        "full_name": AvatarFormatter(),
        "is_active": BooleanIconFormatter(),
    })

deck = Deck(
    app,
    db,
    auth=BasicAuthProvider.from_plain_passwords({"admin": "change-me"}),
    title="Ops",
)
deck.register(UserView)
```
