from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask, jsonify
from markupsafe import Markup
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    BrandConfig,
    ConfigurationError,
    Deck,
    DeckConfig,
    DeckUser,
    Fieldset,
    FormWidget,
    InlineModelView,
    ModelURL,
    ModelView,
    RBACAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
    ViewMedia,
    check_model_view,
    run_model_view_checks,
    run_security_audit,
)
from tests.conftest import login_as


class EBase(DeclarativeBase):
    pass


class EItem(EBase):
    __tablename__ = "v06_e_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    note: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    password_hash: Mapped[str] = mapped_column(sa.String(120), default="secret")


class EUnrelated(EBase):
    __tablename__ = "v06_e_unrelated"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(80), nullable=False)


class _AssetWidget(FormWidget):
    media_css = ("/static/widget-custom.css",)
    media_js = ("/static/widget-custom.js",)

    def render(
        self,
        *,
        name: str,
        field_id: str,
        value: Any,
        readonly: bool = False,
        required: bool = False,
        label: str = "",
    ) -> Markup:
        _ = (readonly, required, label)
        return Markup(
            f'<input type="text" id="{Markup.escape(field_id)}" '
            f'name="{Markup.escape(name)}" value="{Markup.escape(str(value or ""))}" class="dk-input">'
        )


def test_model_view_checks_all_codes_and_strict_prod_fail_fast() -> None:
    class BadInline(InlineModelView):
        model = EUnrelated  # no FK pointing to EItem -> DECK-E008

    class BrokenView(ModelView):
        model = EItem
        slug = "broken"
        columns = ("name", "nonexistent_col", "password_hash")  # DECK-E001 & DECK-E009
        searchable_columns = ("ghost_search",)  # DECK-E002
        fieldsets = (Fieldset("Main", ("name", "ghost_fs")),)  # DECK-E003
        date_hierarchy = "name"  # non-date -> DECK-E004
        prepopulated_fields = MappingProxyType({"note": ("missing_src",)})  # DECK-E005
        list_display_links = ("note",)  # not in columns -> DECK-E006
        kanban_column = "name"  # non-enum -> DECK-E007
        inlines = (BadInline,)  # DECK-E008
        list_template = "../escape.html"  # path traversal -> DECK-E010
        media = ViewMedia(css=("https://evil.example/a.css",), js=("javascript:alert(1)",))  # DECK-E011
        list_select_related = ("missing_rel",)  # DECK-W001

        def get_urls(self) -> Sequence[ModelURL]:
            return (ModelURL(rule="../escape", endpoint="bad", handler=lambda: "no"),)  # DECK-E012

    v = BrokenView()
    codes = {f.code for f in check_model_view(v)}
    assert {
        "DECK-E001",
        "DECK-E002",
        "DECK-E003",
        "DECK-E004",
        "DECK-E005",
        "DECK-E006",
        "DECK-E007",
        "DECK-E008",
        "DECK-E009",
        "DECK-E010",
        "DECK-E011",
        "DECK-E012",
        "DECK-W001",
    }.issubset(codes)

    # Dev mode warns & surfaces in run_security_audit without crashing
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    EBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    auth = RBACAuthProvider(
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="a", username="admin", roles=("admin",), is_superuser=True),
                password="pass",
            )
        ],
        roles=[Role(name="admin", permissions=frozenset({"*"}))],
    )
    app_dev = Flask(__name__)
    app_dev.config["SECRET_KEY"] = "dev-secret-key-at-least-32-characters-long"
    deck_dev = Deck(app_dev, session_factory=SessionLocal, engine=engine, auth=auth, environment="development")
    deck_dev.register(BrokenView)
    audit_findings = run_security_audit(app_dev, deck_dev)
    assert any(f.get("code") == "DECK-E001" for f in audit_findings)
    deck_dev.close()

    # DECK-W002 advisory in production with SQLAlchemyAuthProvider(strict_password_policy=False)
    sa_auth = SQLAlchemyAuthProvider(engine)
    app_w2 = Flask(__name__)
    app_w2.config["SECRET_KEY"] = "w2-secret-key-at-least-32-characters-long"
    deck_w2 = Deck(app_w2, session_factory=SessionLocal, engine=engine, auth=sa_auth, environment="production")
    assert any(f.code == "DECK-W002" for f in run_model_view_checks(deck_w2))
    deck_w2.close()

    # strict_view_checks=True OR environment="production" fails fast with ConfigurationError
    app_strict = Flask(__name__)
    app_strict.config["SECRET_KEY"] = "strict-secret-key-at-least-32-characters-long"
    deck_strict = Deck(
        app_strict,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        strict_view_checks=True,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        deck_strict.register(BrokenView)
    assert "DECK-E001" in str(exc_info.value)
    deck_strict.close()

    app_prod = Flask(__name__)
    app_prod.config["SECRET_KEY"] = "prod-secret-key-at-least-32-characters-long"
    deck_prod = Deck(
        app_prod,
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        environment="production",
    )
    with pytest.raises(ConfigurationError):
        deck_prod.register(BrokenView)
    deck_prod.close()
    engine.dispose()


def test_site_url_validation_and_extensibility_urls_media_templates_slots_category(
    tmp_path: Path,
) -> None:
    # site_url rejects unsafe javascript: scheme
    with pytest.raises(ValueError):
        DeckConfig(site_url="javascript:alert(1)")

    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "custom_item_list.html").write_text(
        '{% extends "flask_deck/model_list.html" %}'
        "{% block content %}<!-- CUSTOM-LIST-TPL -->{{ super() }}{% endblock %}",
        encoding="utf-8",
    )
    (tpl_dir / "slot_form_above.html").write_text(
        '<div class="dk-alert dk-alert-neutral">FORM-ABOVE-SLOT {{ custom_banner }}</div>',
        encoding="utf-8",
    )
    (tpl_dir / "slot_detail_below.html").write_text(
        '<div class="dk-alert dk-alert-neutral">DETAIL-BELOW-SLOT</div>',
        encoding="utf-8",
    )

    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    EBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as sess:
        sess.add(EItem(name="Widget A", note=None))
        sess.commit()

    class ItemExtView(ModelView):
        model = EItem
        slug = "items"
        category = "Inventory"
        nav_order = 10
        columns = ("name", "note")
        list_template = "custom_item_list.html"
        media = ViewMedia(css=("/static/view-ext.css",), js=("/static/view-ext.js",))
        field_widgets = MappingProxyType({"name": _AssetWidget()})

        def get_urls(self) -> Sequence[ModelURL]:
            def _ping_get() -> Any:
                return jsonify({"ok": True, "route": "custom-get"})

            def _ping_post() -> Any:
                return jsonify({"ok": True, "route": "custom-post"})

            return (
                ModelURL(rule="custom-ping", endpoint="custom_ping", handler=_ping_get, methods=("GET",)),
                ModelURL(
                    rule="custom-mutate",
                    endpoint="custom_mutate",
                    handler=_ping_post,
                    methods=("POST",),
                ),
            )

    class BetaView(ModelView):
        model = EUnrelated
        slug = "unrelated"
        category = "Catalog"
        nav_order = 5

    auth = RBACAuthProvider(
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="adm", username="admin", roles=("admin",), is_superuser=True),
                password="pass",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="vw", username="viewer", roles=("viewer",)),
                password="pass",
            ),
        ],
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(name="viewer", permissions=frozenset({"items:view"})),
        ],
    )

    app = Flask(__name__, template_folder=str(tpl_dir))
    app.config["SECRET_KEY"] = "v06-ext-test-secret-key-at-least-32-bytes"
    app.config["TESTING"] = True

    # Test pre-init_app registration for get_urls() too!
    deck = Deck(
        session_factory=SessionLocal,
        engine=engine,
        auth=auth,
        site_url="https://acme.example.com",
        empty_value_display="(empty)",
        sidebar_order=("Catalog", "Inventory"),
        brand=BrandConfig(
            template_slots=MappingProxyType(
                {
                    "form_above": "slot_form_above.html",
                    "detail_below": "slot_detail_below.html",
                }
            )
        ),
    )

    @deck.context_processor
    def _ctx() -> dict[str, Any]:
        return {
            "custom_banner": "HELLO-CTX",
            "csrf_token": "TAMPERED-CSRF",  # protected key MUST NOT be overwritten!
            "csp_nonce": "TAMPERED-NONCE",
        }

    deck.register(ItemExtView, BetaView)
    deck.init_app(app)

    c_anon = app.test_client()
    # Custom ModelView.get_urls() inherits Deck auth boundary (anon redirected to /admin/login)
    assert c_anon.get("/admin/items/custom-ping").status_code == 302

    c_vw = app.test_client()
    vw_csrf = login_as(c_vw, "viewer", "pass")
    # Viewer has items:view -> GET custom-ping succeeds with strict CSP headers
    r_ping = c_vw.get("/admin/items/custom-ping")
    assert r_ping.status_code == 200
    assert r_ping.get_json() == {"ok": True, "route": "custom-get"}
    assert "Content-Security-Policy" in r_ping.headers
    # Viewer lacks items:edit -> POST custom-mutate denied (403)
    assert (
        c_vw.post("/admin/items/custom-mutate", headers={"X-Deck-CSRFToken": vw_csrf}).status_code
        == 403
    )

    c_adm = app.test_client()
    adm_csrf = login_as(c_adm, "admin", "pass")
    # POST without CSRF token is rejected (403) even for superuser!
    assert c_adm.post("/admin/items/custom-mutate").status_code == 403
    r_mut = c_adm.post("/admin/items/custom-mutate", headers={"X-Deck-CSRFToken": adm_csrf})
    assert r_mut.status_code == 200
    assert r_mut.get_json() == {"ok": True, "route": "custom-post"}

    # Template override, global empty_value_display, ViewMedia + FormWidget media, site_url, sidebar_order
    list_html = c_adm.get("/admin/items/").get_data(as_text=True)
    assert "<!-- CUSTOM-LIST-TPL -->" in list_html
    assert "(empty)" in list_html
    assert 'href="/static/view-ext.css"' in list_html
    assert 'src="/static/view-ext.js"' in list_html
    assert 'href="https://acme.example.com"' in list_html
    assert list_html.index("Catalog") < list_html.index("Inventory")
    assert "TAMPERED-CSRF" not in list_html
    assert "TAMPERED-NONCE" not in list_html

    # Form renders widget media + form_above slot + custom context_processor value
    form_html = c_adm.get("/admin/items/1/edit").get_data(as_text=True)
    assert "FORM-ABOVE-SLOT HELLO-CTX" in form_html
    assert 'href="/static/widget-custom.css"' in form_html
    assert 'src="/static/widget-custom.js"' in form_html

    # Detail renders detail_below slot
    detail_html = c_adm.get("/admin/items/1").get_data(as_text=True)
    assert "DETAIL-BELOW-SLOT" in detail_html

    # Category index page /_category/inventory (authorized vs 404 unknown)
    cat_html = c_adm.get("/admin/_category/inventory").get_data(as_text=True)
    assert "Inventory" in cat_html
    assert "/admin/items/" in cat_html
    assert c_adm.get("/admin/_category/nonexistent").status_code == 404
    # Viewer cannot see Catalog category (no unrelated:view perm) -> 404
    assert c_vw.get("/admin/_category/catalog").status_code == 404

    deck.close()
    engine.dispose()
