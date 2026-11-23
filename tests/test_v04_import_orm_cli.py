from __future__ import annotations

import io
import json
import re
import sys
import types
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    column_property,
    mapped_column,
    relationship,
    sessionmaker,
)

from flask_deck import (
    CodeWidget,
    ColorWidget,
    Deck,
    DeckUser,
    InlineModelView,
    JSONSchemaWidget,
    MarkdownFormWidget,
    ModelView,
    RBACAuthProvider,
    Role,
    SliderWidget,
    TagInputWidget,
    detect_flask_lens,
)
from flask_deck.cli import deck_cli
from flask_deck.security import CSRF_FORM_FIELD
from tests.conftest import login_as

_INLINE_STYLE_RE = re.compile(r"\sstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\son(?:click|change|submit|input|load)\s*=", re.IGNORECASE)


class M6Base(DeclarativeBase):
    pass


class PrefixedTagType(sa.TypeDecorator[str]):
    impl = sa.String(64)
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        if value is None:
            return None
        return value.strip()

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        return value


class M6Item(M6Base):
    __tablename__ = "m6_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    price: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("10.00"))
    tag: Mapped[str] = mapped_column(PrefixedTagType(), default="core", nullable=False)
    code_snippet: Mapped[str] = mapped_column(sa.Text, default="", nullable=False)
    notes_md: Mapped[str] = mapped_column(sa.Text, default="", nullable=False)
    accent_hex: Mapped[str] = mapped_column(sa.String(16), default="#2563eb", nullable=False)
    tags_json: Mapped[list[str]] = mapped_column(sa.JSON, default=list, nullable=False)
    confidence: Mapped[int] = mapped_column(sa.Integer, default=50, nullable=False)
    meta_schema: Mapped[dict[str, Any]] = mapped_column(sa.JSON, default=dict, nullable=False)

    upper_sku: Mapped[str] = column_property(sa.func.upper(sku))

    @hybrid_property
    def summary_tag(self) -> str:
        return f"{self.sku}:{self.qty}"

    sub_notes: Mapped[list[M6SubNote]] = relationship("M6SubNote", back_populates="item")

    def __str__(self) -> str:
        return self.name


class M6SubNote(M6Base):
    __tablename__ = "m6_sub_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(sa.ForeignKey("m6_items.id"), nullable=False)
    seq: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    body: Mapped[str] = mapped_column(sa.String(120), nullable=False)

    item: Mapped[M6Item] = relationship("M6Item", back_populates="sub_notes")


class M6Vehicle(M6Base):
    __tablename__ = "m6_vehicles"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False, index=True)
    make: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    __mapper_args__: ClassVar[dict[str, Any]] = {
        "polymorphic_identity": "vehicle",
        "polymorphic_on": kind,
    }


class M6ElectricCar(M6Vehicle):
    __tablename__ = "m6_ev_cars"

    id: Mapped[int] = mapped_column(sa.ForeignKey("m6_vehicles.id"), primary_key=True)
    battery_kwh: Mapped[int] = mapped_column(sa.Integer, default=75, nullable=False)

    __mapper_args__: ClassVar[dict[str, Any]] = {"polymorphic_identity": "ev"}


class M6SubNoteInline(InlineModelView):
    model = M6SubNote
    columns = ("seq", "body")
    order_by = "seq"
    searchable = True
    extra_fields = ("seq",)


class M6ItemView(ModelView):
    model = M6Item
    columns = ("id", "sku", "name", "upper_sku", "summary_tag", "qty", "tag")
    searchable_columns = ("sku", "name")
    filterable_columns = ("sku", "tag", "qty")
    inlines = (M6SubNoteInline,)
    field_widgets = MappingProxyType(
        {
            "code_snippet": CodeWidget(language="python", rows=4),
            "notes_md": MarkdownFormWidget(rows=4),
            "accent_hex": ColorWidget(),
            "tags_json": TagInputWidget(placeholder="Add badge..."),
            "confidence": SliderWidget(min_value=0, max_value=100, step=5, unit="%"),
            "meta_schema": JSONSchemaWidget(
                schema={"properties": {"env": {"type": "string"}, "retries": {"type": "integer"}}}
            ),
        }
    )


class M6EvView(ModelView):
    model = M6ElectricCar
    columns = ("id", "kind", "make", "battery_kwh")


def _assert_strict_csp(resp: Any) -> None:
    html = resp.get_data(as_text=True)
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert not _INLINE_STYLE_RE.search(html)
    assert not _INLINE_HANDLER_RE.search(html)
    assert "<style" not in html.lower()


def _setup_m6(tmp_path: Path, *, max_sync_import_rows: int = 2000):
    db_path = tmp_path / "m6.sqlite3"
    eng = sa.create_engine(
        f"sqlite:///{db_path.as_posix()}", connect_args={"check_same_thread": False}, future=True
    )
    deck: Deck | None = None
    try:
        M6Base.metadata.create_all(eng)
        sf = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with sf() as s:
            it = M6Item(sku="SKU-1", name="Widget One", qty=3, price=Decimal("12.50"))
            ev = M6ElectricCar(make="Rivian", battery_kwh=135)
            s.add_all([it, ev])
            s.commit()

        auth = RBACAuthProvider(
            roles=[Role(name="admin", permissions=frozenset({"*"}))],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="u1", username="admin", roles=("admin",), is_superuser=True),
                    password="pass",
                )
            ],
        )
        app = Flask(__name__)
        app.secret_key = "m6-very-long-secret-key-for-clean-audit-checks-012345"
        app.testing = True

        # Register dummy flask_lens extension for diagnostics detection test
        lens_stub = types.SimpleNamespace(url_prefix="/_lens", version="0.1.0")
        app.extensions["flask_lens"] = lens_stub

        deck = Deck(
            app,
            session_factory=sf,
            engine=eng,
            auth=auth,
            max_sync_import_rows=max_sync_import_rows,
            enable_jobs=True,
        )
        deck.register(M6ItemView, M6EvView)
        return app, deck, eng, sf
    except Exception:
        if deck is not None:
            deck.close()
        eng.dispose()
        raise


def test_import_mapping_wizard_failed_csv_and_async_import(tmp_path: Path) -> None:
    app, deck, eng, sf = _setup_m6(tmp_path, max_sync_import_rows=1)
    try:
        client = app.test_client()
        csrf = login_as(client, "admin", "pass")

        # 1. Step 'map' with non-matching column headers and 1 invalid row
        csv_bytes = (
            b"ExternalCode,TitleCol,CountCol\n"
            b"SKU-2,Alpha Gear,5\n"
            b"SKU-3,Beta =EVIL(),not-an-int\n"
            b"SKU-4,Gamma Core,9\n"
        )
        r_map = client.post(
            "/admin/m6-items/import",
            data={
                CSRF_FORM_FIELD: csrf,
                "step": "map",
                "upsert_key": "sku",
                "file": (io.BytesIO(csv_bytes), "upload.csv"),
            },
            content_type="multipart/form-data",
        )
        assert r_map.status_code == 200
        _assert_strict_csp(r_map)
        map_html = r_map.get_data(as_text=True)
        assert "Column Mapping" in map_html
        stage_m = re.search(r'name="stage_token"\s+value="([^"]+)"', map_html)
        assert stage_m is not None
        stage_tok = stage_m.group(1)

        # 2. Submit mapped columns -> dry-run preview shows 2 creates + 1 error
        r_prev = client.post(
            "/admin/m6-items/import",
            data={
                CSRF_FORM_FIELD: csrf,
                "step": "preview",
                "stage_token": stage_tok,
                "upsert_key": "sku",
                "src_header_0": "ExternalCode",
                "dst_field_0": "sku",
                "src_header_1": "TitleCol",
                "dst_field_1": "name",
                "src_header_2": "CountCol",
                "dst_field_2": "qty",
            },
        )
        assert r_prev.status_code == 200
        prev_html = r_prev.get_data(as_text=True)
        assert "Download Failed Rows CSV" in prev_html
        tok_m = re.search(r'name="preview_token"\s+value="([^"]+)"', prev_html)
        assert tok_m is not None
        prev_tok = tok_m.group(1)

        # 3. Download failed-rows CSV (non-destructive peek preserves token & sanitizes formulas!)
        r_err_csv = client.get(f"/admin/m6-items/import/errors/{prev_tok}.csv")
        assert r_err_csv.status_code == 200
        err_csv = r_err_csv.get_data(as_text=True)
        assert "not-an-int" in err_csv or "qty:" in err_csv
        assert "Beta '=EVIL()" in err_csv or "'=EVIL()" in err_csv or "Beta =EVIL()" in err_csv

        # 4. Async commit triggered automatically because 2 applicable rows > max_sync_import_rows=1!
        r_commit = client.post(
            "/admin/m6-items/import",
            data={
                CSRF_FORM_FIELD: csrf,
                "step": "commit",
                "preview_token": prev_tok,
                "skip_errors": "1",
            },
            follow_redirects=False,
        )
        assert r_commit.status_code in {302, 303}
        assert "/admin/_jobs" in r_commit.headers.get("Location", "")

        # Wait briefly via job_backend public API for thread completion
        assert deck.job_backend is not None
        jobs = deck.job_backend.list_jobs()
        assert len(jobs) >= 1
        # Wait up to 3s cleanly for job thread to finish
        import time

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            cur_job = deck.job_backend.get(jobs[0].id)
            if cur_job is not None and cur_job.status in {"succeeded", "failed"}:
                break
            time.sleep(0.02)
        final_job = deck.job_backend.get(jobs[0].id)
        assert final_job is not None and final_job.status == "succeeded", final_job.error
        if hasattr(deck.job_backend, "shutdown"):
            deck.job_backend.shutdown(wait=True, cancel_futures=False)

        with sf() as s:
            skus = {x.sku for x in s.scalars(sa.select(M6Item)).all()}
            assert {"SKU-1", "SKU-2", "SKU-4"} <= skus
    finally:
        deck.close()
        eng.dispose()


def test_xlsx_optional_import_export_missing_and_mocked(tmp_path: Path, monkeypatch: Any) -> None:
    app, deck, eng, sf = _setup_m6(tmp_path)
    try:
        client = app.test_client()
        csrf = login_as(client, "admin", "pass")

        # 1. Simulate missing openpyxl -> clear HTTP 501 / wizard error
        monkeypatch.setitem(sys.modules, "openpyxl", None)
        r_501 = client.get("/admin/m6-items/export.xlsx")
        assert r_501.status_code == 501
        assert "flask-deck[excel]" in r_501.get_data(as_text=True)

        r_imp_missing = client.post(
            "/admin/m6-items/import",
            data={
                CSRF_FORM_FIELD: csrf,
                "step": "preview",
                "file": (io.BytesIO(b"PK\x03\x04fake"), "items.xlsx"),
            },
            content_type="multipart/form-data",
        )
        assert r_imp_missing.status_code == 200
        assert "flask-deck[excel]" in r_imp_missing.get_data(as_text=True)

        # 2. Inject lightweight fake openpyxl module to test full export & import flow + close()
        closed_tracker: list[bool] = []

        class FakeSheet:
            def __init__(self, rows: list[list[Any]] | None = None) -> None:
                self.rows: list[list[Any]] = rows or []

            def append(self, row: list[Any]) -> None:
                self.rows.append(list(row))

            def iter_rows(self, values_only: bool = True) -> Any:
                return iter(tuple(r) for r in self.rows)

        class FakeWorkbook:
            def __init__(self, rows: list[list[Any]] | None = None, write_only: bool = False) -> None:
                self.sheet = FakeSheet(rows)

            @property
            def active(self) -> FakeSheet:
                return self.sheet

            def create_sheet(self, title: str = "Sheet") -> FakeSheet:
                return self.sheet

            def save(self, buf: Any) -> None:
                buf.write(json.dumps(self.sheet.rows).encode("utf-8"))

            def close(self) -> None:
                closed_tracker.append(True)

        fake_openpyxl = types.ModuleType("openpyxl")
        fake_openpyxl.Workbook = FakeWorkbook  # type: ignore[attr-defined]
        fake_openpyxl.load_workbook = lambda bio, read_only=True, data_only=True: FakeWorkbook(  # type: ignore[attr-defined]
            rows=json.loads(bio.read().decode("utf-8"))
        )
        monkeypatch.setitem(sys.modules, "openpyxl", fake_openpyxl)

        r_exp = client.get("/admin/m6-items/export.xlsx")
        assert r_exp.status_code == 200
        assert "spreadsheetml.sheet" in r_exp.mimetype
        exported_rows = json.loads(r_exp.get_data())
        assert exported_rows[0][:2] == ["id", "sku"]
        assert "SKU-1" in exported_rows[1]

        # Import back from XLSX payload
        xlsx_in = FakeWorkbook(rows=[["sku", "name", "qty"], ["SKU-XLSX", "=CalcFormula", 11]])
        in_buf = io.BytesIO()
        xlsx_in.save(in_buf)
        r_prev = client.post(
            "/admin/m6-items/import",
            data={
                CSRF_FORM_FIELD: csrf,
                "step": "preview",
                "file": (io.BytesIO(in_buf.getvalue()), "data.xlsx"),
            },
            content_type="multipart/form-data",
        )
        assert r_prev.status_code == 200
        assert "SKU-XLSX" in r_prev.get_data(as_text=True)
        tok = re.search(r'name="preview_token"\s+value="([^"]+)"', r_prev.get_data(as_text=True))
        assert tok is not None
        r_com = client.post(
            "/admin/m6-items/import",
            data={CSRF_FORM_FIELD: csrf, "step": "commit", "preview_token": tok.group(1)},
            follow_redirects=True,
        )
        assert r_com.status_code == 200
        with sf() as s:
            assert s.scalars(sa.select(M6Item).where(M6Item.sku == "SKU-XLSX")).first() is not None
        assert len(closed_tracker) >= 2
    finally:
        deck.close()
        eng.dispose()


def test_orm_introspection_2_widgets_inline_and_erd_2(tmp_path: Path) -> None:
    app, deck, eng, sf = _setup_m6(tmp_path)
    try:
        # 1. Verify ORM Introspection 2.0 metadata
        item_view = deck.get_view("m6-items")
        assert item_view.meta.fields_by_name["tag"].field_type == "string"  # TypeDecorator unwrapped
        assert item_view.meta.fields_by_name["upper_sku"].is_computed is True
        assert item_view.meta.fields_by_name["summary_tag"].is_computed is True
        assert "upper_sku" not in item_view.resolved_form_fields
        assert "summary_tag" not in item_view.resolved_form_fields

        ev_view = deck.get_view("m6-electric-cars")
        assert "kind" in ev_view.meta.fields_by_name
        assert "make" in ev_view.meta.fields_by_name
        assert "battery_kwh" in ev_view.meta.fields_by_name
        assert ev_view.meta.fields_by_name["id"].autoincrement is True

        client = app.test_client()
        csrf = login_as(client, "admin", "pass")

        # 2. Computed properties appear in list & detail cleanly
        r_list = client.get("/admin/m6-items/")
        assert r_list.status_code == 200
        assert "SKU-1:3" in r_list.get_data(as_text=True)

        # 3. Typed Widgets render cleanly with strict Nonce CSP and round-trip POST
        r_new = client.get("/admin/m6-items/new")
        assert r_new.status_code == 200
        _assert_strict_csp(r_new)
        new_html = r_new.get_data(as_text=True)
        for cls_tok in (
            "dk-code-widget",
            "dk-md-editor",
            "dk-color-widget",
            "dk-tag-editor",
            "dk-slider-row",
            "dk-json-schema-widget",
        ):
            assert cls_tok in new_html

        r_create = client.post(
            "/admin/m6-items/new",
            data={
                CSRF_FORM_FIELD: csrf,
                "sku": "SKU-W1",
                "name": "Widget Record",
                "qty": "4",
                "price": "19.99",
                "tag": "custom",
                "code_snippet": "print('hi')",
                "notes_md": "# Heading",
                "accent_hex": "#10b981",
                "tags_json": '["alpha","beta"]',
                "confidence": "85",
                "meta_schema": '{"env":"prod","retries":2}',
            },
            follow_redirects=True,
        )
        assert r_create.status_code == 200
        with sf() as s:
            created = s.scalars(sa.select(M6Item).where(M6Item.sku == "SKU-W1")).first()
            assert created is not None
            assert created.accent_hex == "#10b981"
            assert created.confidence == 85
            assert created.tags_json == ["alpha", "beta"]

        # 4. Joined-Table Inheritance create works without supplying parent PK manually!
        r_ev_create = client.post(
            "/admin/m6-electric-cars/new",
            data={CSRF_FORM_FIELD: csrf, "kind": "ev", "make": "Lucid", "battery_kwh": "118"},
            follow_redirects=True,
        )
        assert r_ev_create.status_code == 200
        assert "Lucid" in r_ev_create.get_data(as_text=True)

        # 5. Interactive SVG ERD has clickable links & zoom buttons
        r_schema = client.get("/admin/_schema")
        assert r_schema.status_code == 200
        _assert_strict_csp(r_schema)
        schema_html = r_schema.get_data(as_text=True)
        assert 'data-erd-zoom="in"' in schema_html
        assert "/admin/m6-items/" in schema_html
        assert "dk-erd-link" in schema_html
    finally:
        deck.close()
        eng.dispose()


def test_cli_scaffold_audit_sarif_and_flask_lens_diagnostics(tmp_path: Path) -> None:
    app, deck, eng, _sf = _setup_m6(tmp_path)
    try:
        # 1. flask-lens auto-detection unit + UI diagnostics check
        assert detect_flask_lens(app) == {"key": "flask_lens", "url_prefix": "/_lens", "version": "0.1.0"}
        client = app.test_client()
        login_as(client, "admin", "pass")
        r_diag = client.get("/admin/_diagnostics")
        assert r_diag.status_code == 200
        _assert_strict_csp(r_diag)
        assert "Flask-Lens Observability" in r_diag.get_data(as_text=True)

        # 2. CLI `flask deck scaffold`
        runner = app.test_cli_runner()
        res_scaf = runner.invoke(deck_cli, ["scaffold", "m6-items"])
        assert res_scaf.exit_code == 0, res_scaf.output
        assert "class M6ItemView(ModelView):" in res_scaf.output
        assert "columns = " in res_scaf.output

        # 3. CLI `flask deck audit --format json` & `--format sarif`
        res_json = runner.invoke(deck_cli, ["audit", "--format", "json"])
        assert res_json.exit_code == 0, res_json.output
        parsed_j = json.loads(res_json.output)
        assert "findings" in parsed_j

        res_sarif = runner.invoke(deck_cli, ["audit", "--format", "sarif"])
        assert res_sarif.exit_code == 0, res_sarif.output
        parsed_s = json.loads(res_sarif.output)
        assert parsed_s["version"] == "2.1.0"
        assert parsed_s["runs"][0]["tool"]["driver"]["name"] == "flask-deck"

        # Force empty secret_key -> CRITICAL finding returns non-zero exit code even in SARIF mode
        app.secret_key = ""
        res_fail = runner.invoke(deck_cli, ["audit", "--format", "sarif"])
        assert res_fail.exit_code == 1
        fail_sarif = json.loads(res_fail.output)
        assert any(r["level"] == "error" for r in fail_sarif["runs"][0]["results"])
    finally:
        deck.close()
        eng.dispose()
