"""Behavioral tests for CSV/JSON/XLSX importer, ModelView coercion, inlines, VirtualField, and system checks."""

from __future__ import annotations

import enum
import io
import json
import time
import uuid
from datetime import date, datetime, timezone
from datetime import time as dt_time
from decimal import Decimal
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from werkzeug.datastructures import FileStorage

from flask_deck import (
    Deck,
    DeckUser,
    Fieldset,
    FileFieldConfig,
    InlineModelView,
    InMemoryAuditStore,
    InMemorySessionStore,
    MemoryFileStorage,
    ModelURL,
    ModelView,
    OpenAuthProvider,
    RBACAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
    ThreadPoolJobBackend,
    ViewMedia,
    VirtualField,
    display,
    pydantic_validator,
)
from flask_deck.checks import check_model_view, run_model_view_checks
from flask_deck.exceptions import ImportLimitError, PermissionDeniedError, ValidationError
from flask_deck.importer import (
    DryRunReport,
    ImportPreviewStore,
    RowDiff,
    commit_dry_run_import,
    deserialize_dry_run_report,
    format_failed_rows_csv,
    parse_import_payload,
    run_dry_run_import,
    serialize_dry_run_report,
)
from flask_deck.introspection import FieldMeta, introspect_model
from flask_deck.model_view import coerce_form_value, is_safe_media_path, is_safe_template_name
from flask_deck.security import CSRF_FORM_FIELD
from flask_deck.widgets import FormWidget
from tests._backends import sqlite_memory_engine


class ImpKind(enum.Enum):
    ALPHA = "alpha"
    BETA = "beta"


class ImpBase(DeclarativeBase):
    pass


class ImpProduct(ImpBase):
    __tablename__ = "imp_products"
    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    kind: Mapped[ImpKind] = mapped_column(sa.Enum(ImpKind), default=ImpKind.ALPHA, nullable=False)
    price: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("0.00"), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    meta_json: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON, nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    created_on: Mapped[date | None] = mapped_column(sa.Date, nullable=True)
    attachment: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)

    parts: Mapped[list[ImpPart]] = relationship(back_populates="product")


class ImpPart(ImpBase):
    __tablename__ = "imp_parts"
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(sa.ForeignKey("imp_products.id"), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    spec_file: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    api_secret: Mapped[str | None] = mapped_column(sa.String(80), nullable=True)

    product: Mapped[ImpProduct] = relationship(back_populates="parts")


class ImpComposite(ImpBase):
    __tablename__ = "imp_composites"
    region: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(60), nullable=False)


def _extract_csrf(client: Any, url: str = "/admin/login") -> str:
    resp = client.get(url)
    html = resp.get_data(as_text=True)
    marker = f'name="{CSRF_FORM_FIELD}" value="'
    idx = html.find(marker)
    if idx != -1:
        start = idx + len(marker)
        return html[start : html.find('"', start)]
    meta = 'name="csrf-token" content="'
    idx = html.find(meta)
    assert idx != -1
    start = idx + len(meta)
    return html[start : html.find('"', start)]


def test_importer_serialization_limits_savepoint_dry_run_and_http_wizard() -> None:
    # 1. DryRunReport typed serialization round-trip (Decimal, datetime, date, time, UUID, Enum, tuple)
    uid = uuid.uuid4()
    rep = DryRunReport(
        token="tok-1",
        model_slug="products",
        filename="data.json",
        format="json",
        upsert_key="sku",
        headers=("sku", "price"),
        mapped_columns={"sku": "sku", "price": "price"},
        rows=(
            RowDiff(
                row_number=1,
                status="create",
                key_display="SKU-1",
                changes={"price": (None, Decimal("12.34"))},
                coerced_data={
                    "price": Decimal("12.34"),
                    "at": datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc),
                    "d": date(2026, 1, 2),
                    "t": dt_time(3, 4, 5),
                    "u": uid,
                    "k": ImpKind.BETA,
                    "tup": (1, "x"),
                    "lst": [Decimal("1.5")],
                },
                existing_pk=(1, "a"),
                raw_row={"sku": "=CMD()", "price": "12.34"},
            ),
            RowDiff(
                row_number=2,
                status="error",
                key_display="=ERR",
                errors=("sku: required",),
                raw_row={"sku": "=SUM(A1)", "price": "bad"},
            ),
        ),
        creates=1,
        updates=0,
        unchanged=0,
        errors=1,
    )
    assert rep.total_rows == 2 and rep.applicable_count == 1
    rep2 = deserialize_dry_run_report(serialize_dry_run_report(rep))
    assert rep2.rows[0].coerced_data["price"] == Decimal("12.34")
    assert rep2.rows[0].coerced_data["u"] == uid
    assert rep2.rows[0].coerced_data["tup"] == (1, "x")
    assert rep2.rows[0].existing_pk == (1, "a")

    # Formula-safe failed-rows CSV
    err_csv = format_failed_rows_csv(rep, sanitize_csv=True)
    assert "'=SUM(A1)" in err_csv

    # PreviewStore capacity eviction + peek/consume boundaries
    pstore = ImportPreviewStore(ttl_seconds=60, max_entries=4)
    for idx in range(6):
        r_i = DryRunReport(
            token=f"t-{idx}",
            model_slug="products",
            filename="x.csv",
            format="csv",
            upsert_key=None,
            headers=("sku",),
            mapped_columns={"sku": "sku"},
            rows=(),
            creates=0,
            updates=0,
            unchanged=0,
            errors=0,
        )
        pstore.put(r_i, user_id="u1", session_token="s1")
    assert pstore.peek("t-0", user_id="u1", session_token="s1", model_slug="products") is None
    assert pstore.peek("t-5", user_id="u1", session_token="s1", model_slug="products") is not None

    # 2. parse_import_payload boundary errors (empty, size, UTF-8, JSON, CSV)
    with pytest.raises(ImportLimitError, match="empty"):
        parse_import_payload(b"   ", filename="a.csv", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="exceeds maximum allowed size"):
        parse_import_payload(b"x" * 20, filename="a.csv", max_bytes=10, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="UTF-8"):
        parse_import_payload(b"\xff\xfe", filename="a.csv", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="Invalid JSON"):
        parse_import_payload(b"[{bad", filename="a.json", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="array of objects"):
        parse_import_payload(b'{"a":1}', filename="a.json", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="row limit"):
        parse_import_payload(b'[{"a":1},{"a":2}]', filename="a.json", max_bytes=1024, max_rows=1, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="depth"):
        parse_import_payload(b'[{"a":{"b":{"c":1}}}]', filename="a.json", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=2)
    with pytest.raises(ImportLimitError, match="must be an object"):
        parse_import_payload(b"[123]", filename="a.json", max_bytes=1024, max_rows=10, max_columns=10, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="column limit"):
        parse_import_payload(b'[{"a":1,"b":2,"c":3}]', filename="a.json", max_bytes=1024, max_rows=10, max_columns=2, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="column limit"):
        parse_import_payload(b"a;b;c\n1;2;3\n", filename="a.csv", max_bytes=1024, max_rows=10, max_columns=2, max_json_depth=4)
    with pytest.raises(ImportLimitError, match="row limit"):
        parse_import_payload(b"a,b\n1,2\n3,4\n", filename="a.csv", max_bytes=1024, max_rows=1, max_columns=5, max_json_depth=4)

    # 3. End-to-end SAVEPOINT dry-run + commit + HTTP wizard (map -> preview -> error CSV -> commit + async)
    class ProdView(ModelView):
        model = ImpProduct
        slug = "products"
        version_column = "version"
        import_key_columns = ("sku",)

        def can_edit_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.locked

        def get_readonly_fields(self, user: Any, obj: Any = None) -> tuple[str, ...]:
            _ = user
            return ("notes",) if (obj is not None and obj.sku == "SKU-EXIST") else ()

        def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
            _ = obj
            if data.get("name") == "BAD_NAME":
                return {"name": ["Rejected by validate()"]}
            return {}

    with sqlite_memory_engine() as eng:
        ImpBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            s.add_all(
                [
                    ImpProduct(sku="SKU-EXIST", name="Original", price=Decimal("10.00"), notes="keep"),
                    ImpProduct(sku="SKU-SAME", name="Unchanged", price=Decimal("5.00")),
                    ImpProduct(sku="SKU-LOCKED", name="Locked", price=Decimal("1.00"), locked=True),
                ]
            )
            s.commit()

        view = ProdView()
        auth = OpenAuthProvider()
        with SessionLocal() as s:
            # No matching columns -> ImportLimitError
            with pytest.raises(ImportLimitError, match="No uploaded columns"):
                run_dry_run_import(s, view, raw_bytes=b"unknown_col\nval\n", filename="u.csv", auth=auth, user=None)

            payload = json.dumps(
                [
                    {"sku": "SKU-EXIST", "name": "Updated", "price": "19.99", "notes": "ignored-ro", "kind": "beta"},
                    {"sku": "SKU-SAME", "name": "Unchanged", "price": "5.00", "kind": "alpha"},
                    {"sku": "SKU-LOCKED", "name": "Try Edit Locked", "price": "2.00", "kind": "alpha"},
                    {"sku": "SKU-NEW", "name": "Fresh", "price": "7.50", "kind": "alpha"},
                    {"sku": "SKU-ERR-VAL", "name": "BAD_NAME", "price": "1.00", "kind": "alpha"},
                    {"sku": "SKU-ERR-COERCE", "name": "Bad Price", "price": "not-decimal", "kind": "alpha"},
                    {"sku": "SKU-ERR-REQ", "kind": "alpha"},  # missing required 'name'
                    {"sku": "SKU-EXIST", "name": "BAD_NAME", "price": "10.00", "kind": "alpha"},  # update validation error
                ]
            ).encode("utf-8")
            dr = run_dry_run_import(s, view, raw_bytes=payload, filename="mix.json", auth=auth, user=None, upsert_key="sku")
            assert dr.creates == 1
            assert dr.updates == 1  # SKU-LOCKED is rejected as error during dry-run!
            assert dr.unchanged == 1
            assert dr.errors == 5
            upd_row = next(r for r in dr.rows if r.status == "update")
            assert "notes" not in upd_row.changes  # dynamic readonly excluded from preview diff!

            # Verify outer SAVEPOINT rolled back completely!
            assert s.scalar(sa.select(sa.func.count()).select_from(ImpProduct)) == 3

            # Commit refuses when errors > 0 unless skip_errors=True
            with pytest.raises(ImportLimitError):
                commit_dry_run_import(s, view, dr, user=None, skip_errors=False)

            audits: list[Any] = []
            created, updated = commit_dry_run_import(
                s,
                view,
                dr,
                user=None,
                skip_errors=True,
                row_audit_cb=lambda *a: audits.append(a),
            )
            assert created == 1 and updated == 1  # SKU-LOCKED skipped by can_edit_record!
            assert len(audits) == 2

            exist = s.scalar(sa.select(ImpProduct).where(ImpProduct.sku == "SKU-EXIST"))
            assert exist is not None
            assert exist.name == "Updated"
            assert exist.notes == "keep"  # dynamic readonly preserved
            assert exist.version == 2

        # HTTP import wizard (step=map -> step=preview -> error csv -> commit + async)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "import-wizard-secret-32-bytes!!!"
        app.config["TESTING"] = True
        jobs = ThreadPoolJobBackend(max_workers=1)
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=OpenAuthProvider(),
            audit_store=InMemoryAuditStore(),
            session_store=InMemorySessionStore(),
            job_backend=jobs,
        )
        deck.register(ProdView)

        try:
            c = app.test_client()
            csrf = _extract_csrf(c, "/admin/products/import")
            # step=map without file
            r_nf = c.post("/admin/products/import", data={"step": "map", CSRF_FORM_FIELD: csrf})
            assert r_nf.status_code == 200 and "Select a CSV" in r_nf.get_data(as_text=True)

            # step=map with custom header names
            r_map = c.post(
                "/admin/products/import",
                data={
                    "step": "map",
                    "upsert_key": "sku",
                    "file": (io.BytesIO(b"ItemCode,ItemTitle,Cost\nSKU-W1,Widget 1,4.25\nSKU-W2,,bad\n"), "w.csv"),
                    CSRF_FORM_FIELD: csrf,
                },
                content_type="multipart/form-data",
            )
            assert r_map.status_code == 200
            map_html = r_map.get_data(as_text=True)
            st_idx = map_html.find('name="stage_token" value="')
            assert st_idx != -1
            st_start = st_idx + len('name="stage_token" value="')
            stage_tok = map_html[st_start : map_html.find('"', st_start)]

            # Expired/bogus stage token error
            r_bad_st = c.post(
                "/admin/products/import",
                data={"step": "preview", "stage_token": "bogus", CSRF_FORM_FIELD: csrf},
            )
            assert r_bad_st.status_code == 200 and "expired" in r_bad_st.get_data(as_text=True).lower()

            # step=preview using valid stage_token + column overrides
            r_prev = c.post(
                "/admin/products/import",
                data={
                    "step": "preview",
                    "stage_token": stage_tok,
                    "upsert_key": "sku",
                    "src_header_0": "ItemCode",
                    "dst_field_0": "sku",
                    "src_header_1": "ItemTitle",
                    "dst_field_1": "name",
                    "src_header_2": "Cost",
                    "dst_field_2": "price",
                    CSRF_FORM_FIELD: csrf,
                },
            )
            assert r_prev.status_code == 200
            prev_html = r_prev.get_data(as_text=True)
            pt_idx = prev_html.find('name="preview_token" value="')
            assert pt_idx != -1
            pt_start = pt_idx + len('name="preview_token" value="')
            prev_tok = prev_html[pt_start : prev_html.find('"', pt_start)]

            # Download failed-rows CSV + 404 on unknown token
            r_ecsv = c.get(f"/admin/products/import/errors/{prev_tok}.csv")
            assert r_ecsv.status_code == 200 and "SKU-W2" in r_ecsv.get_data(as_text=True)
            assert c.get("/admin/products/import/errors/unknown-tok.csv").status_code == 404

            # Commit without skip_errors re-caches token & shows error message
            r_c_fail = c.post(
                "/admin/products/import",
                data={"step": "commit", "preview_token": prev_tok, CSRF_FORM_FIELD: csrf},
            )
            assert r_c_fail.status_code == 200 and "Skip errored rows" in r_c_fail.get_data(as_text=True)

            # Commit with skip_errors=1 & async_commit=1 queues background job
            r_c_async = c.post(
                "/admin/products/import",
                data={
                    "step": "commit",
                    "preview_token": prev_tok,
                    "skip_errors": "1",
                    "async_commit": "1",
                    CSRF_FORM_FIELD: csrf,
                },
            )
            assert r_c_async.status_code == 302 and "/_jobs" in r_c_async.headers["Location"]
            jid = r_c_async.headers["Location"].split("focus=")[-1]
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                jrec = jobs.get(jid)
                if jrec is not None and jrec.status in {"succeeded", "failed"}:
                    break
                time.sleep(0.02)
            assert jobs.get(jid).status == "succeeded"  # type: ignore[union-attr]
        finally:
            deck.close()


def test_model_view_coercion_virtual_fields_inlines_and_system_checks() -> None:
    # 1. Media/template safety helpers
    assert is_safe_media_path("/static/a.js") is True
    assert is_safe_media_path("//cdn.evil/a.js") is False
    assert is_safe_media_path("/static/../secret.js") is False
    assert is_safe_media_path("https://evil.test/a.js") is False
    assert is_safe_media_path("/static/bad space.js") is False
    assert is_safe_template_name(None) is True
    assert is_safe_template_name("custom/list.html") is True
    assert is_safe_template_name("../etc/passwd") is False
    assert is_safe_template_name("/abs/path.html") is False

    # 2. coerce_form_value edge types & failure modes
    def _fm(ft: str, **kw: Any) -> FieldMeta:
        return FieldMeta(
            name="x",
            label="X",
            field_type=ft,
            python_type=str,
            nullable=kw.get("nullable", False),
            primary_key=False,
            unique=False,
            indexed=False,
            autoincrement=False,
            has_default=False,
            max_length=kw.get("max_length"),
            choices=kw.get("choices", ()),
            enum_class=kw.get("enum_class"),
            is_sensitive=False,
            is_heavy=False,
            fk_column=None,
            fk_target_table=None,
            fk_target_model=None,
            fk_relationship_name=None,
            array_item_type=kw.get("array_item_type"),
        )

    assert coerce_form_value("", _fm("boolean", nullable=True)) is None
    assert coerce_form_value("", _fm("string"), utc_passthrough=True) == ""
    with pytest.raises(ValueError, match="required"):
        coerce_form_value("", _fm("string"))
    with pytest.raises(ValueError, match="Must be one of"):
        coerce_form_value("nope", _fm("enum", enum_class=ImpKind))
    with pytest.raises(ValueError, match="Must be one of"):
        coerce_form_value("nope", _fm("enum", choices=(("a", "A"),)))
    with pytest.raises(ValueError, match="integer"):
        coerce_form_value(True, _fm("integer"))
    with pytest.raises(ValueError, match="finite"):
        coerce_form_value("nan", _fm("float"))
    with pytest.raises(ValueError, match="decimal"):
        coerce_form_value("abc", _fm("float"))
    with pytest.raises(ValueError, match="finite"):
        coerce_form_value("Infinity", _fm("decimal"))
    with pytest.raises(ValueError, match="UUID"):
        coerce_form_value("not-uuid", _fm("uuid"))
    with pytest.raises(ValueError, match="ISO date"):
        coerce_form_value("bad-date", _fm("date"))
    assert coerce_form_value("2026-01-01T12:00:00", _fm("datetime"), utc_passthrough=True).tzinfo == timezone.utc
    with pytest.raises(ValueError, match="ISO datetime"):
        coerce_form_value("bad-dt", _fm("datetime"))
    assert coerce_form_value("12:30:00", _fm("time")) == dt_time(12, 30, 0)
    with pytest.raises(ValueError, match="valid time"):
        coerce_form_value("bad-time", _fm("time"))
    assert coerce_form_value("[1, 2]", _fm("array", array_item_type="integer")) == [1, 2]
    assert coerce_form_value("1.5, 2.5", _fm("array", array_item_type="float")) == [1.5, 2.5]
    assert coerce_form_value(["true", "false", True], _fm("array", array_item_type="boolean")) == [True, False, True]
    with pytest.raises(ValueError, match="Invalid integer"):
        coerce_form_value(["x"], _fm("array", array_item_type="integer"))
    with pytest.raises(ValueError, match="Invalid float"):
        coerce_form_value(["nan"], _fm("array", array_item_type="float"))
    with pytest.raises(ValueError, match="Invalid boolean"):
        coerce_form_value(["maybe"], _fm("array", array_item_type="boolean"))
    with pytest.raises(ValueError, match="depth"):
        coerce_form_value({"a": {"b": {"c": 1}}}, _fm("json"), max_json_depth=2)
    with pytest.raises(ValueError, match="http://"):
        coerce_form_value("javascript:alert(1)", _fm("url"))
    with pytest.raises(ValueError, match="at most 3"):
        coerce_form_value("abcd", _fm("string", max_length=3))

    # 3. pydantic_validator bridge (v2 model_validate + nested loc + plain constructor fallback)
    class FakePydError(Exception):
        def errors(self) -> list[dict[str, Any]]:
            return [{"loc": ("price", "amount"), "msg": "must be > 0"}]

    class FakePydSchema:
        @classmethod
        def model_validate(cls, data: dict[str, Any]) -> None:
            if data.get("bad"):
                raise FakePydError()

    vfn = pydantic_validator(FakePydSchema)
    assert vfn({"bad": False}, None, True) == {}
    assert vfn({"bad": True}, None, True) == {"price": ["amount: must be > 0"]}

    class LegacySchema:
        def __init__(self, **kw: Any) -> None:
            if kw.get("bad"):
                raise RuntimeError("legacy boom")

    vfn2 = pydantic_validator(LegacySchema)
    assert vfn2({"bad": True}, None, True) == {"__all__": ["legacy boom"]}

    # 4. InlineModelView + ModelView hooks (format_inline_cell, field_conditions, VirtualField, view_on_site, uploads, inlines)
    p_store = MemoryFileStorage()
    i_store = MemoryFileStorage()

    class RichPartInline(InlineModelView):
        model = ImpPart
        fk_column = "product_id"
        columns = ("label", "qty", "spec_file", "is_big", "tier_badge")
        readonly_fields = ("qty",)
        file_fields = MappingProxyType({"spec_file": FileFieldConfig(storage=i_store, kind="file")})
        min_num = 1
        max_rows = 3

        @display(label="Big", boolean=True)
        def is_big(self, obj: Any) -> bool:
            return bool(obj.qty >= 5)

        @display(label="Tier", tone="ok")
        def tier_badge(self, obj: Any) -> str:
            return f"x{obj.qty}"

        def validate_rows(self, rows_data: Any, *, parent_obj: Any = None, user: Any = None) -> dict[str, list[str]]:
            _ = (parent_obj, user)
            if any(r.get("label") == "FORBIDDEN_INLINE" for r in rows_data):
                return {"imp_parts": ["Forbidden inline row"]}
            return {}

    class RichProductView(ModelView):
        model = ImpProduct
        slug = "products"
        columns = ("sku", "name", "parts", "meta_json", "status_tag")
        extra_form_fields = (
            VirtualField(name="audit_reason", label="Reason", default="manual", modes=("create", "edit")),
            VirtualField(name="notify", field_type="boolean", modes=("create",)),
        )
        field_conditions = MappingProxyType(
            {
                "notes": ("active", "truthy", True),
                "created_on": ("kind", "in", ("alpha", "beta")),
            }
        )
        file_fields = MappingProxyType(
            {"attachment": FileFieldConfig(storage=p_store, kind="file", delete_orphan=True)}
        )
        inlines = (RichPartInline,)
        view_on_site = "/shop/{sku}"

        @display(label="Status", tone="info")
        def status_tag(self, obj: Any) -> str:
            return obj.kind.value

    with sqlite_memory_engine() as eng:
        ImpBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        rv = RichProductView()
        inl = rv.inline_views[0]
        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role("masked", permissions=frozenset({"*"}), masked_fields={inl.meta.slug: frozenset({"label"})}),
            ]
        )
        u_adm = DeckUser(id="1", username="adm", roles=("admin",), is_superuser=True)
        u_msk = DeckUser(id="2", username="msk", roles=("masked",))

        with SessionLocal() as s:
            p1 = ImpProduct(sku="S1", name="Prod 1", meta_json={"long": "x" * 60})
            p2 = ImpProduct(sku="S2", name="Prod 2")
            s.add_all([p1, p2])
            s.flush()
            parts = [ImpPart(product_id=p1.id, label=f"P{i}", qty=i) for i in range(1, 6)]
            p2_part = ImpPart(product_id=p2.id, label="OtherParent", qty=1)
            s.add_all([*parts, p2_part])
            s.commit()

            # format_inline_cell & format_cell variants
            assert "—" in str(inl.format_inline_cell("label", None))
            assert "dk-masked" in str(inl.format_inline_cell("label", parts[0], auth=auth, user=u_msk))
            assert "dk-badge" in str(inl.format_inline_cell("tier_badge", parts[0]))
            assert inl.format_inline_cell("is_big", parts[4]) is not None
            assert "+2" in str(rv.format_cell("parts", p1, auth=auth, user=u_adm))
            assert "…" in str(rv.format_cell("meta_json", p1, auth=auth, user=u_adm))
            assert "dk-badge" in str(rv.format_cell("status_tag", p1, auth=auth, user=u_adm))

            # view_on_site & initial data
            assert rv.get_view_on_site_url(p1) == "/shop/S1"
            rv_fn = RichProductView()
            rv_fn.view_on_site = lambda o: f"https://ok.test/{o.sku}"  # type: ignore[assignment]
            assert rv_fn.get_view_on_site_url(p1) == "https://ok.test/S1"
            rv_fn.view_on_site = lambda o: "javascript:alert(1)"  # type: ignore[assignment]
            assert rv_fn.get_view_on_site_url(p1) is None
            init = rv.get_changeform_initial_data({"sku": "NEW", "audit_reason": "init", "_skip": "1"}, u_adm, auth=auth)
            assert init["sku"] == "NEW" and init["audit_reason"] == "init"

            # apply_form_data with VirtualField + field_conditions
            vd = rv.apply_form_data(
                s,
                p1,
                {"sku": "S1", "name": "Prod 1 Updated", "active": "", "notes": "ignored-falsy", "audit_reason": "r2"},
                auth=auth,
                user=u_adm,
                mode="edit",
            )
            assert vd["audit_reason"] == "r2"

            # apply_file_uploads upload + clear orphan
            up = FileStorage(stream=io.BytesIO(b"doc bytes"), filename="spec.txt")
            stored_f, _ = rv.apply_file_uploads(
                p1, {"attachment": up}, {}, auth=auth, user=u_adm, mode="edit", default_max_bytes=1024 * 1024
            )
            assert len(stored_f) == 1
            _, orph = rv.apply_file_uploads(
                p1, {}, {"_clear_attachment": "1"}, auth=auth, user=u_adm, mode="edit", default_max_bytes=1024 * 1024
            )
            assert len(orph) == 1

            # apply_inline_forms: IDOR cross-parent child rejection + validate_rows failure
            inl_p = f"inline__{inl.meta.slug}__0__"
            with pytest.raises(PermissionDeniedError):
                rv.apply_inline_forms(
                    s,
                    p1,
                    {f"{inl_p}_pk": str(p2_part.id), f"{inl_p}label": "Hijack"},
                    auth=auth,
                    user=u_adm,
                )
            with pytest.raises(ValidationError):
                rv.apply_inline_forms(
                    s,
                    p1,
                    {f"{inl_p}label": "FORBIDDEN_INLINE"},
                    auth=auth,
                    user=u_adm,
                )

    # 5. System checks (DECK-E001 .. DECK-E012, DECK-W001, DECK-W002)
    class BadWidget(FormWidget):
        template = "text"
        media_js = ("https://evil.cdn/x.js",)

        def render(self, *args: Any, **kwargs: Any) -> str:
            _ = (args, kwargs)
            return ""

    class BadInline(InlineModelView):
        model = ImpPart
        fk_column = "nonexistent_fk"
        columns = ("api_secret", "ghost_col")
        readonly_fields = ("api_secret", "ghost_ro")

    class BrokenView(ModelView):
        model = ImpProduct
        slug = "broken"
        columns = ("password_hash", "ghost_col")
        form_columns = ("ghost_form",)
        searchable_columns = ("", "a.b.c.d", "password_hash", "ghost_s", "parts.api_secret", "parts.ghost_leaf")
        filterable_columns = ("password_hash", "ghost_f", "bad.dot")
        sortable_columns = ("password_hash", "ghost_sort", "bad.dot")
        inline_editable_columns = ("password_hash", "ghost_ie")
        export_columns = ("password_hash", "ghost_exp")
        readonly_fields = ("ghost_ro",)
        fieldsets = (Fieldset("Main", ("sku", "sku", "ghost_fs", "password_hash")),)
        date_hierarchy = "name"
        prepopulated_fields = MappingProxyType({"password_hash": ("ghost_src", "password_hash")})
        list_display_links = ("not_in_list",)
        kanban_column = "name"
        inlines = (BadInline,)
        list_template = "../escape.html"
        media = ViewMedia(css=("https://evil.cdn/a.css",))
        field_widgets = MappingProxyType({"name": BadWidget()})
        list_select_related = ("", "nonexistent_rel")

        def get_urls(self) -> tuple[Any, ...]:
            return (
                "not-a-model-url",
                ModelURL(rule="../escape", endpoint="bad-ep!", handler="not-callable"),  # type: ignore[arg-type]
            )

    findings = check_model_view(BrokenView())
    codes = {f.code for f in findings}
    for expected in (
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
    ):
        assert expected in codes, f"Missing check code {expected} in {sorted(codes)}"

    # DECK-W002: production advisory when SQLAlchemyAuthProvider has strict_password_policy=False
    with sqlite_memory_engine() as eng:
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "checks-secret-32-bytes-long!!!!!"
        app.config["TESTING"] = True
        iam_auth = SQLAlchemyAuthProvider(eng, strict_password_policy=False)
        deck = Deck(
            app,
            engine=eng,
            auth=iam_auth,
            audit_store=False,
            environment="production",
        )
        try:
            deck_codes = {f.code for f in run_model_view_checks(deck)}
            assert "DECK-W002" in deck_codes
        finally:
            deck.close()
    assert introspect_model(ImpComposite).primary_keys


def test_inline_forms_file_uploads_soft_delete_min_max_and_rbac_guards() -> None:
    i_store = MemoryFileStorage()

    class PartInline(InlineModelView):
        model = ImpPart
        fk_column = "product_id"
        columns = ("label", "qty", "spec_file")
        file_fields = MappingProxyType(
            {"spec_file": FileFieldConfig(storage=i_store, kind="file", delete_orphan=True)}
        )
        min_num = 1
        max_rows = 2

    class ReadOnlyPartInline(InlineModelView):
        model = ImpPart
        fk_column = "product_id"
        columns = ("label",)
        can_create = False
        can_edit = False
        can_delete = False

    class PartSoftView(ModelView):
        model = ImpPart
        slug = "imp-parts"
        soft_delete_column = "deleted_at"

    class ProdWithInlinesView(ModelView):
        model = ImpProduct
        slug = "products"
        inlines = (PartInline,)

    with sqlite_memory_engine() as eng:
        ImpBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        auth = RBACAuthProvider(
            roles=[
                Role("admin", permissions=frozenset({"*"})),
                Role(
                    "limited",
                    permissions=frozenset({"imp-parts:view", "imp-parts:edit"}),
                    readonly_fields={"imp-parts": frozenset({"qty"})},
                ),
            ]
        )
        u_adm = DeckUser(id="1", username="adm", roles=("admin",), is_superuser=True)
        u_lim = DeckUser(id="2", username="lim", roles=("limited",))

        pv = ProdWithInlinesView()
        soft_child_view = PartSoftView()
        ro_inl = ReadOnlyPartInline()
        slug = pv.inline_views[0].meta.slug

        with SessionLocal() as s:
            p1 = ImpProduct(sku="INL-1", name="Parent")
            s.add(p1)
            s.flush()
            existing = ImpPart(product_id=p1.id, label="Existing", qty=2)
            s.add(existing)
            s.commit()

            # 1. Create new child with file upload + edit existing child (preserving masked/ro fields for limited user)
            newly: list[Any] = []
            orphans: list[Any] = []
            diffs = pv.apply_inline_forms(
                s,
                p1,
                {
                    f"inline__{slug}__0___pk": str(existing.id),
                    f"inline__{slug}__0__label": "Existing Edited",
                    f"inline__{slug}__0__qty": "3",
                    f"inline__{slug}__1__label": "New With File",
                    f"inline__{slug}__1__qty": "4",
                    f"inline__{slug}__2__label": "",  # blank row skipped
                    f"inline__{slug}__3___delete": "1",  # new row marked delete skipped
                },
                auth=auth,
                user=u_adm,
                files={f"inline__{slug}__1__spec_file": FileStorage(io.BytesIO(b"spec"), filename="a.txt")},
                newly_stored_files=newly,
                orphan_files=orphans,
            )
            s.commit()
            assert len(diffs) == 2 and len(newly) == 1
            created_part = s.scalar(sa.select(ImpPart).where(ImpPart.label == "New With File"))
            assert created_part is not None and created_part.spec_file is not None

            # 2. Edit existing child clearing file (queues orphan) + limited user readonly col preserved
            orphans2: list[Any] = []
            pv.apply_inline_forms(
                s,
                p1,
                {
                    f"inline__{slug}__0___pk": str(created_part.id),
                    f"inline__{slug}__0__label": "Cleared File",
                    f"inline__{slug}__0__qty": "99",  # readonly for u_lim
                    f"inline__{slug}__0___clear_spec_file": "1",
                },
                auth=auth,
                user=u_lim,
                orphan_files=orphans2,
            )
            s.commit()
            assert len(orphans2) == 1 and created_part.spec_file is None and created_part.qty == 4

            # 3. Soft-delete child when child_view has soft_delete_column
            pv.apply_inline_forms(
                s,
                p1,
                {
                    f"inline__{slug}__0___pk": str(created_part.id),
                    f"inline__{slug}__0___delete": "1",
                },
                auth=auth,
                user=u_adm,
                views_by_model={ImpPart: soft_child_view},
            )
            s.commit()
            assert created_part.deleted_at is not None

            # 4. Invalid PK & max_rows & min_num validation errors
            with pytest.raises(ValidationError):
                pv.apply_inline_forms(
                    s,
                    p1,
                    {f"inline__{slug}__0___pk": "not-an-int", f"inline__{slug}__0__label": "Bad"},
                    auth=auth,
                    user=u_adm,
                )
            with pytest.raises(ValidationError, match="Maximum"):
                pv.apply_inline_forms(
                    s,
                    p1,
                    {
                        f"inline__{slug}__0__label": "Over 1",
                        f"inline__{slug}__0__qty": "1",
                        f"inline__{slug}__1__label": "Over 2",
                        f"inline__{slug}__1__qty": "1",
                    },
                    auth=auth,
                    user=u_adm,
                )
            with pytest.raises(ValidationError, match="At least"):
                pv.apply_inline_forms(
                    s,
                    p1,
                    {
                        f"inline__{slug}__0___pk": str(existing.id),
                        f"inline__{slug}__0___delete": "1",
                    },
                    auth=auth,
                    user=u_adm,
                    views_by_model={ImpPart: soft_child_view},
                )
            s.rollback()

            # 5. Read-only inline guards (can_delete=False, can_create=False, can_edit=False skip)
            with pytest.raises(PermissionDeniedError):
                pv.apply_inline_forms(
                    s,
                    p1,
                    {f"inline__{slug}__0___pk": str(existing.id), f"inline__{slug}__0___delete": "1"},
                    auth=auth,
                    user=u_adm,
                    inlines=(ro_inl,),
                )
            with pytest.raises(PermissionDeniedError):
                pv.apply_inline_forms(
                    s,
                    p1,
                    {f"inline__{slug}__0__label": "Unauthorized Create"},
                    auth=auth,
                    user=u_adm,
                    inlines=(ro_inl,),
                )
            # Editing with can_edit=False skips mutation cleanly
            pv.apply_inline_forms(
                s,
                p1,
                {f"inline__{slug}__0___pk": str(existing.id), f"inline__{slug}__0__label": "Ignored"},
                auth=auth,
                user=u_adm,
                inlines=(ro_inl,),
            )


def test_importer_fk_scoping_dynamic_readonly_noop_approval_block_and_redis_preview_store() -> None:
    from flask_deck import InMemoryApprovalStore
    from flask_deck.importer import (
        RedisPreviewStore,
        format_failed_rows_csv,
        parse_import_payload,
    )

    class _ImpScopeBase(DeclarativeBase):
        pass

    class _ImpTenant(_ImpScopeBase):
        __tablename__ = "imp_tenants"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(sa.String(60), nullable=False)
        active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    class _ImpRecord(_ImpScopeBase):
        __tablename__ = "imp_records"
        id: Mapped[int] = mapped_column(primary_key=True)
        code: Mapped[str] = mapped_column(sa.String(40), unique=True, nullable=False)
        tenant_id: Mapped[int] = mapped_column(sa.ForeignKey("imp_tenants.id"), nullable=False)
        title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
        secret_note: Mapped[str] = mapped_column(sa.String(80), default="orig", nullable=False)
        version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    class _TenantView(ModelView):
        model = _ImpTenant
        slug = "tenants"

        def scope_query(self, stmt: Any, user: Any) -> Any:
            _ = user
            return stmt.where(_ImpTenant.active.is_(True))

    class _RecordView(ModelView):
        model = _ImpRecord
        slug = "records"
        version_column = "version"

        def get_readonly_fields(self, user: Any, obj: Any = None) -> tuple[str, ...]:
            _ = user
            return ("secret_note",) if obj is not None else ("version",)

    class _GovRecordView(_RecordView):
        slug = "gov-records"
        approval_required = ("create",)

    # 1. parse_import_payload error paths + failed rows CSV formatting
    kw_lim = {"max_bytes": 1024, "max_rows": 2, "max_columns": 20, "max_json_depth": 4}
    with pytest.raises(ImportLimitError):
        parse_import_payload(b"", filename="empty.csv", **kw_lim)
    with pytest.raises(ImportLimitError):
        parse_import_payload(b"\xff\xfe", filename="bad.csv", **kw_lim)
    with pytest.raises(ImportLimitError):
        parse_import_payload(b'{"not": "a list"}', filename="bad.json", **kw_lim)
    assert parse_import_payload(b"[]", filename="empty.json", **kw_lim) == ("json", (), [])
    with pytest.raises(ImportLimitError):
        parse_import_payload(b"[123]", filename="badrow.json", **kw_lim)
    with pytest.raises(ImportLimitError):
        parse_import_payload(b"a\n1\n2\n3\n", filename="big.csv", **kw_lim)

    # 2. FK scoping via views_by_model & dynamic-readonly no-op skip during commit
    with sqlite_memory_engine() as eng:
        _ImpScopeBase.metadata.create_all(eng)
        SL = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SL() as s:
            t_ok = _ImpTenant(name="Active Co", active=True)
            t_no = _ImpTenant(name="Inactive Co", active=False)
            s.add_all([t_ok, t_no])
            s.flush()
            r1 = _ImpRecord(code="REC-1", tenant_id=t_ok.id, title="Keep", secret_note="orig")
            s.add(r1)
            s.commit()
            t_ok_id, t_no_id, r1_id = t_ok.id, t_no.id, r1.id

        rv = _RecordView()
        tv = _TenantView()
        vmap = {_ImpTenant: tv, _ImpRecord: rv}
        auth = OpenAuthProvider()
        with SL() as s:
            rows_json = json.dumps(
                [
                    # Out-of-scope FK tenant_id -> rejected during dry-run!
                    {"code": "REC-BAD-FK", "tenant_id": str(t_no_id), "title": "Bad FK"},
                    # Existing row where ONLY dynamic-readonly 'secret_note' differs -> unchanged / no-op!
                    {"code": "REC-1", "tenant_id": str(t_ok_id), "title": "Keep", "secret_note": "tamper"},
                    # Valid new row in active tenant
                    {"code": "REC-GOOD", "tenant_id": str(t_ok_id), "title": "Good"},
                ]
            ).encode("utf-8")
            dr = run_dry_run_import(
                s,
                rv,
                raw_bytes=rows_json,
                filename="scoped.json",
                auth=auth,
                user=None,
                upsert_key="code",
                views_by_model=vmap,
            )
            assert dr.errors == 1
            assert dr.creates == 1
            assert dr.updates == 0 and dr.unchanged == 1
            assert "REC-BAD-FK" in format_failed_rows_csv(dr)

            audits: list[Any] = []
            created, updated = commit_dry_run_import(
                s,
                rv,
                dr,
                user=None,
                skip_errors=True,
                row_audit_cb=lambda *a: audits.append(a),
                views_by_model=vmap,
            )
            assert created == 1 and updated == 0
            assert len(audits) == 1
            r1_after = s.get(_ImpRecord, r1_id)
            assert r1_after is not None and r1_after.version == 1 and r1_after.secret_note == "orig"

        # 3. HTTP bulk import blocked on approval-required view
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "imp-gov-block-secret-32-bytes!!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SL,
            engine=eng,
            allow_insecure_open=True,
            approval_store=InMemoryApprovalStore(),
            audit_store=False,
        )
        deck.register(_TenantView, _GovRecordView)
        try:
            c = app.test_client()
            csrf = _extract_csrf(c, "/admin/gov-records/import")
            r_prev = c.post(
                "/admin/gov-records/import",
                data={
                    "step": "preview",
                    "file": (
                        io.BytesIO(f"code,tenant_id,title\nREC-GOV,{t_ok_id},Bypass\n".encode()),
                        "g.csv",
                    ),
                    CSRF_FORM_FIELD: csrf,
                },
                content_type="multipart/form-data",
            )
            assert r_prev.status_code == 200
            html_p = r_prev.get_data(as_text=True)
            pt_idx = html_p.find('name="preview_token" value="')
            if pt_idx != -1:
                pt_start = pt_idx + len('name="preview_token" value="')
                ptok = html_p[pt_start : html_p.find('"', pt_start)]
                r_com = c.post(
                    "/admin/gov-records/import",
                    data={"step": "commit", "preview_token": ptok, CSRF_FORM_FIELD: csrf},
                )
                assert r_com.status_code == 200 and "approval" in r_com.get_data(as_text=True).lower()
            with SL() as s:
                assert s.scalar(sa.select(_ImpRecord).where(_ImpRecord.code == "REC-GOV")) is None
        finally:
            deck.close()

    # 4. RedisPreviewStore full put / peek / consume / delete / isolation / corrupt JSON lifecycle
    class _MemRedis:
        def __init__(self) -> None:
            self.kv: dict[str, str] = {}

        def set(self, k: str, v: str, ex: int | None = None) -> None:
            _ = ex
            self.kv[k] = v

        def get(self, k: str) -> str | None:
            return self.kv.get(k)

        def delete(self, k: str) -> int:
            return 1 if self.kv.pop(k, None) is not None else 0

        def eval(self, _script: str, _numkeys: int, key: str, uid: str, st: str, slug: str) -> str | None:
            raw = self.kv.get(key)
            if not raw:
                return None
            try:
                env = json.loads(raw)
            except Exception:
                return None
            if not isinstance(env, dict) or env.get("user_id") != uid or env.get("session_token") != st or env.get("model_slug") != slug:
                return None
            self.kv.pop(key, None)
            return raw

    mr = _MemRedis()
    rps = RedisPreviewStore(mr, ttl_seconds=60, key_prefix="test:prev:")
    rps.put(dr, user_id="u1", session_token="s1")
    assert rps.peek(dr.token, user_id="u1", session_token="s1", model_slug="records") is not None
    assert rps.peek(dr.token, user_id="u2", session_token="s1", model_slug="records") is None
    assert rps.consume(dr.token, user_id="u2", session_token="s1", model_slug="records") is None
    got = rps.consume(dr.token, user_id="u1", session_token="s1", model_slug="records")
    assert got is not None and got.token == dr.token
    assert rps.consume(dr.token, user_id="u1", session_token="s1", model_slug="records") is None
    mr.set("test:prev:corrupt", "{not-json")
    assert rps.peek("corrupt", user_id="u1", session_token="s1", model_slug="records") is None
    assert rps.consume("corrupt", user_id="u1", session_token="s1", model_slug="records") is None
