# ruff: noqa: RUF001
from __future__ import annotations

import io
import re
import struct
import types
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from markupsafe import Markup
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    BabelTranslator,
    BrandConfig,
    DateTimeFormatter,
    Deck,
    DeckUser,
    FileFieldConfig,
    FileFormatter,
    ImageFormatter,
    LocalFileStorage,
    MemoryFileStorage,
    ModelView,
    RBACAuthProvider,
    Role,
    S3StorageBackend,
)
from flask_deck.security import CSRF_FORM_FIELD, CSRF_SESSION_KEY
from flask_deck.storage import make_demo_png


class MediaBase(DeclarativeBase):
    pass


class AssetItem(MediaBase):
    __tablename__ = "v03_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    tenant_id: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    avatar_key: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    doc_key: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    secret_doc_key: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    published_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime(2026, 6, 15, 10, 30, tzinfo=timezone.utc)
    )


def _csrf_token(client: Any) -> str:
    with client.session_transaction() as sess:
        tok = sess.get(CSRF_SESSION_KEY)
        if not tok:
            tok = "t" * 48
            sess[CSRF_SESSION_KEY] = tok
        return str(tok)


def _login_user(client: Any, username: str, password: str) -> None:
    resp = client.get("/admin/login")
    assert resp.status_code == 200
    tok = _csrf_token(client)
    post = client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: tok},
        follow_redirects=False,
    )
    assert post.status_code == 302


def test_file_upload_magic_bytes_bomb_guard_and_rbac_media_proxy(tmp_path: Path) -> None:
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    MediaBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    local_store = LocalFileStorage(tmp_path / "uploads")

    class AssetView(ModelView):
        model = AssetItem
        columns = ("title", "avatar_key", "doc_key", "published_at")
        file_fields = MappingProxyType(
            {
                "avatar_key": FileFieldConfig(
                    storage=local_store,
                    kind="image",
                    max_bytes=512_000,
                    max_image_pixels=500_000,
                    prefix="avatars",
                    delete_orphan=True,
                ),
                "doc_key": FileFieldConfig(
                    storage=local_store,
                    kind="file",
                    prefix="docs",
                ),
                "secret_doc_key": FileFieldConfig(
                    storage=local_store,
                    kind="file",
                    prefix="secrets",
                ),
            }
        )
        column_formatters = MappingProxyType(
            {
                "avatar_key": ImageFormatter(),
                "doc_key": FileFormatter(),
                "published_at": DateTimeFormatter(),
            }
        )

        def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
            if user and not user.is_superuser and user.tenant_id is not None:
                return stmt.where(AssetItem.tenant_id == user.tenant_id)
            return stmt

    roles = [
        Role(name="admin", permissions=frozenset({"*"})),
        Role(
            name="tenant_user",
            permissions=frozenset({"asset-items:view", "asset-items:create", "asset-items:edit"}),
            hidden_fields={"asset-items": frozenset({"secret_doc_key"})},
        ),
    ]
    auth = RBACAuthProvider(
        roles=roles,
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="admin", username="admin", roles=("admin",), is_superuser=True),
                password="pw",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="t1", username="t1", roles=("tenant_user",), tenant_id=1),
                password="pw",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="t2", username="t2", roles=("tenant_user",), tenant_id=2),
                password="pw",
            ),
        ],
    )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key-thirty-two-bytes-long!"
    app.config["TESTING"] = True
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, auto_audit=False)
    try:
        deck.register(AssetView)

        client = app.test_client()
        _login_user(client, "admin", "pw")
        tok = _csrf_token(client)

        # 1. Spoofed .png containing XSS <script> must be REJECTED
        bad_xss = client.post(
            "/admin/asset-items/new",
            data={
                CSRF_FORM_FIELD: tok,
                "title": "Bad XSS",
                "tenant_id": "1",
                "avatar_key": (io.BytesIO(b"<script>alert(1)</script>"), "fake.png"),
            },
            content_type="multipart/form-data",
        )
        assert bad_xss.status_code == 200
        assert b"Unsupported or disallowed file content" in bad_xss.data

        # 2. SVG upload must be REJECTED by default
        bad_svg = client.post(
            "/admin/asset-items/new",
            data={
                CSRF_FORM_FIELD: tok,
                "title": "Bad SVG",
                "tenant_id": "1",
                "avatar_key": (io.BytesIO(b'<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>'), "evil.svg"),
            },
            content_type="multipart/form-data",
        )
        assert bad_svg.status_code == 200
        assert b"SVG uploads are disabled" in bad_svg.data

        # 3. Decompression-bomb PNG header (5000x5000 = 25MP > 500K cap) must be REJECTED
        bomb_ihdr = struct.pack(">IIBBBBB", 5000, 5000, 8, 2, 0, 0, 0)
        bomb_png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + bomb_ihdr + b"\x00\x00\x00\x00"
        bad_bomb = client.post(
            "/admin/asset-items/new",
            data={
                CSRF_FORM_FIELD: tok,
                "title": "Bomb",
                "tenant_id": "1",
                "avatar_key": (io.BytesIO(bomb_png), "bomb.png"),
            },
            content_type="multipart/form-data",
        )
        assert bad_bomb.status_code == 200
        assert b"exceed safety limit" in bad_bomb.data

        # 4. Valid PNG + valid PDF upload succeeds
        valid_png = make_demo_png(32, 32)
        valid_pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"
        ok_create = client.post(
            "/admin/asset-items/new",
            data={
                CSRF_FORM_FIELD: tok,
                "title": "Tenant 1 Asset",
                "tenant_id": "1",
                "avatar_key": (io.BytesIO(valid_png), "logo.png"),
                "doc_key": (io.BytesIO(valid_pdf), "manual.pdf"),
                "secret_doc_key": (io.BytesIO(valid_pdf), "topsecret.pdf"),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert ok_create.status_code == 302

        with SessionLocal() as sess:
            item = sess.scalars(sa.select(AssetItem)).one()
            old_avatar = item.avatar_key
            assert old_avatar is not None and local_store.exists(old_avatar)
            asset_id = item.id

        # 5. Authorized /_media serves PNG inline with sandbox CSP & nosniff, PDF as attachment
        img_resp = client.get(f"/admin/_media/asset-items/avatar_key/{asset_id}")
        assert img_resp.status_code == 200
        assert img_resp.mimetype == "image/png"
        assert "inline" in img_resp.headers["Content-Disposition"]
        assert img_resp.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
        assert img_resp.headers["X-Content-Type-Options"] == "nosniff"

        pdf_resp = client.get(f"/admin/_media/asset-items/doc_key/{asset_id}")
        assert pdf_resp.status_code == 200
        assert pdf_resp.mimetype == "application/pdf"
        assert "attachment" in pdf_resp.headers["Content-Disposition"]

        # 6. Edit with _clear_avatar_key=1 clears reference and deletes orphan after commit
        clear_resp = client.post(
            f"/admin/asset-items/{asset_id}/edit",
            data={CSRF_FORM_FIELD: tok, "title": "Tenant 1 Asset", "tenant_id": "1", "_clear_avatar_key": "1"},
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert clear_resp.status_code == 302
        assert not local_store.exists(old_avatar)

        # 7. Path traversal check on LocalFileStorage directly
        with pytest.raises(ValueError):
            local_store.save(b"x", key="../../etc/passwd", content_type="text/plain")

        # 8. Multi-tenant IDOR & hidden_fields check on /_media
        t1_client = app.test_client()
        _login_user(t1_client, "t1", "pw")
        assert t1_client.get(f"/admin/_media/asset-items/doc_key/{asset_id}").status_code == 200
        assert t1_client.get(f"/admin/_media/asset-items/secret_doc_key/{asset_id}").status_code == 403

        t2_client = app.test_client()
        _login_user(t2_client, "t2", "pw")
        assert t2_client.get(f"/admin/_media/asset-items/doc_key/{asset_id}").status_code == 404
    finally:
        deck.close()


def test_s3_storage_backend_roundtrip_with_fake_client() -> None:
    objects: dict[tuple[str, str], tuple[bytes, str, str | None]] = {}

    class FakeS3Client:
        def put_object(
            self, *, Bucket: str, Key: str, Body: bytes, ContentType: str, **kwargs: Any
        ) -> None:
            objects[(Bucket, Key)] = (Body, ContentType, kwargs.get("ContentDisposition"))

        def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if (Bucket, Key) not in objects:
                raise FileNotFoundError(Key)
            body, ctype, _disp = objects[(Bucket, Key)]
            return {"Body": io.BytesIO(body), "ContentType": ctype}

        def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if (Bucket, Key) not in objects:
                raise KeyError(Key)
            return {"ContentLength": len(objects[(Bucket, Key)][0])}

        def delete_object(self, *, Bucket: str, Key: str) -> None:
            objects.pop((Bucket, Key), None)

        def generate_presigned_url(
            self, op: str, *, Params: dict[str, str], ExpiresIn: int
        ) -> str:
            return f"https://r2.example.com/{Params['Bucket']}/{Params['Key']}?ttl={ExpiresIn}&op={op}"

    s3 = S3StorageBackend("acme-bucket", prefix="prod", client=FakeS3Client())
    stored = s3.save(b"hello-r2", key="docs/a.txt", content_type="text/plain")
    assert stored.size_bytes == 8
    assert objects[("acme-bucket", "prod/docs/a.txt")][2] == "attachment"
    assert s3.exists("docs/a.txt")
    stream, ctype = s3.open("docs/a.txt")
    assert stream.read() == b"hello-r2"
    assert ctype == "text/plain"
    url = s3.presigned_url("docs/a.txt", expires_in=120)
    assert url is not None and "acme-bucket/prod/docs/a.txt" in url
    s3.delete("docs/a.txt")
    assert not s3.exists("docs/a.txt")


def test_i18n_rtl_timezone_babel_and_strict_csp_branding() -> None:
    # 1. BrandConfig adversarial injection tests
    with pytest.raises(ValueError):
        BrandConfig(accent="#ff0000; } body { background: url(evil)")
    with pytest.raises(ValueError):
        BrandConfig(logo_url="javascript:alert(1)")
    with pytest.raises(ValueError):
        BrandConfig(extra_css=("https://evil.example/x.css",))
    with pytest.raises(ValueError):
        BrandConfig(template_slots={"nonexistent_slot": lambda _c: Markup("")})

    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    MediaBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as sess:
        sess.add(
            AssetItem(
                title="TZ Record",
                published_at=datetime(2026, 6, 15, 10, 30, tzinfo=timezone.utc),
            )
        )
        sess.commit()

    class TZAssetView(ModelView):
        model = AssetItem
        columns = ("title", "published_at")
        column_formatters = MappingProxyType({"published_at": DateTimeFormatter()})

    brand = BrandConfig(
        accent="#2563eb",
        logo_mark="A",
        footer_note="ACME-CORP",
        template_slots={
            "dashboard_top": lambda _ctx: "<script>alert('xss')</script>",  # plain str must be escaped!
            "topbar_right": lambda _ctx: Markup('<span class="dk-badge dk-badge-info">VIP</span>'),
        },
    )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "brand-test-secret-key-thirty-two-bytes!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        allow_insecure_open=True,
        auto_audit=False,
        brand=brand,
    )
    try:
        deck.register(TZAssetView)
        client = app.test_client()

        # 2. Verify /_theme.css strict CSP compliance & WCAG contrast
        dash = client.get("/admin/")
        assert dash.status_code == 200
        html = dash.data.decode()
        assert "/admin/_theme.css?v=" in html
        assert "ACME-CORP" in html
        assert "&lt;script&gt;alert(" in html  # plain slot string auto-escaped
        assert '<span class="dk-badge dk-badge-info">VIP</span>' in html
        assert not re.search(r'\sstyle="', html)  # zero inline style=
        assert "<style" not in html.lower()

        css_resp = client.get("/admin/_theme.css?v=abc")
        assert css_resp.status_code == 200
        assert "text/css" in css_resp.content_type
        assert b"--btn-bg:#2563eb;" in css_resp.data
        assert b"--btn-fg:#fafafa;" in css_resp.data  # dark cobalt gets crisp light fg

        # 3. Switch locale -> Turkish ('tr') and Timezone -> Europe/Istanbul (+03:00)
        tok = _csrf_token(client)
        pref_tr = client.post(
            "/admin/_preferences",
            data={CSRF_FORM_FIELD: tok, "locale": "tr", "timezone": "Europe/Istanbul", "next": "/admin/asset-items/"},
            follow_redirects=True,
        )
        assert pref_tr.status_code == 200
        tr_html = pref_tr.data.decode()
        assert 'lang="tr" dir="ltr"' in tr_html
        assert "Genel Bakış" in tr_html
        assert "2026-06-15 13:30" in tr_html  # 10:30 UTC -> 13:30 Europe/Istanbul!

        # 4. Switch locale -> Arabic ('ar') verifies RTL dir="rtl"
        pref_ar = client.post(
            "/admin/_preferences",
            data={CSRF_FORM_FIELD: tok, "locale": "ar", "timezone": "UTC", "next": "/admin/"},
            follow_redirects=True,
        )
        assert pref_ar.status_code == 200
        ar_html = pref_ar.data.decode()
        assert 'lang="ar" dir="rtl"' in ar_html
        assert "لوحة التحكم" in ar_html

        # 5. Invalid locale / invalid timezone rejected (400)
        assert (
            client.post(
                "/admin/_preferences",
                data={CSRF_FORM_FIELD: tok, "locale": "zz"},
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/admin/_preferences",
                data={CSRF_FORM_FIELD: tok, "timezone": "Mars/Olympus"},
            ).status_code
            == 400
        )
    finally:
        deck.close()

    # 6. BabelTranslator works cleanly with injected flask_babel-compatible module
    fake_babel = types.SimpleNamespace(
        get_locale=lambda: "tr_TR",
        gettext=lambda msg, **kw: "Özel Çeviri" if msg == "Dashboard" else msg,
    )
    bt = BabelTranslator(babel_module=fake_babel)
    assert bt.get_locale() == "tr"
    assert bt.translate("Dashboard") == "Özel Çeviri"
    assert not bt.is_rtl()
    _ = MemoryFileStorage()
