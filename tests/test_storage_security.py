"""Security and storage contract tests: magic-byte sniffing, image bombs, Local & S3 backends."""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import Any

import pytest

from flask_deck.storage import (
    FileFieldConfig,
    LocalFileStorage,
    MemoryFileStorage,
    S3StorageBackend,
    detect_mime_from_bytes,
    make_demo_png,
    parse_image_dimensions,
    save_stream_to_storage,
    store_validated_upload,
    stream_storage_object,
    validate_and_read_upload,
)


def _make_minimal_jpeg(width: int, height: int) -> bytes:
    # SOI + APP0 dummy segment + SOF0 with (height, width) + EOI
    app0 = b"\xff\xe0" + struct.pack(">H", 4) + b"\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 8, 8, height, width, 1)
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xd9"


def _make_minimal_gif(screen_w: int, screen_h: int, frame_w: int, frame_h: int) -> bytes:
    # GIF89a header + Global Color Table (2 entries = 6 bytes) + Comment Ext + Image Descriptor + Trailer
    header = b"GIF89a" + struct.pack("<HHBBB", screen_w, screen_h, 0x80, 0, 0) + (b"\x00" * 6)
    ext = b"\x21\xfe\x02hi\x00"
    img = b"\x2c" + struct.pack("<HHHHB", 0, 0, frame_w, frame_h, 0x00) + b"\x02\x01\x00\x00"
    return header + ext + img + b"\x3b"


def _make_webp_vp8l(width: int, height: int) -> bytes:
    bits = ((width - 1) & 0x3FFF) | (((height - 1) & 0x3FFF) << 14)
    return b"RIFF\x00\x00\x00\x00WEBPVP8L\x00\x00\x00\x00\x2f" + struct.pack("<I", bits)


def _make_webp_vp8x(width: int, height: int) -> bytes:
    return (
        b"RIFF\x00\x00\x00\x00WEBPVP8X\x00\x00\x00\x00\x00\x00\x00\x00"
        + (width - 1).to_bytes(3, "little")
        + (height - 1).to_bytes(3, "little")
    )


def _make_webp_vp8(width: int, height: int) -> bytes:
    return b"RIFF\x00\x00\x00\x00WEBPVP8 \x00\x00\x00\x00\x00\x00\x00\x9d\x01\x2a" + struct.pack("<HH", width, height)


def test_magic_byte_sniffing_html_svg_and_multibyte_boundaries() -> None:
    assert detect_mime_from_bytes(b"") is None
    assert detect_mime_from_bytes(make_demo_png(8, 8)) == "image/png"
    assert detect_mime_from_bytes(_make_minimal_jpeg(16, 12)) == "image/jpeg"
    assert detect_mime_from_bytes(_make_minimal_gif(10, 10, 20, 20)) == "image/gif"
    assert detect_mime_from_bytes(_make_webp_vp8l(16, 16)) == "image/webp"
    assert detect_mime_from_bytes(b"%PDF-1.7\n") == "application/pdf"
    assert detect_mime_from_bytes(b"PK\x03\x04zipdata") == "application/zip"
    assert detect_mime_from_bytes(b"\x1f\x8bgzipdata") == "application/gzip"
    assert detect_mime_from_bytes(b"abc\x00def") is None
    assert detect_mime_from_bytes(b"\xff\xfe\xfd") is None

    # Split 3-byte UTF-8 character across the 4096-byte sniff boundary still decodes cleanly
    boundary_payload = (b"a" * 4095) + "€".encode() + b"tail"
    assert detect_mime_from_bytes(boundary_payload, "report.txt") == "text/plain"
    assert detect_mime_from_bytes(b'{"ok":true}', "data.json") == "application/json"
    assert detect_mime_from_bytes(b'{"ok":true}') == "application/json"
    assert detect_mime_from_bytes(b"a,b\n1,2\n", "items.csv") == "text/csv"
    assert detect_mime_from_bytes(b"plain text") == "text/plain"

    # Active HTML/script blocked; SVG detected even behind BOM + XML comments
    assert detect_mime_from_bytes(b"<!-- c --><script>alert(1)</script>") is None
    assert detect_mime_from_bytes(b"\xef\xbb\xbf<!-- comment --><svg xmlns='x'></svg>") == "image/svg+xml"


def test_image_dimension_parsers_and_decompression_bomb_rejection() -> None:
    assert parse_image_dimensions(make_demo_png(32, 16), "image/png") == (32, 16)
    assert parse_image_dimensions(_make_minimal_jpeg(640, 480), "image/jpeg") == (640, 480)
    # Multi-frame GIF reports max across logical screen & image descriptors
    assert parse_image_dimensions(_make_minimal_gif(10, 10, 400, 300), "image/gif") == (400, 300)
    assert parse_image_dimensions(b"GIF89a", "image/gif") is None
    assert parse_image_dimensions(_make_webp_vp8l(120, 80), "image/webp") == (120, 80)
    assert parse_image_dimensions(_make_webp_vp8x(240, 160), "image/webp") == (240, 160)
    assert parse_image_dimensions(_make_webp_vp8(320, 200), "image/webp") == (320, 200)
    assert parse_image_dimensions(b"\xff\xd8\x00\x00\x00\x00", "image/jpeg") is None

    storage = MemoryFileStorage()
    cfg = FileFieldConfig(storage=storage, kind="image", max_bytes=1024, max_image_pixels=10_000)

    with pytest.raises(ValueError, match="empty"):
        validate_and_read_upload(io.BytesIO(b""), filename="a.png", config=cfg, default_max_bytes=1024)
    with pytest.raises(ValueError, match="exceeds maximum"):
        validate_and_read_upload(io.BytesIO(b"x" * 2048), filename="a.png", config=cfg, default_max_bytes=1024)
    with pytest.raises(ValueError, match="SVG uploads are disabled"):
        validate_and_read_upload(io.BytesIO(b"<svg></svg>"), filename="x.svg", config=cfg, default_max_bytes=1024)
    with pytest.raises(ValueError, match="Malformed"):
        validate_and_read_upload(io.BytesIO(b"\x89PNG\r\n\x1a\nshort"), filename="bad.png", config=cfg, default_max_bytes=1024)
    with pytest.raises(ValueError, match="exceed safety limit"):
        validate_and_read_upload(io.BytesIO(_make_minimal_jpeg(500, 500)), filename="bomb.jpg", config=cfg, default_max_bytes=4096)

    svg_cfg = FileFieldConfig(storage=storage, kind="image", allow_svg=True)
    stored = store_validated_upload(io.BytesIO(b"<svg></svg>"), filename="../evil/logo.svg", config=svg_cfg, default_max_bytes=4096)
    assert stored.content_type == "image/svg+xml" and stored.filename == "logo.svg"


def test_local_memory_and_s3_storage_backends(tmp_path: Path) -> None:
    # 1. LocalFileStorage atomic writes, streaming, traversal protection, symlink escape
    local = LocalFileStorage(tmp_path / "vault")
    png = make_demo_png(16, 16)
    saved = save_stream_to_storage(local, io.BytesIO(png), key="docs/a.png", content_type="image/png")
    assert saved.size_bytes == len(png)
    assert local.exists("docs/a.png") is True
    assert local.exists("../etc/passwd") is False
    assert local.presigned_url("docs/a.png") is None

    chunks, mime = stream_storage_object(local, "docs/a.png", chunk_size=1024)
    assert b"".join(chunks) == png and mime == "image/png"
    with pytest.raises(FileNotFoundError):
        local.open_stream("docs/missing.png")
    local.delete("../escape")  # no-op on invalid key
    local.delete("docs/a.png")
    assert local.exists("docs/a.png") is False

    # Symlink escaping root directory is rejected
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    escape_link = local.root_dir / "escape.txt"
    escape_link.symlink_to(outside)
    with pytest.raises(ValueError, match="escapes root"):
        local.open("escape.txt")

    # 2. MemoryFileStorage stream & missing-key behavior
    mem = MemoryFileStorage()
    mem.save(b"hello-world", key="k/1.txt", content_type="text/plain")
    m_iter, m_ct = stream_storage_object(mem, "k/1.txt", chunk_size=1024)
    assert b"".join(m_iter) == b"hello-world" and m_ct == "text/plain"
    with pytest.raises(FileNotFoundError):
        mem.open("k/missing.txt")
    with pytest.raises(FileNotFoundError):
        mem.open_stream("k/missing.txt")
    mem.delete("../bad")
    assert mem.exists("../bad") is False

    # 3. Fallback _ClosingChunkIterator for minimal custom StorageBackend without open_stream/save_stream
    class _MinimalStorage:
        def __init__(self) -> None:
            self.data: dict[str, bytes] = {}

        def save(self, data: bytes, *, key: str, content_type: str) -> Any:
            self.data[key] = data
            return MemoryFileStorage().save(data, key=key, content_type=content_type)

        def open(self, key: str) -> tuple[Any, str | None]:
            return io.BytesIO(self.data[key]), "application/octet-stream"

        def delete(self, key: str) -> None:
            self.data.pop(key, None)

        def exists(self, key: str) -> bool:
            return key in self.data

        def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
            return None

    minimal = _MinimalStorage()
    save_stream_to_storage(minimal, io.BytesIO(b"streamed-bytes"), key="m/f.bin", content_type="application/octet-stream")
    c_iter, c_mime = stream_storage_object(minimal, "m/f.bin", chunk_size=4)
    assert b"".join(c_iter) == b"streamed-bytes" and c_mime == "application/octet-stream"

    # 4. S3StorageBackend with injected fake boto3 client
    with pytest.raises(ValueError, match="non-empty bucket"):
        S3StorageBackend("   ")

    class _FakeBody:
        def __init__(self, raw: bytes, *, with_iter_chunks: bool = True) -> None:
            self._buf = io.BytesIO(raw)
            self.closed = False
            if with_iter_chunks:
                self.iter_chunks = self._iter_chunks  # type: ignore[method-assign]

        def _iter_chunks(self, chunk_size: int = 1024) -> Any:
            while True:
                b = self._buf.read(chunk_size)
                if not b:
                    break
                yield b

        def read(self, size: int = -1) -> bytes:
            return self._buf.read(size)

        def close(self) -> None:
            self.closed = True

    class _FakeS3Error(Exception):
        def __init__(self, code: str, status: int) -> None:
            super().__init__(code)
            self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}

    class _FakeS3Client:
        def __init__(self) -> None:
            self.objects: dict[tuple[str, str], tuple[bytes, str, str | None]] = {}
            self.use_iter_chunks = True

        def put_object(self, **kw: Any) -> None:
            self.objects[(kw["Bucket"], kw["Key"])] = (
                kw["Body"],
                kw["ContentType"],
                kw.get("ContentDisposition"),
            )

        def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if (Bucket, Key) not in self.objects:
                raise _FakeS3Error("NoSuchKey", 404)
            raw, ct, _ = self.objects[(Bucket, Key)]
            return {"Body": _FakeBody(raw, with_iter_chunks=self.use_iter_chunks), "ContentType": ct}

        def delete_object(self, *, Bucket: str, Key: str) -> None:
            self.objects.pop((Bucket, Key), None)

        def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if (Bucket, Key) not in self.objects:
                raise _FakeS3Error("404", 404)
            return {}

        def generate_presigned_url(self, op: str, *, Params: dict[str, Any], ExpiresIn: int) -> str:
            disp = Params.get("ResponseContentDisposition", "inline")
            return f"https://s3.local/{Params['Bucket']}/{Params['Key']}?exp={ExpiresIn}&disp={disp}"

    s3_client = _FakeS3Client()
    s3 = S3StorageBackend("acme-bucket", prefix="media", client=s3_client)
    s3.save(b"%PDF-1.4", key="specs/a.pdf", content_type="application/pdf")
    assert s3_client.objects[("acme-bucket", "media/specs/a.pdf")][2] == "attachment"
    assert s3.exists("specs/a.pdf") is True
    assert s3.exists("../bad") is False

    fh, ct = s3.open("specs/a.pdf")
    assert fh.read() == b"%PDF-1.4" and ct == "application/pdf"
    fh.close()

    it1, _ = s3.open_stream("specs/a.pdf", chunk_size=1024)
    assert b"".join(it1) == b"%PDF-1.4"
    s3_client.use_iter_chunks = False
    it2, _ = s3.open_stream("specs/a.pdf", chunk_size=1024)
    assert b"".join(it2) == b"%PDF-1.4"

    url = s3.presigned_url("specs/a.pdf", expires_in=99999)
    assert url is not None and "exp=3600" in url and "disp=attachment" in url
    with pytest.raises(FileNotFoundError):
        s3.open("specs/missing.pdf")

    s3.delete("../bad")
    s3.delete("specs/a.pdf")
    assert s3.exists("specs/a.pdf") is False
