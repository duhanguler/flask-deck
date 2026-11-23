from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import struct
import tempfile
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Literal, Protocol, runtime_checkable

DEFAULT_IMAGE_MIMES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/webp", "image/gif"}
)
DEFAULT_FILE_MIMES: frozenset[str] = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "application/pdf",
        "text/plain",
        "text/csv",
        "application/json",
        "application/zip",
        "application/gzip",
    }
)
RASTER_INLINE_MIMES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/webp", "image/gif"}
)

_MIME_TO_EXT: dict[str, str] = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "application/pdf": "pdf",
    "text/plain": "txt",
    "text/csv": "csv",
    "application/json": "json",
    "application/zip": "zip",
    "application/gzip": "gz",
}

_PREFIX_SAFE_RE = re.compile(r"[^a-zA-Z0-9/_-]+")


@dataclass(frozen=True, slots=True)
class StoredFile:
    """Immutable metadata returned after storing an uploaded artifact."""

    key: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    width: int | None = None
    height: int | None = None


@runtime_checkable
class _ReadableBytes(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@runtime_checkable
class StorageBackend(Protocol):
    """Storage-agnostic contract implemented by Local, S3/R2, and Memory backends."""

    def save(self, data: bytes, *, key: str, content_type: str) -> StoredFile:
        """Persist validated bytes at opaque key."""

    def open(self, key: str) -> tuple[BinaryIO, str | None]:
        """Return (readable binary stream, optional content_type) for key."""

    def delete(self, key: str) -> None:
        """Delete object if present (idempotent)."""

    def exists(self, key: str) -> bool:
        """Return True if key exists in storage."""

    def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
        """Optionally return a short-lived signed URL (None for private proxy-only backends)."""


@dataclass(frozen=True, slots=True)
class FileFieldConfig:
    """Declarative configuration for one file or image upload column on a ModelView."""

    storage: StorageBackend
    kind: Literal["file", "image"] = "file"
    allowed_mimes: frozenset[str] = field(default_factory=frozenset)
    max_bytes: int | None = None
    max_image_pixels: int = 25_000_000  # 25 MP decompression-bomb cap
    prefix: str = "uploads"
    delete_orphan: bool = False
    allow_svg: bool = False
    use_presigned_redirect: bool = False
    presign_ttl: int = 300

    def resolved_allowed_mimes(self) -> frozenset[str]:
        base = self.allowed_mimes or (
            DEFAULT_IMAGE_MIMES if self.kind == "image" else DEFAULT_FILE_MIMES
        )
        if not self.allow_svg:
            return base - {"image/svg+xml"}
        return base | {"image/svg+xml"}


def sanitize_filename(filename: str) -> str:
    """Extract a clean basename without path separators or control characters."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in base if 32 <= ord(ch) < 127 and ch not in {'"', "'", "<", ">"})
    cleaned = cleaned.strip().lstrip(".")
    return cleaned[:120] or "file"


def build_storage_key(prefix: str, mime: str) -> str:
    """Build a collision-free opaque storage key never trusting user filenames."""
    clean_prefix = _PREFIX_SAFE_RE.sub("", prefix.strip("/")) or "uploads"
    now = datetime.now(timezone.utc)
    ext = _MIME_TO_EXT.get(mime, "bin")
    return f"{clean_prefix}/{now.year:04d}/{now.month:02d}/{uuid.uuid4().hex}.{ext}"


_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_ACTIVE_TAG_RE = re.compile(
    r"<\s*(?:!doctype\s+html|html|script|iframe|object|embed|body|head|meta|link|style|img|form)\b",
    re.IGNORECASE,
)


def _decode_utf8_prefix(data: bytes, limit: int = 4096) -> str | None:
    """Decode up to ``limit`` bytes of UTF-8 without failing on a split trailing multibyte char."""
    chunk = data[:limit]
    if len(data) > limit:
        # Trim up to 3 trailing UTF-8 continuation/incomplete lead bytes at the slice boundary
        for trim in range(4):
            sub = chunk[: len(chunk) - trim] if trim else chunk
            try:
                return sub.decode("utf-8")
            except UnicodeDecodeError:
                continue
        return None
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        return None


def detect_mime_from_bytes(data: bytes, filename: str = "") -> str | None:
    """Pure-Python magic-byte MIME sniffer (zero libmagic dependency)."""
    if not data:
        return None
    head = data[:64]

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "application/zip"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"

    # Reject binary blobs with NUL bytes before checking text/SVG/JSON/CSV
    if b"\x00" in data[:4096]:
        return None

    sample = _decode_utf8_prefix(data, 4096)
    if sample is None:
        return None

    # Strip UTF-8 BOM, leading whitespace, and XML comments before checking SVG / HTML payloads
    stripped = sample.lstrip("\ufeff \t\r\n")
    no_comments = _XML_COMMENT_RE.sub("", stripped).lstrip()
    lower = no_comments.lower()
    if (
        lower.startswith("<svg")
        or lower.startswith("<!doctype svg")
        or (lower.startswith("<?xml") and "<svg" in lower[:2048])
        or "<svg" in lower[:512]
    ):
        return "image/svg+xml"
    if _HTML_ACTIVE_TAG_RE.search(no_comments[:1024]):
        # Never classify HTML/script payloads as safe text or image uploads.
        return None

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if stripped.startswith(("{", "[")) and ext == "json":
        return "application/json"
    if ext == "csv":
        return "text/csv"
    if ext == "txt":
        return "text/plain"
    if stripped.startswith(("{", "[")):
        return "application/json"
    return "text/plain"


def _parse_gif_max_dimensions(data: bytes) -> tuple[int, int] | None:
    """Return max (width, height) across the GIF logical screen and all 0x2C image descriptors."""
    if len(data) < 13:
        return None
    max_w, max_h = struct.unpack("<HH", data[6:10])
    packed = data[10]
    idx = 13
    if packed & 0x80:
        gct_size = 3 * (1 << ((packed & 0x07) + 1))
        idx += gct_size
    n = len(data)
    while idx < n:
        block = data[idx]
        idx += 1
        if block == 0x3B:  # Trailer
            break
        if block == 0x2C:  # Image Descriptor
            if idx + 9 > n:
                break
            _left, _top, fw, fh, ipacked = struct.unpack("<HHHHB", data[idx : idx + 9])
            max_w = max(max_w, fw)
            max_h = max(max_h, fh)
            idx += 9
            if ipacked & 0x80:
                idx += 3 * (1 << ((ipacked & 0x07) + 1))
            if idx >= n:
                break
            idx += 1  # LZW minimum code size
            while idx < n:
                sub_len = data[idx]
                idx += 1
                if sub_len == 0:
                    break
                idx += sub_len
        elif block == 0x21:  # Extension
            if idx >= n:
                break
            idx += 1  # Extension label
            while idx < n:
                sub_len = data[idx]
                idx += 1
                if sub_len == 0:
                    break
                idx += sub_len
        else:
            break
    return int(max_w), int(max_h)


def parse_image_dimensions(data: bytes, mime: str) -> tuple[int, int] | None:
    """Parse image (width, height) directly from binary headers to stop decompression bombs."""
    try:
        if mime == "image/png" and len(data) >= 24 and data[12:16] == b"IHDR":
            w, h = struct.unpack(">II", data[16:24])
            return int(w), int(h)
        if mime == "image/gif" and len(data) >= 10:
            return _parse_gif_max_dimensions(data)
        if mime == "image/webp" and len(data) >= 25:
            chunk = data[12:16]
            if chunk == b"VP8L" and data[20] == 0x2F:
                bits = struct.unpack("<I", data[21:25])[0]
                return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
            if chunk == b"VP8X" and len(data) >= 30:
                w = 1 + int.from_bytes(data[24:27], "little")
                h = 1 + int.from_bytes(data[27:30], "little")
                return w, h
            if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
                w = struct.unpack("<H", data[26:28])[0] & 0x3FFF
                h = struct.unpack("<H", data[28:30])[0] & 0x3FFF
                return int(w), int(h)
        if mime == "image/jpeg" and len(data) >= 4:
            idx = 2
            length = len(data)
            while idx + 4 < length:
                if data[idx] != 0xFF:
                    break
                while idx < length and data[idx] == 0xFF:
                    idx += 1
                if idx >= length:
                    break
                marker = data[idx]
                idx += 1
                if marker in {0xD8, 0xD9, 0x01} or (0xD0 <= marker <= 0xD7):
                    continue
                if idx + 2 > length:
                    break
                seg_len = struct.unpack(">H", data[idx : idx + 2])[0]
                if seg_len < 2 or idx + seg_len > length:
                    break
                if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB}:
                    if idx + 7 <= length:
                        h, w = struct.unpack(">HH", data[idx + 3 : idx + 7])
                        return int(w), int(h)
                    break
                idx += seg_len
    except (struct.error, ValueError, IndexError):
        return None
    return None


def validate_and_read_upload(
    stream: BinaryIO,
    *,
    filename: str,
    config: FileFieldConfig,
    default_max_bytes: int,
) -> tuple[bytes, str, int | None, int | None]:
    """Read upload with strict byte ceiling, magic-byte MIME sniff, and pixel bomb check."""
    limit = config.max_bytes if config.max_bytes is not None else default_max_bytes
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            mb = limit / (1024 * 1024)
            raise ValueError(f"File exceeds maximum allowed size ({mb:.1f} MiB).")
        chunks.append(chunk)

    data = b"".join(chunks)
    if not data:
        raise ValueError("Uploaded file is empty.")

    detected = detect_mime_from_bytes(data, filename)
    allowed = config.resolved_allowed_mimes()
    if detected is None or detected not in allowed:
        if detected == "image/svg+xml" and not config.allow_svg:
            raise ValueError("SVG uploads are disabled by security policy.")
        raise ValueError(
            f"Unsupported or disallowed file content ({detected or 'unknown'})."
        )

    width: int | None = None
    height: int | None = None
    if detected in RASTER_INLINE_MIMES:
        dims = parse_image_dimensions(data, detected)
        if dims is None:
            raise ValueError("Malformed or unreadable image header.")
        width, height = dims
        if width <= 0 or height <= 0 or (width * height) > config.max_image_pixels:
            raise ValueError(
                f"Image dimensions ({width}x{height}) exceed safety limit "
                f"({config.max_image_pixels:,} pixels)."
            )

    return data, detected, width, height


def store_validated_upload(
    stream: BinaryIO,
    *,
    filename: str,
    config: FileFieldConfig,
    default_max_bytes: int,
) -> StoredFile:
    """Validate an uploaded file stream and persist it cleanly to config.storage."""
    data, mime, width, height = validate_and_read_upload(
        stream,
        filename=filename,
        config=config,
        default_max_bytes=default_max_bytes,
    )
    key = build_storage_key(config.prefix, mime)
    stored = config.storage.save(data, key=key, content_type=mime)
    return StoredFile(
        key=stored.key,
        filename=sanitize_filename(filename),
        content_type=mime,
        size_bytes=len(data),
        sha256=stored.sha256,
        width=width,
        height=height,
    )


def _validate_opaque_key(key: str) -> str:
    clean = key.strip().lstrip("/")
    if not clean or "\\" in clean or "\x00" in clean:
        raise ValueError("Invalid storage key")
    parts = clean.split("/")
    if any(p in {"", ".", ".."} for p in parts):
        raise ValueError("Invalid storage key")
    return clean


class LocalFileStorage:
    """Path-traversal-proof local filesystem storage backend with atomic writes."""

    __slots__ = ("root_dir",)

    def __init__(self, root_dir: str | Path) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_path(self, key: str) -> Path:
        clean = _validate_opaque_key(key)
        candidate = (self.root_dir / clean).resolve()
        if candidate == self.root_dir or not candidate.is_relative_to(self.root_dir):
            raise ValueError("Storage key escapes root directory")
        return candidate

    def save(self, data: bytes, *, key: str, content_type: str) -> StoredFile:
        target = self._resolve_path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()
        fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".dk_tmp_")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp_name, target)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        return StoredFile(
            key=_validate_opaque_key(key),
            filename=target.name,
            content_type=content_type,
            size_bytes=len(data),
            sha256=digest,
        )

    def open(self, key: str) -> tuple[BinaryIO, str | None]:
        target = self._resolve_path(key)
        if not target.is_file():
            raise FileNotFoundError(key)
        fh: BinaryIO = target.open("rb")
        head = fh.read(4096)
        fh.seek(0)
        return fh, detect_mime_from_bytes(head, target.name)

    def open_stream(
        self, key: str, *, chunk_size: int = 65536
    ) -> tuple[Iterator[bytes], str | None]:
        target = self._resolve_path(key)
        if not target.is_file():
            raise FileNotFoundError(key)
        with target.open("rb") as probe:
            head = probe.read(4096)
        mime = detect_mime_from_bytes(head, target.name)
        size = max(1024, int(chunk_size))

        def _gen() -> Iterator[bytes]:
            with target.open("rb") as fh:
                while True:
                    buf = fh.read(size)
                    if not buf:
                        break
                    yield buf

        return _gen(), mime

    def save_stream(
        self, stream: _ReadableBytes, *, key: str, content_type: str
    ) -> StoredFile:
        target = self._resolve_path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        total = 0
        fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".dk_tmp_")
        try:
            with os.fdopen(fd, "wb") as fh:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    total += len(chunk)
                    fh.write(chunk)
            os.replace(tmp_name, target)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        return StoredFile(
            key=_validate_opaque_key(key),
            filename=target.name,
            content_type=content_type,
            size_bytes=total,
            sha256=hasher.hexdigest(),
        )

    def delete(self, key: str) -> None:
        try:
            target = self._resolve_path(key)
        except ValueError:
            return
        if target.is_file():
            target.unlink(missing_ok=True)

    def exists(self, key: str) -> bool:
        try:
            return self._resolve_path(key).is_file()
        except ValueError:
            return False

    def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
        _ = (key, expires_in)
        return None


class MemoryFileStorage:
    """Thread-safe in-memory storage backend ideal for demos and test suites."""

    __slots__ = ("_entries", "_lock")

    def __init__(self) -> None:
        self._entries: dict[str, tuple[bytes, str]] = {}
        self._lock = threading.Lock()

    def save(self, data: bytes, *, key: str, content_type: str) -> StoredFile:
        clean = _validate_opaque_key(key)
        digest = hashlib.sha256(data).hexdigest()
        with self._lock:
            self._entries[clean] = (bytes(data), content_type)
        return StoredFile(
            key=clean,
            filename=clean.rsplit("/", 1)[-1],
            content_type=content_type,
            size_bytes=len(data),
            sha256=digest,
        )

    def open(self, key: str) -> tuple[BinaryIO, str | None]:
        clean = _validate_opaque_key(key)
        with self._lock:
            entry = self._entries.get(clean)
        if entry is None:
            raise FileNotFoundError(key)
        payload, ctype = entry
        return io.BytesIO(payload), ctype

    def open_stream(
        self, key: str, *, chunk_size: int = 65536
    ) -> tuple[Iterator[bytes], str | None]:
        clean = _validate_opaque_key(key)
        with self._lock:
            entry = self._entries.get(clean)
        if entry is None:
            raise FileNotFoundError(key)
        payload, ctype = entry
        size = max(1024, int(chunk_size))

        def _gen() -> Iterator[bytes]:
            for pos in range(0, len(payload), size):
                yield payload[pos : pos + size]

        return _gen(), ctype

    def delete(self, key: str) -> None:
        try:
            clean = _validate_opaque_key(key)
        except ValueError:
            return
        with self._lock:
            self._entries.pop(clean, None)

    def exists(self, key: str) -> bool:
        try:
            clean = _validate_opaque_key(key)
        except ValueError:
            return False
        with self._lock:
            return clean in self._entries

    def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
        _ = (key, expires_in)
        return None


class S3StorageBackend:
    """AWS S3 / Cloudflare R2 / MinIO storage backend (lazy optional boto3 or injected client)."""

    __slots__ = ("_bucket", "_client", "_endpoint_url", "_prefix", "_presign_ttl", "_region_name")

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "",
        client: Any | None = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        presign_ttl: int = 300,
    ) -> None:
        if not bucket.strip():
            raise ValueError("S3StorageBackend requires a non-empty bucket name")
        self._bucket = bucket.strip()
        self._prefix = prefix.strip("/")
        self._client = client
        self._endpoint_url = endpoint_url
        self._region_name = region_name
        self._presign_ttl = max(30, int(presign_ttl))

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "boto3 is required for S3StorageBackend. Install with: pip install 'flask-deck[s3]'"
                ) from exc
            self._client = boto3.client(
                "s3",
                endpoint_url=self._endpoint_url,
                region_name=self._region_name,
            )
        return self._client

    def _full_key(self, key: str) -> str:
        clean = _validate_opaque_key(key)
        return f"{self._prefix}/{clean}" if self._prefix else clean

    def save(self, data: bytes, *, key: str, content_type: str) -> StoredFile:
        clean = _validate_opaque_key(key)
        full = self._full_key(clean)
        digest = hashlib.sha256(data).hexdigest()
        put_kwargs: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": full,
            "Body": data,
            "ContentType": content_type,
        }
        if content_type not in RASTER_INLINE_MIMES:
            put_kwargs["ContentDisposition"] = "attachment"
        self._get_client().put_object(**put_kwargs)
        return StoredFile(
            key=clean,
            filename=clean.rsplit("/", 1)[-1],
            content_type=content_type,
            size_bytes=len(data),
            sha256=digest,
        )

    def _get_s3_object(self, key: str) -> tuple[Any, str | None]:
        full = self._full_key(key)
        try:
            resp = self._get_client().get_object(Bucket=self._bucket, Key=full)
        except FileNotFoundError:
            raise
        except Exception as exc:
            err_resp = getattr(exc, "response", None)
            if isinstance(err_resp, dict):
                code = str(err_resp.get("Error", {}).get("Code", ""))
                status = err_resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
                if code in {"NoSuchKey", "404", "NotFound"} or status == 404:
                    raise FileNotFoundError(key) from exc
            raise
        ctype_raw = resp.get("ContentType")
        return resp["Body"], str(ctype_raw) if isinstance(ctype_raw, str) else None

    def open(self, key: str) -> tuple[BinaryIO, str | None]:
        body, ctype = self._get_s3_object(key)
        try:
            raw: bytes = body.read()
        finally:
            if hasattr(body, "close"):
                body.close()
        return io.BytesIO(raw), ctype

    def open_stream(
        self, key: str, *, chunk_size: int = 65536
    ) -> tuple[Iterator[bytes], str | None]:
        body, ctype = self._get_s3_object(key)
        size = max(1024, int(chunk_size))

        def _gen() -> Iterator[bytes]:
            try:
                if hasattr(body, "iter_chunks"):
                    yield from body.iter_chunks(chunk_size=size)
                else:
                    while True:
                        chunk = body.read(size)
                        if not chunk:
                            break
                        yield chunk
            finally:
                if hasattr(body, "close"):
                    body.close()

        return _gen(), ctype

    def delete(self, key: str) -> None:
        try:
            full = self._full_key(key)
        except ValueError:
            return
        self._get_client().delete_object(Bucket=self._bucket, Key=full)

    def exists(self, key: str) -> bool:
        try:
            full = self._full_key(key)
        except ValueError:
            return False
        try:
            self._get_client().head_object(Bucket=self._bucket, Key=full)
            return True
        except Exception:
            return False

    def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
        full = self._full_key(key)
        ttl = max(30, min(int(expires_in or self._presign_ttl), 3600))
        params: dict[str, Any] = {"Bucket": self._bucket, "Key": full}
        if not full.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
            params["ResponseContentDisposition"] = "attachment"
        url = self._get_client().generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=ttl,
        )
        return str(url) if url else None


class _ClosingChunkIterator:
    """Wrap an already-open BinaryIO in a chunk iterator that always closes on exhaustion/close/GC."""

    __slots__ = ("_chunk_size", "_fh")

    def __init__(self, fh: BinaryIO, chunk_size: int) -> None:
        self._fh = fh
        self._chunk_size = max(1024, int(chunk_size))

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        if getattr(self._fh, "closed", False):
            raise StopIteration
        buf = self._fh.read(self._chunk_size)
        if not buf:
            self.close()
            raise StopIteration
        return buf

    def close(self) -> None:
        if not getattr(self._fh, "closed", False):
            self._fh.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()


def stream_storage_object(
    storage: StorageBackend, key: str, *, chunk_size: int = 65536
) -> tuple[Iterator[bytes], str | None]:
    """Stream object bytes in bounded chunks while guaranteeing handle closure."""
    stream_fn = getattr(storage, "open_stream", None)
    if callable(stream_fn):
        return stream_fn(key, chunk_size=chunk_size)  # type: ignore[no-any-return]
    fh, detected = storage.open(key)
    return _ClosingChunkIterator(fh, chunk_size), detected


def save_stream_to_storage(
    storage: StorageBackend, stream: _ReadableBytes, *, key: str, content_type: str
) -> StoredFile:
    """Persist a readable binary stream without buffering LocalFileStorage in RAM."""
    save_fn = getattr(storage, "save_stream", None)
    if callable(save_fn):
        return save_fn(stream, key=key, content_type=content_type)  # type: ignore[no-any-return]
    data = stream.read()
    return storage.save(data, key=key, content_type=content_type)


def make_demo_png(
    width: int = 64,
    height: int = 64,
    *,
    bg: tuple[int, int, int] = (24, 24, 27),
    fg: tuple[int, int, int] = (244, 244, 245),
    accent: tuple[int, int, int] = (74, 222, 128),
) -> bytes:
    """Synthesize a crisp valid PNG thumbnail in pure Python stdlib (zero Pillow needed)."""
    import zlib

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)  # filter byte None
        for x in range(width):
            border = x in {0, width - 1} or y in {0, height - 1}
            diag = abs((x - width // 2) + (y - height // 2)) <= 3
            bar = (height - 14 <= y <= height - 10) and (10 <= x <= width - 10)
            dot = ((x - 14) ** 2 + (y - 14) ** 2) <= 20
            if border:
                r, g_c, b = (50, 50, 61)
            elif dot:
                r, g_c, b = accent
            elif bar or diag:
                r, g_c, b = fg
            else:
                r, g_c, b = bg
            raw_rows.extend((r, g_c, b))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )
