from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import sqlalchemy as sa
from markupsafe import Markup
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

MFA_PENDING_USER_KEY = "_deck_mfa_pending_user"
MFA_PENDING_NEXT_KEY = "_deck_mfa_pending_next"
MFA_PENDING_AT_KEY = "_deck_mfa_pending_at"
MFA_PENDING_SSO_KEY = "_deck_mfa_pending_sso"
MFA_VERIFIED_KEY = "_deck_mfa_verified"


@dataclass(frozen=True, slots=True)
class MFAEnrollment:
    """Persisted TOTP enrollment record for one DeckUser."""

    user_id: str
    secret: str
    enabled: bool = True
    last_step: int | None = None
    recovery_hashes: tuple[str, ...] = ()
    created_at: datetime | None = None


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generate a 160-bit RFC 6238 Base32 secret (unpadded)."""
    return base64.b32encode(secrets.token_bytes(max(16, num_bytes))).decode("ascii").rstrip("=")


def _decode_base32(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    pad = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + pad, casefold=True)


def compute_totp(
    secret: str,
    *,
    timestamp: float | None = None,
    step_seconds: int = 30,
    digits: int = 6,
) -> str:
    """Compute an RFC 6238 HMAC-SHA1 TOTP code using Python stdlib only."""
    now = time.time() if timestamp is None else float(timestamp)
    counter = int(now // step_seconds)
    key = _decode_base32(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp(
    secret: str,
    candidate: str,
    *,
    timestamp: float | None = None,
    step_seconds: int = 30,
    digits: int = 6,
    window: int = 1,
    last_step: int | None = None,
) -> int | None:
    """Verify TOTP with replay prevention. Returns accepted time-step or None."""
    clean = candidate.strip().replace(" ", "").replace("-", "")
    if not clean.isdigit() or len(clean) != digits:
        return None
    now = time.time() if timestamp is None else float(timestamp)
    base_step = int(now // step_seconds)
    for delta in range(-window, window + 1):
        step = base_step + delta
        if step < 0:
            continue
        if last_step is not None and step <= last_step:
            continue
        expected = compute_totp(
            secret,
            timestamp=step * step_seconds,
            step_seconds=step_seconds,
            digits=digits,
        )
        if hmac.compare_digest(expected, clean):
            return step
    return None


def generate_recovery_codes(count: int = 8) -> tuple[list[str], tuple[str, ...]]:
    """Return (plaintext_codes_to_show_once, pbkdf2_hashed_codes_to_store)."""
    plain: list[str] = []
    hashed: list[str] = []
    for _ in range(max(4, count)):
        raw = secrets.token_hex(4).upper()
        code = f"{raw[:4]}-{raw[4:]}"
        plain.append(code)
        hashed.append(generate_password_hash(code, method="pbkdf2:sha256:200000"))
    return plain, tuple(hashed)


def build_otpauth_uri(
    *,
    secret: str,
    account_name: str,
    issuer: str = "Flask-Deck",
) -> str:
    """Build standard otpauth://totp URI compatible with Google/Apple/1Password Authenticators."""
    safe_issuer = issuer.strip()[:36] or "Flask-Deck"
    safe_account = account_name.strip()[:64] or "user"
    label = f"{quote(safe_issuer, safe='')}:{quote(safe_account, safe='')}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={quote(secret, safe='')}"
        f"&issuer={quote(safe_issuer, safe='')}"
        "&algorithm=SHA1&digits=6&period=30"
    )


# ---------------------------------------------------------------------------
# Pure-Python ISO/IEC 18004 QR Code Generator (Byte mode, ECC Level L, V1-V8)
# Zero external dependencies, zero inline style=, strict CSP safe SVG output.
# ---------------------------------------------------------------------------

# (version, size, total_data_cw, ec_per_block, blocks, alignment_centers)
_QR_SPECS: tuple[tuple[int, int, int, int, int, tuple[int, ...]], ...] = (
    (1, 21, 19, 7, 1, ()),
    (2, 25, 34, 10, 1, (6, 18)),
    (3, 29, 55, 15, 1, (6, 22)),
    (4, 33, 80, 20, 1, (6, 26)),
    (5, 37, 108, 26, 1, (6, 30)),
    (6, 41, 136, 18, 2, (6, 34)),
    (7, 45, 156, 20, 2, (6, 22, 38)),
    (8, 49, 194, 24, 2, (6, 24, 42)),
)

# Precomputed 15-bit format strings for ECC Level L (01) and masks 0..7
_QR_FORMAT_L: tuple[int, ...] = (
    0x77C4,
    0x72F3,
    0x7DAA,
    0x789D,
    0x662F,
    0x6318,
    0x6C41,
    0x6976,
)
_QR_VERSION_INFO: dict[int, int] = {7: 0x07C94, 8: 0x085BC}


def _gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1D
        b >>= 1
    return res


def _rs_generator(degree: int) -> list[int]:
    poly = [1]
    root = 1
    for _ in range(degree):
        nxt = [0] * (len(poly) + 1)
        for i, coeff in enumerate(poly):
            nxt[i] ^= coeff
            nxt[i + 1] ^= _gf_mul(coeff, root)
        poly = nxt
        root = _gf_mul(root, 2)
    return poly


def _rs_remainder(data: list[int], ec_len: int) -> list[int]:
    gen = _rs_generator(ec_len)
    rem = [0] * ec_len
    for byte in data:
        factor = byte ^ rem[0]
        rem = [*rem[1:], 0]
        if factor != 0:
            for i in range(ec_len):
                rem[i] ^= _gf_mul(gen[i + 1], factor)
    return rem


def build_qr_matrix(text: str) -> list[list[bool]]:
    """Encode UTF-8 payload into a valid ISO/IEC 18004 QR boolean matrix (ECC-L, V1-V8)."""
    payload = text.encode("utf-8")
    spec = None
    for cand in _QR_SPECS:
        # 4-bit mode + 8-bit length = 2 bytes header overhead
        if len(payload) + 2 <= cand[2]:
            spec = cand
            break
    if spec is None:
        raise ValueError("Payload exceeds pure-Python QR V8 capacity (192 bytes)")

    ver, size, total_data_cw, ec_per_block, num_blocks, align_centers = spec

    # 1. Build bit stream: Byte mode (0100) + 8-bit length + payload + terminator + pad bytes
    bits: list[int] = [0, 1, 0, 0]
    for shift in range(7, -1, -1):
        bits.append((len(payload) >> shift) & 1)
    for b in payload:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)

    total_bits = total_data_cw * 8
    term_len = min(4, total_bits - len(bits))
    bits.extend([0] * term_len)
    while len(bits) % 8 != 0:
        bits.append(0)

    data_cw: list[int] = []
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i : i + 8]:
            val = (val << 1) | bit
        data_cw.append(val)

    pad_bytes = (0xEC, 0x11)
    pad_idx = 0
    while len(data_cw) < total_data_cw:
        data_cw.append(pad_bytes[pad_idx % 2])
        pad_idx += 1

    # 2. Split into blocks, compute Reed-Solomon EC, interleave codewords
    block_size = total_data_cw // num_blocks
    data_blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    pos = 0
    for _ in range(num_blocks):
        blk = data_cw[pos : pos + block_size]
        pos += block_size
        data_blocks.append(blk)
        ec_blocks.append(_rs_remainder(blk, ec_per_block))

    interleaved: list[int] = []
    for i in range(block_size):
        for blk in data_blocks:
            interleaved.append(blk[i])
    for i in range(ec_per_block):
        for ec in ec_blocks:
            interleaved.append(ec[i])

    code_bits: list[int] = []
    for cw in interleaved:
        for shift in range(7, -1, -1):
            code_bits.append((cw >> shift) & 1)

    # 3. Initialize module grid + function pattern reservation mask
    grid: list[list[bool]] = [[False] * size for _ in range(size)]
    is_func: list[list[bool]] = [[False] * size for _ in range(size)]

    def _set_func(r: int, c: int, val: bool) -> None:
        if 0 <= r < size and 0 <= c < size:
            grid[r][c] = val
            is_func[r][c] = True

    def _draw_finder(top: int, left: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = top + dr, left + dc
                if not (0 <= r < size and 0 <= c < size):
                    continue
                if dr in {-1, 7} or dc in {-1, 7}:
                    _set_func(r, c, False)
                else:
                    dark = dr in {0, 6} or dc in {0, 6} or (2 <= dr <= 4 and 2 <= dc <= 4)
                    _set_func(r, c, dark)

    _draw_finder(0, 0)
    _draw_finder(0, size - 7)
    _draw_finder(size - 7, 0)

    # Timing patterns
    for i in range(8, size - 8):
        _set_func(6, i, i % 2 == 0)
        _set_func(i, 6, i % 2 == 0)

    # Alignment patterns
    for r0 in align_centers:
        for c0 in align_centers:
            if is_func[r0][c0]:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    dark = max(abs(dr), abs(dc)) != 1
                    _set_func(r0 + dr, c0 + dc, dark)

    # Dark module + reserve format info areas
    _set_func(size - 8, 8, True)
    for i in range(9):
        if i != 6:
            is_func[8][i] = True
            is_func[i][8] = True
    for i in range(8):
        is_func[8][size - 1 - i] = True
        is_func[size - 1 - i][8] = True

    # Version info for V7+
    if ver in _QR_VERSION_INFO:
        vbits = _QR_VERSION_INFO[ver]
        for i in range(18):
            bit_val = bool((vbits >> i) & 1)
            a = size - 11 + (i % 3)
            b = i // 3
            _set_func(a, b, bit_val)
            _set_func(b, a, bit_val)

    # 4. Place data bits in upward/downward zigzag columns
    bit_idx = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for dc in (0, -1):
                c = col + dc
                if not is_func[row][c]:
                    grid[row][c] = bool(code_bits[bit_idx]) if bit_idx < len(code_bits) else False
                    bit_idx += 1
        upward = not upward
        col -= 2

    # 5. Apply mask 0 ((r + c) % 2 == 0) — deterministic & clean, write format bits
    mask_id = 0
    for r in range(size):
        for c in range(size):
            if not is_func[r][c] and (r + c) % 2 == 0:
                grid[r][c] = not grid[r][c]

    fmt = _QR_FORMAT_L[mask_id]
    # Place format bits around top-left and split bottom-left/top-right
    for i in range(6):
        bit_val = bool((fmt >> (14 - i)) & 1)
        grid[8][i] = bit_val
        grid[size - 1 - i][8] = bit_val
    grid[8][7] = bool((fmt >> 8) & 1)
    grid[8][8] = bool((fmt >> 7) & 1)
    grid[7][8] = bool((fmt >> 6) & 1)
    for i in range(6):
        grid[5 - i][8] = bool((fmt >> (5 - i)) & 1)
    grid[size - 7][8] = bool((fmt >> 8) & 1)
    for i in range(8):
        grid[8][size - 8 + i] = bool((fmt >> (7 - i)) & 1)

    return grid


def render_qr_svg(data: str, *, pixel_size: int = 184) -> Markup:
    """Render a scannable strict-CSP monochrome SVG QR code with a 4-module quiet zone."""
    matrix = build_qr_matrix(data)
    n = len(matrix)
    quiet = 4
    total = n + quiet * 2
    path_parts: list[str] = []
    for r, row in enumerate(matrix):
        y = r + quiet
        c = 0
        while c < n:
            if row[c]:
                start = c
                while c < n and row[c]:
                    c += 1
                width = c - start
                path_parts.append(f"M{start + quiet} {y}h{width}v1h-{width}z")
            else:
                c += 1
    d_attr = "".join(path_parts)
    safe_px = max(120, min(320, int(pixel_size)))
    return Markup(
        f'<svg class="dk-qr-svg" xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {total} {total}" width="{safe_px}" height="{safe_px}" '
        f'role="img" aria-label="Authenticator QR code" shape-rendering="crispEdges">'
        f'<rect width="{total}" height="{total}" fill="#ffffff"/>'
        f'<path d="{d_attr}" fill="#09090b"/>'
        "</svg>"
    )


# ---------------------------------------------------------------------------
# MFA Persistence Stores
# ---------------------------------------------------------------------------


class MFAStore(ABC):
    """Pluggable store persisting TOTP secrets, replay steps, and hashed recovery codes."""

    @abstractmethod
    def get(self, user_id: str) -> MFAEnrollment | None:
        """Return enrollment for user_id or None."""

    @abstractmethod
    def save(self, enrollment: MFAEnrollment) -> None:
        """Upsert enrollment record."""

    @abstractmethod
    def delete(self, user_id: str) -> None:
        """Remove enrollment (disable MFA)."""

    def verify_and_record(
        self,
        user_id: str,
        code: str,
        *,
        timestamp: float | None = None,
    ) -> bool:
        """Verify TOTP or single-use recovery code and update replay/consumption state."""
        enrollment = self.get(user_id)
        if enrollment is None or not enrollment.enabled:
            return False

        step = verify_totp(
            enrollment.secret,
            code,
            timestamp=timestamp,
            last_step=enrollment.last_step,
        )
        if step is not None:
            self.save(
                MFAEnrollment(
                    user_id=enrollment.user_id,
                    secret=enrollment.secret,
                    enabled=True,
                    last_step=step,
                    recovery_hashes=enrollment.recovery_hashes,
                    created_at=enrollment.created_at,
                )
            )
            return True

        # Check single-use recovery codes
        cleaned = code.strip().upper()
        for idx, hashed in enumerate(enrollment.recovery_hashes):
            if check_password_hash(hashed, cleaned):
                remaining = enrollment.recovery_hashes[:idx] + enrollment.recovery_hashes[idx + 1 :]
                self.save(
                    MFAEnrollment(
                        user_id=enrollment.user_id,
                        secret=enrollment.secret,
                        enabled=True,
                        last_step=enrollment.last_step,
                        recovery_hashes=remaining,
                        created_at=enrollment.created_at,
                    )
                )
                return True
        return False


class InMemoryMFAStore(MFAStore):
    """Thread-safe in-memory MFA store suitable for demos and tests."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, MFAEnrollment] = {}
        self._lock = threading.Lock()

    def get(self, user_id: str) -> MFAEnrollment | None:
        with self._lock:
            return self._records.get(user_id)

    def save(self, enrollment: MFAEnrollment) -> None:
        with self._lock:
            self._records[enrollment.user_id] = enrollment

    def delete(self, user_id: str) -> None:
        with self._lock:
            self._records.pop(user_id, None)

    def verify_and_record(
        self,
        user_id: str,
        code: str,
        *,
        timestamp: float | None = None,
    ) -> bool:
        """Atomically verify and record TOTP / recovery usage under the store lock."""
        with self._lock:
            enrollment = self._records.get(user_id)
            if enrollment is None or not enrollment.enabled:
                return False

            step = verify_totp(
                enrollment.secret,
                code,
                timestamp=timestamp,
                last_step=enrollment.last_step,
            )
            if step is not None:
                self._records[user_id] = MFAEnrollment(
                    user_id=enrollment.user_id,
                    secret=enrollment.secret,
                    enabled=True,
                    last_step=step,
                    recovery_hashes=enrollment.recovery_hashes,
                    created_at=enrollment.created_at,
                )
                return True

            cleaned = code.strip().upper()
            for idx, hashed in enumerate(enrollment.recovery_hashes):
                if check_password_hash(hashed, cleaned):
                    remaining = (
                        enrollment.recovery_hashes[:idx]
                        + enrollment.recovery_hashes[idx + 1 :]
                    )
                    self._records[user_id] = MFAEnrollment(
                        user_id=enrollment.user_id,
                        secret=enrollment.secret,
                        enabled=True,
                        last_step=enrollment.last_step,
                        recovery_hashes=remaining,
                        created_at=enrollment.created_at,
                    )
                    return True
            return False


class SQLAlchemyMFAStore(MFAStore):
    """Persistent SQLAlchemy 2.0 MFA enrollment store (auto-creates `_flask_deck_mfa`)."""

    __slots__ = ("_engine", "_table")

    def __init__(self, engine: Engine, *, table_name: str = "_flask_deck_mfa") -> None:
        self._engine = engine
        metadata = sa.MetaData()
        self._table = sa.Table(
            table_name,
            metadata,
            sa.Column("user_id", sa.String(128), primary_key=True),
            sa.Column("secret", sa.String(128), nullable=False),
            sa.Column("enabled", sa.Boolean, nullable=False, default=True),
            sa.Column("last_step", sa.Integer, nullable=True),
            sa.Column("recovery_hashes_json", sa.Text, nullable=False, default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        metadata.create_all(engine, checkfirst=True)

    def get(self, user_id: str) -> MFAEnrollment | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.user_id == user_id)
            ).mappings().first()
            if row is None:
                return None
            raw_hashes = json.loads(str(row["recovery_hashes_json"] or "[]"))
            return MFAEnrollment(
                user_id=str(row["user_id"]),
                secret=str(row["secret"]),
                enabled=bool(row["enabled"]),
                last_step=int(row["last_step"]) if row["last_step"] is not None else None,
                recovery_hashes=tuple(str(h) for h in raw_hashes),
                created_at=row["created_at"],
            )

    def save(self, enrollment: MFAEnrollment) -> None:
        now = enrollment.created_at or datetime.now(timezone.utc)
        hashes_json = json.dumps(list(enrollment.recovery_hashes))
        with Session(self._engine) as sess:
            existing = sess.execute(
                sa.select(self._table.c.user_id).where(self._table.c.user_id == enrollment.user_id)
            ).first()
            if existing is None:
                sess.execute(
                    self._table.insert().values(
                        user_id=enrollment.user_id,
                        secret=enrollment.secret,
                        enabled=enrollment.enabled,
                        last_step=enrollment.last_step,
                        recovery_hashes_json=hashes_json,
                        created_at=now,
                    )
                )
            else:
                sess.execute(
                    self._table.update()
                    .where(self._table.c.user_id == enrollment.user_id)
                    .values(
                        secret=enrollment.secret,
                        enabled=enrollment.enabled,
                        last_step=enrollment.last_step,
                        recovery_hashes_json=hashes_json,
                    )
                )
            sess.commit()

    def delete(self, user_id: str) -> None:
        with Session(self._engine) as sess:
            sess.execute(self._table.delete().where(self._table.c.user_id == user_id))
            sess.commit()

    def verify_and_record(
        self,
        user_id: str,
        code: str,
        *,
        timestamp: float | None = None,
    ) -> bool:
        """Atomically verify TOTP / recovery code with compare-and-swap SQL updates."""
        with Session(self._engine) as sess:
            row = (
                sess.execute(
                    sa.select(self._table).where(self._table.c.user_id == user_id)
                )
                .mappings()
                .first()
            )
            if row is None or not bool(row["enabled"]):
                return False

            secret = str(row["secret"])
            last_step = int(row["last_step"]) if row["last_step"] is not None else None
            old_hashes_json = str(row["recovery_hashes_json"] or "[]")
            raw_hashes = tuple(str(h) for h in json.loads(old_hashes_json))

            step = verify_totp(secret, code, timestamp=timestamp, last_step=last_step)
            if step is not None:
                res = sess.execute(
                    self._table.update()
                    .where(
                        self._table.c.user_id == user_id,
                        self._table.c.enabled.is_(True),
                        sa.or_(
                            self._table.c.last_step.is_(None),
                            self._table.c.last_step < step,
                        ),
                    )
                    .values(last_step=step)
                )
                sess.commit()
                return bool(getattr(res, "rowcount", 0) == 1)

            cleaned = code.strip().upper()
            for idx, hashed in enumerate(raw_hashes):
                if check_password_hash(hashed, cleaned):
                    remaining = raw_hashes[:idx] + raw_hashes[idx + 1 :]
                    new_hashes_json = json.dumps(list(remaining))
                    res = sess.execute(
                        self._table.update()
                        .where(
                            self._table.c.user_id == user_id,
                            self._table.c.enabled.is_(True),
                            self._table.c.recovery_hashes_json == old_hashes_json,
                        )
                        .values(recovery_hashes_json=new_hashes_json)
                    )
                    sess.commit()
                    return bool(getattr(res, "rowcount", 0) == 1)
            return False
