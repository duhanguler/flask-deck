# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.4.x` | Yes |
| `0.3.x` | Security fixes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, report security concerns privately via GitHub Security Advisories on the `duhanguler/flask-deck` repository.

We aim to acknowledge reports within 48 hours and provide a coordinated fix and disclosure timeline.

## Built-in Security Controls

- **Fail-Closed Production Auth:** Running without an `AuthProvider` when `app.debug` is `False` raises `SecurityConfigurationError`.
- **Strict Nonce CSP:** `default-src 'none'; script-src 'self' 'nonce-…'; style-src 'self'; frame-ancestors 'none'` — zero `'unsafe-inline'`.
- **CSRF + Origin Verification:** Cryptographic per-session token (`hmac.compare_digest`) + `Sec-Fetch-Site` check on mutations, plus `Origin` host-rebinding protection on `/_mcp`.
- **MFA, Passkeys & Session Registry:** Encrypted TOTP secrets at rest (`SecretCipher`), WebAuthn Passkeys, per-session tracking with remote revocation, and audited impersonation.
- **API Keys, Maker-Checker Approvals & Hash-Chained Audit:** SHA-256 hashed Bearer keys (`dk_live_...`) with IP CIDR allowlists & `429 Retry-After` throttling, four-eyes approval queues, and SHA-256 chained audit logs verified by `verify_chain()` and `flask deck audit --format sarif`.
- **Brute-Force Protection:** Sliding-window per-IP/per-username login throttling with constant-time dummy hash verification.
- **Mass-Assignment, IDOR & Injection Guards:** Strict field allowlists, inline parent-ownership checks, `scope_query` row isolation, escaped `LIKE` queries, and CSV/XLSX formula-injection neutralization.
