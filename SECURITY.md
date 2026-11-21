# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, report security concerns privately via GitHub Security Advisories on the `duhanguler/flask-deck` repository.

We aim to acknowledge reports within 48 hours and provide a coordinated fix and disclosure timeline.

## Built-in Security Controls

- **Fail-Closed Production Auth:** Running without an `AuthProvider` when `app.debug` is `False` raises `SecurityConfigurationError`.
- **Strict Nonce CSP:** `default-src 'none'; script-src 'self' 'nonce-…'; style-src 'self'; frame-ancestors 'none'` — zero `'unsafe-inline'`.
- **CSRF + Origin Verification:** Cryptographic per-session token (`hmac.compare_digest`) + `Sec-Fetch-Site` check on mutations.
- **Brute-Force Protection:** Sliding-window per-IP/per-username login throttling with constant-time dummy hash verification.
- **Mass-Assignment, IDOR & Injection Guards:** Strict field allowlists, inline parent-ownership checks, `scope_query` row isolation, escaped `LIKE` queries, and CSV formula-injection neutralization.
