<div align="center">

# GuardianHealth

### Zero-Trust Identity & Access Management for Healthcare

A production-grade Python/Flask platform that protects patient data with
multi-factor email verification, server-bound sessions, role-based access,
and a tamper-evident blockchain audit trail.

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-336791?style=flat-square&logo=postgresql&logoColor=white)](https://supabase.com/)
[![License](https://img.shields.io/badge/License-MIT-14b8a6?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/Status-Active-22c55e?style=flat-square)](#)

</div>

---

## Why GuardianHealth?

Healthcare systems handle some of the most sensitive data on earth, yet most
internal admin tools still rely on plain passwords and ad-hoc audit logs.
GuardianHealth is a clean, opinionated reference implementation that shows
how a small team can ship a **Zero-Trust** internal platform without a heavy
enterprise stack.

> **Zero Trust** — never trust, always verify. Every request is re-validated
> against the database, the session, and the role on every API call.

---

## Highlights

| Pillar | What it gives you |
|---|---|
| **Identity** | Custom JWT in an HttpOnly cookie + CSRF header, optional Google sign-in |
| **MFA** | One-time email codes (HMAC-hashed, single-use, time-limited) |
| **Sessions** | Every JWT is bound to a server-side session row that admins can revoke |
| **RBAC** | Four roles (admin / doctor / staff / patient), enforced server-side |
| **Audit** | SHA-256 hash chain in PostgreSQL **and** an ECDSA-signed blockchain |
| **Security Headers** | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS |
| **Input Hygiene** | Parameterized SQL everywhere, regex-validated names/emails, role/status allow-lists |
| **XSS Defense** | All dynamic JS rendering goes through an `escapeHtml` helper |

---

## Tech Stack

```
Backend     →  Python 3.11 · Flask · psycopg2
Database    →  PostgreSQL (hosted on Supabase)
Auth        →  PyJWT (HS256) · bcrypt · HMAC-SHA256
Crypto      →  cryptography (ECDSA secp256k1)
Frontend    →  Server-rendered Jinja2 + vanilla JS · Inter font
Email       →  SMTP (Brevo / any provider)
```

---

## Architecture at a Glance

```
                    ┌──────────────────────┐
   Browser  ───▶    │  Flask  (app.py)     │  ───▶  PostgreSQL (Supabase)
                    │  • JWT + Session     │
                    │  • RBAC middleware   │  ───▶  Blockchain (signed)
                    │  • CSRF guard        │
                    │  • Security headers  │  ───▶  SMTP (MFA codes)
                    └──────────────────────┘
```

* **One Flask app** — all auth, RBAC, and APIs live in `app.py`
* **One per-request DB connection**, opened in `get_db()` and closed on teardown
* **Append-only blockchain** — PostgreSQL `RULE`s block any UPDATE / DELETE
* **External anchor file** stores the latest block hash for out-of-band verification

---

## Project Layout

```
guardianhealth/
├── app.py                  # Flask app, routes, auth, RBAC, APIs
├── main.py                 # Trivial CLI entry stub
├── blockchain/
│   ├── block.py            # Block dataclass (hash + signature)
│   ├── chain.py            # HealthcareBlockchain (mine, sign, persist, verify)
│   ├── anchor.txt          # Latest block hash (out-of-band anchor)
│   └── signing_key.pem     # ECDSA private key (auto-generated, git-ignored)
├── templates/              # Jinja2 templates (one per page)
├── static/
│   ├── css/style.css       # Premium dark + light theme
│   └── js/
│       ├── auth.js         # Auth state, API client, escapeHtml helper
│       └── pages/          # One JS file per page
├── requirements.txt
├── .env.example            # Copy to .env and fill in secrets
└── replit.md               # Architectural notes
```

---

## Roles

| Role | What they can do |
|---|---|
| **admin** | Full access — users, patients, sessions, audit logs, blockchain |
| **doctor** | Their own assigned patients only |
| **staff** | Read-only patient list |
| **patient** | Their own audit logs only |

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/<you>/guardianhealth.git
cd guardianhealth
cp .env.example .env       # then fill in the secrets below
```

### 2. Required environment variables

| Variable | Purpose |
|---|---|
| `SUPABASE_DB_URL` | PostgreSQL connection string |
| `SUPABASE_SERVICE_ROLE_KEY` | Service-role key (used as needed) |
| `JWT_SECRET` | Random 32+ byte string for signing JWTs |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for MFA email |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP credentials |
| `SMTP_FROM_EMAIL` / `SMTP_FROM_NAME` | Verified sender identity |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Optional — enables Google sign-in |

### 3. Install and run

```bash
pip install -r requirements.txt
python app.py                  # listens on http://localhost:5000
```

That's it. Tables and indexes are created on first start.

---

## API Surface

### Auth
```
POST   /api/auth/login                 Email + password (returns MFA challenge)
POST   /api/auth/verify-mfa            Submit 6-digit email code
POST   /api/auth/resend-mfa            Re-issue a code (rate-limited)
POST   /api/auth/logout                End the current session
POST   /api/auth/logout-all            End every session for the current user
GET    /api/auth/me                    Current user info
POST   /api/auth/register              New user → status = pending
PUT    /api/auth/password              Change own password
POST   /api/auth/forgot-password       Email a one-time reset link
POST   /api/auth/reset-password        Consume the reset link
PUT    /api/auth/mfa                   Enable / disable own MFA
GET    /api/auth/sessions              List own sessions
DELETE /api/auth/sessions/<id>         Revoke a session
```

### Resources (admin)
```
GET / POST / PUT / DELETE  /api/users[/<id>]
GET                        /api/patients[/<id>]
GET                        /api/audit-logs
GET                        /api/audit-logs/verify
GET                        /api/blockchain/chain
GET                        /api/blockchain/verify
GET                        /api/blockchain/public-key
POST                       /api/blockchain/tamper-demo
GET / DELETE               /api/sessions[/<id>]
```

### Pages
```
/  /login  /register  /forgot-password  /reset-password
/admin  /doctor  /staff  /patient
/security  /iam  /audit-logs  /settings  /blockchain
```

---

## Security Model

### What's protected
* **Passwords** — bcrypt with per-user salt; legacy SHA-256 hashes are silently re-hashed on next login.
* **MFA codes** — only the HMAC-SHA256 hash is stored; codes are single-use, time-limited, and bound to a temp token.
* **Reset tokens** — only the hash is stored; tokens are single-use, time-limited, and revoke siblings on issue.
* **Sessions** — every protected request re-checks: session active, user status active, current DB role; mismatches return 401/403 immediately.
* **CSRF** — cookie-auth + unsafe methods require a matching `X-CSRF-Token` header.

### What's prevented
| Attack | Defense |
|---|---|
| **SQL Injection** | psycopg2 parameter binding everywhere — no string concatenation in queries |
| **XSS (stored / reflected)** | `escapeHtml` helper for every dynamic insertion + strict CSP |
| **Clickjacking** | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| **MIME sniffing** | `X-Content-Type-Options: nosniff` |
| **Token theft** | HttpOnly cookie, server-bound session, instant revocation |
| **Audit tampering** | SHA-256 chain + ECDSA-signed blockchain + external anchor |
| **Enumeration** | `/forgot-password` always returns the same generic response |

---

## Tamper-Evident Audit Trail

Every sensitive action writes **two** records:

1. A row in `audit_logs` whose `hash` includes the previous row's hash → SHA-256 chain.
2. A signed block in the `blockchain` table that embeds the row hash and the previous block's hash.

Five hardening layers keep it honest:

1. **Chain anchoring** — `blockchain/anchor.txt` stores the latest block hash externally.
2. **ECDSA signing** — every block is signed with a secp256k1 key (`blockchain/signing_key.pem`).
3. **Proof-of-work** — difficulty locked per block (`hash` must start with `000`); timestamps must increase.
4. **Row-binding** — each block embeds the SHA-256 hash of the exact `audit_logs` row.
5. **Append-only enforcement** — PostgreSQL `RULE`s reject any `UPDATE` or `DELETE` on the `blockchain` table.

Verify the whole chain end-to-end:

```http
GET /api/blockchain/verify
GET /api/audit-logs/verify
```

---

## Development Notes

* Set `NODE_ENV=production` to enable HTTP caching of static assets.
* `ACCESS_TOKEN_HOURS`, `MFA_OTP_TTL_MINUTES`, `MFA_OTP_MAX_ATTEMPTS`, and
  `PASSWORD_RESET_TTL_MINUTES` are all environment-tunable.
* The frontend uses Inter from Google Fonts and Lucide icons from unpkg —
  both whitelisted in the CSP.
* Light / dark mode toggle persists per-user via `localStorage`.

---

## Roadmap

- [ ] Push notifications for security alerts
- [ ] Per-doctor break-glass emergency access requests
- [ ] WebAuthn / passkey support
- [ ] Per-tenant isolation
- [ ] Background job queue for email delivery

---

## License

Released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

**Built with care for healthcare teams that take Zero Trust seriously.**

</div>
