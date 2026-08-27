# Finance Tracker v2

A security-first, ground-up rebuild of my university capstone finance tracker, with application-security discipline wired in from the first commit.

**v1 to v2:** the [original capstone](https://github.com/ViperKEKW/Milton-Seligson---Capstone-Project---Finance-Tracker) taught me full-stack fundamentals. Before starting v2, I ran a security review of it and found the classic early-career mistakes: committed `.env` secrets, unauthenticated endpoints, `SELECT *` responses leaking password hashes, and missing object-level authorization. **v2 exists to do all of that right**, and to prove it with CI gates that catch those mistake classes automatically.

Design reasoning, threat models, and the alternatives I rejected are written up in **[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)**.

## What is built today

| Piece | Stack |
|---|---|
| Backend | Flask (Python) + SQLite, 112 tests |
| Passwords | Argon2id (memory-hard), dummy-hash verification to close the account-enumeration timing channel |
| Sessions | Server-side, keyed on a SHA-256 token hash, in `httpOnly` / `Secure` / `SameSite` cookies, with idle and absolute expiry |
| CSRF | Double-submit token enforced by a `before_request` hook, so protection is the default rather than opt-in |
| Authorization | Object-level, enforced inside the SQL `WHERE` clause rather than checked after the fetch |
| CI/CD | GitHub Actions: Ruff lint, pytest, **Semgrep (SAST)**, **pip-audit (SCA)**, **gitleaks (secret scanning)** as merge gates |

## Security principles

1. **No secrets in version control.** gitleaks gates every push, and `.env.example` documents configuration.
2. **Every route is authenticated and authorized.** Object-level checks, not just "is logged in."
3. **All input is validated, all queries parameterized.** No string-built SQL, ever.
4. **Responses return only what the client needs.** No `SELECT *`, no leaked hashes.
5. **Dependencies are scanned.** Known-vulnerable packages fail the build.

## Roadmap

Built:

- [x] **Layer 0** Project skeleton with security-gated CI
- [x] **Layer 1** Flask API core: session auth done right, accounts and transactions domain, 112 tests

Not built yet. Everything below is planned work, not current functionality:

- [ ] **Layer 2** React frontend on Vercel (TypeScript is a learning target for this layer)
- [ ] **Layer 3** Docker and docker-compose, migrating SQLite to PostgreSQL
- [ ] **Layer 4** CI/CD extended: build, scan, and deploy pipelines
- [ ] **Layer 5** Live deployment: AWS EC2 + Nginx + TLS
- [ ] **Layer 6** AI insights assistant with a security design doc (prompt-injection defense, least-privilege data access)
- [ ] **Layer 7** Budgets and goals, recurring transactions, bank CSV import, investments
- [ ] **Layer 8** Observability (Prometheus / Grafana)

## Development

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```
