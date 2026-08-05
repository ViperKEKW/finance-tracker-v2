# Finance Tracker v2

A security-first, ground-up rebuild of my university capstone finance tracker — modern stack, real deployment, and application-security discipline wired in from the first commit.

**v1 → v2:** the [original capstone](https://github.com/ViperKEKW/Milton-Seligson---Capstone-Project---Finance-Tracker) taught me full-stack fundamentals. Before starting v2, I ran a security review of it and found the classic early-career mistakes: committed `.env` secrets, unauthenticated endpoints, `SELECT *` responses leaking password hashes, and missing object-level authorization. **v2 exists to do all of that right** — and to prove it with CI gates that catch those mistake classes automatically.

## Architecture

| Piece | Stack |
|---|---|
| Frontend | React + TypeScript + Vite + Tailwind, deployed on Vercel |
| Backend | Flask (Python) + PostgreSQL, deployed on AWS EC2 behind Nginx with TLS (Let's Encrypt) |
| Auth | Server-side sessions in `httpOnly` / `Secure` / `SameSite` cookies + CSRF protection |
| AI | Insights assistant (Claude API) with an explicit security design: prompt-injection defense, least-privilege data access |
| CI/CD | GitHub Actions: lint, tests, **Semgrep (SAST)**, **pip-audit (SCA)**, **gitleaks (secret scanning)** as merge gates |

## Security principles

1. **No secrets in version control** — gitleaks gates every push; `.env.example` documents configuration.
2. **Every route is authenticated and authorized** — object-level checks, not just "is logged in."
3. **All input is validated, all queries parameterized** — no string-built SQL, ever.
4. **Responses return only what the client needs** — no `SELECT *`, no leaked hashes.
5. **Dependencies are scanned** — known-vulnerable packages fail the build.

## Roadmap

- [x] **Layer 0** — Project skeleton with security-gated CI (this commit)
- [ ] **Layer 1** — Flask API core: session auth done right, accounts & transactions domain
- [ ] **Layer 2** — TypeScript/React frontend on Vercel
- [ ] **Layer 3** — Docker + docker-compose (api + Postgres + Redis)
- [ ] **Layer 4** — CI/CD extended: build, scan, and deploy pipelines
- [ ] **Layer 5** — Live deployment: EC2 + Nginx + TLS
- [ ] **Layer 6** — AI insights assistant with security design doc
- [ ] **Layer 7** — Budgets & goals, recurring transactions, bank CSV import, investments
- [ ] **Layer 8** — Observability (Prometheus/Grafana)

## Development

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```
