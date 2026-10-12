# IntelBrief — Threat Intelligence Briefing Pipeline

## Project Overview
IntelBrief is an automated cyber threat intelligence (CTI) pipeline. It collects
vulnerability and threat data from free public feeds, prioritizes it against a
fictional organization's asset inventory, and uses the Claude API to generate a
daily briefing for two audiences: the IT/security team and non-technical leadership.

This is a **portfolio project** for a Computer Information Systems student pursuing
a career in cybersecurity / security intelligence. It will be shown to recruiters
and discussed in interviews.

## Working Agreement (read this first)
- **I am learning.** After writing any non-trivial code, briefly explain what it does
  and why you chose that approach. If there are tradeoffs, name them.
- **Plan before building.** For any new feature, propose a plan and wait for my
  approval before writing code.
- **Small steps.** Work one phase at a time. Keep changes small enough to review.
  Suggest a commit message after each working change.
- **Ask before adding dependencies.** Prefer the standard library and the approved
  stack below.
- **Keep it simple.** Favor readable code over clever code. I need to be able to
  explain every part of this project in an interview.
- **Defensive use only.** This project consumes public threat data for prioritization
  and reporting. It never scans, probes, or interacts with third-party systems.

## Tech Stack
- Python 3.11+
- `requests` — HTTP calls to data feeds
- `sqlite3` (standard library) — local storage
- `anthropic` — Claude API for briefing generation
- `python-dotenv` — load secrets from `.env`
- `typer` — command-line interface
- Static HTML site (standard library templates) published to GitHub Pages
- `pytest` — tests
- `ruff` — linting and formatting

## Project Structure
```
intelbrief/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── .env.example            # template for secrets; real .env is gitignored
├── data/
│   ├── assets.csv          # mock asset inventory for "Shenandoah Valley Health" (fictional)
│   └── intelbrief.db       # SQLite database (gitignored)
├── src/intelbrief/
│   ├── __init__.py
│   ├── config.py           # settings and environment variables
│   ├── db.py               # schema creation and database helpers
│   ├── cli.py              # typer commands: ingest, score, brief
│   ├── ingest/
│   │   ├── cisa_kev.py     # CISA Known Exploited Vulnerabilities
│   │   ├── nvd.py          # NVD CVE API 2.0
│   │   ├── epss.py         # FIRST EPSS scores
│   │   └── urlhaus.py      # abuse.ch URLhaus (Phase 4, optional)
│   ├── assets.py           # load inventory, match CVEs to assets
│   ├── scoring.py          # priority scoring logic
│   └── briefing.py         # build prompt, call Claude API, save report
├── reports/                # generated briefings as Markdown (gitignored except samples/)
├── app.py                  # streamlit dashboard (Phase 4)
├── tests/
└── .github/workflows/
    └── daily.yml           # scheduled pipeline run (Phase 4)
```

## Data Sources
| Source | Endpoint | Auth | Notes |
|---|---|---|---|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | Full catalog in one JSON file. Includes `vendorProject`, `product`, `dueDate`, `knownRansomwareCampaignUse`. |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Optional free API key | Rate limited, much lower without a key. Always sleep between requests and cache results. |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | None | Probability (0–1) a CVE is exploited in the next 30 days. Supports batching multiple CVEs per request. |
| abuse.ch URLhaus | See abuse.ch docs | Free auth key | Phase 4 stretch goal only. |

Rules for all ingestion code:
- Respect rate limits. Add delays and retries with backoff.
- Cache raw responses so we don't re-download data unnecessarily during development.
- Set a descriptive `User-Agent` header.
- Handle missing fields gracefully. Real-world feeds are messy.

## Asset Inventory
`data/assets.csv` describes a fictional regional healthcare organization. Columns:
`asset_id, hostname, vendor, product, version, business_criticality (low/medium/high), internet_facing (true/false)`

Matching starts simple: case-insensitive vendor + product comparison against KEV
`vendorProject` / `product` fields. Upgrading to CPE-based matching via NVD data is a
later improvement. Document known false positives/negatives in the README.

## Priority Scoring (initial draft, revisit in Phase 2)
Score from 0–100, computed only for CVEs that match at least one asset:
- +40 if listed in CISA KEV (actively exploited)
- +25 × EPSS probability
- +15 × (CVSS base score / 10)
- +10 if KEV marks known ransomware campaign use
- +10 if the matched asset is internet-facing and high criticality

Keep the weights in `config.py` so they're easy to tune. Every score must be
explainable: store the component breakdown, not just the total.

## Briefing Generation Rules
- The API key comes from the `ANTHROPIC_API_KEY` environment variable. Never hardcode it.
- The model name is set in `config.py` via an environment variable, not hardcoded in logic.
- **Grounding is mandatory.** The prompt passes only structured data from our database.
  Instruct the model to use only the provided data, cite CVE IDs for every claim, and
  never invent CVEs, vendors, dates, or statistics.
- Output two sections:
  1. **Technical brief** — top priorities, affected assets, why each matters, recommended action, CISA due date if present.
  2. **Executive summary** — 3–5 sentences in plain language focused on business risk.
- After generation, validate that every CVE ID mentioned in the output exists in the
  input data. Flag any that don't.
- Save each briefing as `reports/brief-YYYY-MM-DD.md`.

## Code Conventions
- Type hints on all function signatures.
- Docstrings on public functions (one or two lines is fine).
- Use `logging`, not `print`, outside the CLI.
- No secrets in code or commits. Keep `.env` in `.gitignore` and maintain `.env.example`.
- Tests should never hit live APIs. Use saved sample responses in `tests/fixtures/`.

## Commands
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                    # run tests
ruff check . && ruff format .
intelbrief ingest         # pull feeds into SQLite
intelbrief score          # match assets and compute priorities
intelbrief brief          # generate today's briefing
streamlit run app.py      # dashboard (Phase 4)
```

## Roadmap
Update the checkboxes as work is completed.

**Phase 1 — Foundation**
- [x] Project scaffolding, `pyproject.toml`, `.gitignore`, `.env.example`
- [x] SQLite schema and `db.py`
- [x] CISA KEV ingestion with tests
- [x] `intelbrief ingest` command working end to end

**Phase 2 — Enrichment and Prioritization**
- [ ] NVD enrichment (CVSS, description, CWE) with rate limiting and caching
- [ ] EPSS enrichment (batched)
- [ ] Mock asset inventory and matching logic
- [ ] Scoring with stored component breakdown

**Phase 3 — AI Briefing**
- [ ] Prompt design with grounding rules
- [ ] Claude API integration and Markdown report output
- [ ] Post-generation CVE ID validation
- [ ] Save one strong sample briefing to `reports/samples/` for the README

**Phase 4 — Polish and Automation**
- [ ] Streamlit dashboard
- [ ] GitHub Actions daily run
- [ ] Stretch: MITRE ATT&CK technique mapping
- [ ] Stretch: URLhaus indicator feed
- [ ] README with architecture diagram, design decisions, limitations, sample output
