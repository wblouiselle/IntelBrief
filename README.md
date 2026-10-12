# IntelBrief

Automated cyber threat intelligence pipeline. It pulls free public vulnerability feeds
(CISA KEV, NVD, FIRST EPSS), prioritizes them against a fictional healthcare
organization's asset inventory, and uses the Claude API to write a daily briefing for
both the security team and leadership.

> Work in progress. See the roadmap in `CLAUDE.md`.

## Setup (Windows)

```powershell
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
copy .env.example .env
```

## Public website

The pipeline publishes a readable, searchable view of the CISA KEV catalog to GitHub Pages,
rebuilt every day by GitHub Actions (`.github/workflows/site.yml`). To build it locally:

```powershell
intelbrief ingest
intelbrief site      # writes HTML to site/; open site/index.html in a browser
```

## Testing

See [docs/TESTING.md](docs/TESTING.md) for running the test suite and checking the
pipeline end to end.
