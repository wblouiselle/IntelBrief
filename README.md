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
