# Testing IntelBrief

IntelBrief is tested in three ways:

| Level | What it checks | Speed | Uses internet? |
|---|---|---|---|
| **1. Automated tests** (`pytest`) | Each function does what it should, including when things go wrong | Under 1 second | No |
| **2. Code quality** (`ruff`) | Style problems and likely bugs | Instant | No |
| **3. Manual end-to-end** | The real program works against the live CISA feed | A few seconds | Yes |

Commands below are for PowerShell on Windows, run from the project root. On macOS/Linux,
activate with `source .venv/bin/activate`; everything else is the same.

---

## Setup

Follow the setup steps in the [README](../README.md), then activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell says *"running scripts is disabled"*, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

---

## Level 1: Automated tests

```powershell
pytest                      # run everything
pytest -v                   # list each test by name
pytest tests/test_cli.py    # one file
pytest -k ransomware        # only tests with "ransomware" in the name
pytest --lf                 # only the tests that failed last time
```

In the output, each `.` is a passing test, `F` is a failed test and `E` is a test that crashed.

### What the tests cover

| File | Covers |
|---|---|
| `test_config.py` | Settings load correctly from environment variables |
| `test_db.py` | Tables are created; saving the same data twice updates it instead of duplicating it; each ingest run is logged |
| `test_http.py` | Requests send a descriptive User-Agent and retry on errors like 429 (rate limited) and 503 (server busy) |
| `test_cisa_kev.py` | Messy feed data is cleaned; bad CVE IDs are skipped; the local copy of the feed is reused or re-downloaded correctly; failed runs are logged |
| `test_cli.py` | The `intelbrief` commands produce the right output and exit codes |

### Why the tests never use the internet

The tests read `tests/fixtures/cisa_kev_sample.json`, a small, hand-made copy of the
real feed that includes some broken records on purpose. They also use pytest's
`monkeypatch`, which temporarily replaces a function during a test; here it swaps the
download function for one that reads the sample file. That makes the tests:

- **Repeatable:** same input, same result, every time
- **Fast:** no waiting on the network
- **Polite:** they don't hit public data feeds every time someone runs them

### Check that a test can fail

A test only proves something if it fails when the code is wrong. To see this:

1. In `src/intelbrief/ingest/cisa_kev.py`, find `known_ransomware_use=ransomware == "known",`.
2. Change `"known"` to `"yes"` and run `pytest`. Some tests fail, and pytest shows the
   expected value next to the actual value.
3. Undo the change and run `pytest` again until everything passes.

---

## Level 2: Code quality

```powershell
ruff check .     # look for bugs and style problems
ruff format .    # fix formatting automatically
```

---

## Level 3: Manual end-to-end test

### Run the pipeline

```powershell
intelbrief --help
intelbrief ingest
```

You should see log lines and then `CISA KEV: <number> entries stored in ...\data\intelbrief.db`.
The number goes up over time as CISA adds vulnerabilities to the catalog.

### Check that the local copy of the feed is reused

Run `intelbrief ingest` again right away. This time the log should say
**`Using cached KEV catalog`** instead of `Downloading...`, because a copy less than
6 hours old in `data\cache\` is reused. To force a fresh download:

```powershell
Remove-Item data\cache\cisa_kev.json
intelbrief ingest
```

### Look inside the database

```powershell
python -c "import sqlite3; c = sqlite3.connect('data/intelbrief.db'); print(c.execute('SELECT COUNT(*) FROM kev_entries').fetchone()); [print(r) for r in c.execute('SELECT * FROM ingest_runs')]"
```

This prints the number of saved entries, then one row per ingest run. For a
point-and-click view, open `data\intelbrief.db` in [DB Browser for SQLite](https://sqlitebrowser.org/).

Things to check:

- The number of saved entries is the same after running ingest twice (no duplicates).
- One CVE picked at random matches the
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  vendor, product and due date.

### Make it fail on purpose

Set a timeout so short that the download has to fail. Deleting the cached copy first
forces the program to try the network:

```powershell
Remove-Item data\cache\cisa_kev.json -ErrorAction SilentlyContinue
$env:INTELBRIEF_HTTP_TIMEOUT = "0.001"
intelbrief ingest
$LASTEXITCODE                                  # should print 1
Remove-Item Env:INTELBRIEF_HTTP_TIMEOUT        # back to normal
intelbrief ingest                              # restore the cached copy
```

What to look for:

- `Retrying...` warnings show the retry logic working.
- A one-line `CISA KEV ingest failed: ...` message appears instead of a Python traceback.
- The exit code is `1`, so an automated job would know the run failed.
- A `failed` row with the error text appears in `ingest_runs`.

### Commands not built yet

`intelbrief score` and `intelbrief brief` print "not implemented yet" and exit with
code `1`, so automation can't mistake them for a successful run.

---

## Before every commit

```powershell
pytest
ruff check .
ruff format .
intelbrief ingest   # when ingest or CLI code changed
```

## Planned testing

- **Scoring:** tests with made-up inputs where the right answer is known, e.g. a KEV CVE
  on an internet-facing, high-criticality server scores higher than the same CVE on a
  low-criticality internal one, and the parts of each score add up to the total.
- **AI briefing:** every CVE ID in a generated briefing is checked against the input
  data, and any that aren't found are flagged.
- **Continuous integration:** GitHub Actions runs `pytest` and `ruff` on every push.
