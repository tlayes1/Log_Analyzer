# Log_Analyzer

`loganalyze` is a batch command-line tool that scans system and web-server logs
for known attack signatures and statistical anomalies. It reads logs read-only,
normalizes each line into a common event model, runs a set of detectors, and
reports findings to the console and optional JSON/CSV reports.

The core is **standard-library only** — no runtime dependencies — and runs on
Python 3.10+.

## Features

- **Multiple log formats** with per-file auto-detection or a forced parser:
  - `nginx` — nginx combined access logs
  - `apache` — Apache combined access logs
  - `syslog` — traditional RFC3164 (BSD) syslog
  - `authlog` — Linux `auth.log` (sshd, sudo, su, PAM)
- **Signature detections** (rule engine):
  - Web: SQL-injection probes, XSS probes, known scanner user-agents
  - Auth: failed logins, privilege escalation via `sudo`/`su`
  - Windowed: SSH/auth brute force, HTTP error-status spikes
- **Statistical detections**:
  - Rate spikes (z-score over fixed time buckets)
  - Rare categorical events (relative-frequency cutoff)
- **Outputs**: console table (always), a self-contained HTML report, JSON
  report, optional CSV report
- **Safe ingestion**: per-line byte cap, gzip support, truncated/unparseable
  lines are counted and skipped rather than fatal.

## Requirements

- Python 3.10, 3.11, or 3.12

## Quick start (no experience needed)

If you have never used a command line before, follow these steps exactly. Text
in `code font` is typed into the terminal and run by pressing Enter.

1. **Install Python** (3.10 or newer) from
   [python.org/downloads](https://www.python.org/downloads/). On Windows, tick
   "Add Python to PATH" in the installer.
2. **Open a terminal.** On Windows, open **PowerShell** (search for it in the
   Start menu). On macOS, open **Terminal**.
3. **Go into the project folder.** Use `cd` followed by the path to the
   `Log_Analyzer` folder. For example:
   ```
   cd Log_Analyzer
   ```
4. **Create and turn on a private workspace** (a "virtual environment") so this
   tool's files stay separate from the rest of your computer:
   ```
   python -m venv .venv
   ```
   Then turn it on:
   - Windows (PowerShell): `.venv\Scripts\Activate.ps1`
   - macOS / Linux: `source .venv/bin/activate`
5. **Install the tool:**
   ```
   pip install .
   ```
6. **Run it on a log file.** Put the path to your log where `your-log.log` is:
   ```
   loganalyze your-log.log
   ```
   A table of anything suspicious prints in the terminal. If nothing is found,
   it says `No findings.` — that is a good thing.
7. **Make an easy-to-read report.** Add `--html report.html` to write a report
   file:
   ```
   loganalyze your-log.log --html report.html
   ```
8. **Open the report.** Find `report.html` in the folder and double-click it. It
   opens in your web browser, grouped by severity, with a search box and
   category filters. Nothing is sent over the internet — the file works offline.

That's it. To analyze another log later, repeat steps 2, 3, turn the workspace
back on (step 4's activate line), and run step 6 or 7.

## Installation

Clone the repository and install into a virtual environment.

```bash
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

# Install the CLI
pip install .
```

For development (editable install plus test/lint tooling):

```bash
pip install -e ".[dev]"
```

Installation adds a `loganalyze` console command. You can also run it as a
module with `python -m loganalyze.cli`.

## Usage

```bash
loganalyze PATH [PATH ...] [options]
```

`PATH` is one or more log files or directories (directories are scanned for
readable files). At least one path is required.

### Options

| Option | Description |
| --- | --- |
| `--format KEY` | Force a parser (`nginx`, `apache`, `syslog`, `authlog`) instead of auto-detecting per file. |
| `--html PATH` | Write a self-contained HTML report to `PATH` (opens in any browser, works offline). |
| `--report PATH` | Write a structured JSON report to `PATH`. |
| `--csv PATH` | Write a CSV report to `PATH` (requires the optional CSV renderer). |
| `--max-line-bytes N` | Line-length cap in bytes applied before any regex (default `65536`, min `1`). |
| `--z-threshold Z` | Rate-spike z-score threshold (default `3.0`, range `1.0`–`10.0`). |
| `--rare-cutoff F` | Rare-event relative-frequency cutoff (default `0.01`, `0 < F < 1`). |

### Examples

Analyze a single auth log:

```bash
loganalyze /var/log/auth.log
```

Analyze an auth log and write a readable HTML report:

```bash
loganalyze /var/log/auth.log --html report.html
```

The HTML report is a single self-contained file (no external assets, no network
calls). It groups findings by severity, summarizes what was found in a "What was
found" dropdown, and offers a text search box with category filter toggles and
typeahead suggestions. All log-derived values are masked and HTML-escaped, so a
report never carries a raw client IP, secret, or executable content.

Analyze a directory of nginx logs and write a JSON report:

```bash
loganalyze /var/log/nginx/ --format nginx --report findings.json
```

Analyze several files with a stricter rate-spike threshold and a CSV report:

```bash
loganalyze access.log access.log.1.gz --z-threshold 4.0 --csv findings.csv
```

After each run, the number of skipped lines (truncated and unparseable) is
reported on standard error.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean run — no findings. |
| `1` | At least one finding was produced. |
| `2` | Error — usage error, unknown `--format`, nonexistent/unreadable/empty input, invalid configuration, or an output write failure. |

Scripts can branch on these codes (e.g. exit `1` to flag that something was
detected).

## Development

Run the test suite with `pytest`:

```bash
pip install -e ".[dev]"
pytest
```

Lint and format with `ruff` and `black`:

```bash
ruff check .
black .
```

## Project layout

```
src/loganalyze/
  cli.py            Command-line entry point and exit-code handling
  pipeline.py       Batch run orchestration
  ingest.py         Read-only ingestion, line capping, gzip support
  models.py         Event / Finding / Severity data models
  config.py         Validated run configuration
  registry.py       Plugin registry for parsers, detectors, outputs
  parsers/          nginx, apache, syslog, authlog parsers
  detections/
    rules/          Signature + windowed detectors
    statistical/    Rate-spike and rare-event detectors
  outputs/          Console, HTML, JSON, and CSV renderers
tests/              Unit and property-based tests
```

## License

MIT
