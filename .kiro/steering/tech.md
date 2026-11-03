---
inclusion: always
---

# Tech Stack

## Language and runtime

- **Python 3.10+.** Use modern typing (`X | None`, `list[str]`,
  `from __future__ import annotations` where helpful).

## Core is standard-library only

The core of `loganalyze` must run with **no third-party runtime dependencies**.
A fresh `pip install loganalyze` (no extras) gives a fully working analyzer.

Core relies on these stdlib modules:

- `argparse` — CLI argument parsing and subcommands.
- `logging` — the tool's own diagnostic logging (distinct from the logs it
  analyzes).
- `re` — pattern matching for parsers and rule/signature detections. All regexes
  must be ReDoS-safe and precompiled; see `security.md`.
- `statistics` — baselines and anomaly scoring: `mean`, `median`, `pstdev` /
  `stdev` for z-scores, `quantiles` for rare-event thresholds.
- `json` — structured file output.
- `csv` — optional tabular export (apply formula-injection neutralization from
  `security.md`).
- `pathlib`, `dataclasses`, `enum`, `collections` — models, config, and
  aggregation.

**Rule:** the statistical engine computes baselines and z-scores with
`statistics`. Do not reach for `numpy`/`pandas` in core code paths.

## Optional extra: `loganalyze[stats]`

`pandas` and `numpy` are available **only** as an optional extra:

```bash
pip install "loganalyze[stats]"
```

Constraints:

- These libraries power an accelerated/vectorized statistical path for large
  inputs only.
- Core detection **must function identically without them.** The optional path is
  isolated behind a feature check (see `structure.md`); never import `pandas` or
  `numpy` at module top level in core packages.
- Results from the optional path must match the stdlib path within tolerance.

## Dependency management

- `pyproject.toml` is the single source of truth.
- Declare the extra under `[project.optional-dependencies]`:

  ```toml
  [project.optional-dependencies]
  stats = ["numpy>=1.24", "pandas>=2.0"]
  dev = ["pytest>=7", "ruff", "black"]
  ```

- Pin lower bounds; avoid open-ended ranges on direct deps.
- Develop inside a virtualenv (`python -m venv .venv`).

## Packaging

- Ship as an installable package exposing a **console entry point** named
  `loganalyze`:

  ```toml
  [project.scripts]
  loganalyze = "loganalyze.cli:main"
  ```

## Common commands

```bash
# Set up
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1

# Install (core only — no third-party runtime deps)
pip install -e .

# Install with the optional accelerated stats extra
pip install -e ".[stats]"

# Install dev tooling
pip install -e ".[dev]"

# Run the analyzer
loganalyze /var/log/nginx/access.log --format nginx --report out.json
loganalyze /var/log/ --report findings.json

# Test, lint, format
pytest
ruff check .
black .
```

## Future (not v1)

- Alert-sink clients (webhook/Slack/email/SIEM) would arrive as a separate
  optional extra, e.g. `loganalyze[alerts]`. Do not add those dependencies now.
