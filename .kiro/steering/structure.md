---
inclusion: always
---

# Project Structure

## Directory layout

```
log-analyzer/
├── pyproject.toml                 # packaging, deps, [stats] extra, entry point
├── README.md
├── .kiro/
│   └── steering/                  # these guidance docs
├── src/
│   └── loganalyze/
│       ├── __init__.py
│       ├── cli.py                 # argparse entry point -> main()
│       ├── ingest.py              # discover/read files & dirs, line iteration
│       ├── models.py              # Event, Finding, Severity (normalized model)
│       ├── registry.py            # plugin registration for parsers & detectors
│       ├── pipeline.py            # wires ingest -> parse -> detect -> aggregate -> output
│       ├── parsers/               # pluggable, one module per log format
│       │   ├── __init__.py
│       │   ├── base.py            # Parser protocol / ABC
│       │   ├── nginx.py
│       │   ├── apache.py
│       │   ├── syslog.py
│       │   └── authlog.py
│       ├── detections/
│       │   ├── __init__.py
│       │   ├── base.py            # Detector protocol / ABC, Finding yield contract
│       │   ├── rules/             # rule / signature engine
│       │   │   ├── __init__.py
│       │   │   ├── engine.py
│       │   │   └── signatures/    # individual signature definitions
│       │   └── statistical/       # statistical engine
│       │       ├── __init__.py
│       │       ├── engine.py      # stdlib `statistics`-based; always available
│       │       ├── zscore.py
│       │       ├── rate_spike.py
│       │       └── accelerated.py # OPTIONAL numpy/pandas path; isolated
│       ├── aggregator.py          # dedupe, group, rank findings
│       ├── outputs/
│       │   ├── __init__.py
│       │   ├── base.py            # Output protocol / ABC
│       │   ├── console.py         # human-readable console report
│       │   ├── file_json.py       # structured JSON report
│       │   └── file_report.py     # human-readable file report
│       └── security.py            # shared sanitization/masking helpers
└── tests/
    ├── conftest.py
    ├── fixtures/                  # sanitized sample logs (NO real PII/secrets)
    │   ├── nginx/
    │   ├── apache/
    │   ├── syslog/
    │   └── authlog/
    ├── parsers/
    ├── detections/
    └── outputs/
```

## Pipeline (how a run flows)

`cli.py` -> `ingest.py` -> `parsers/*` -> `models.Event` ->
`detections/{rules,statistical}` -> `models.Finding` -> `aggregator.py` ->
`outputs/*`.

Alert sinks (webhook/Slack/email/SIEM) are a **reserved future extension point**:
they would be added as new modules under `outputs/` implementing the same
`Output` protocol. Do not build them in v1.

## Module responsibilities

- **cli** — parse args, resolve input paths, select format(s) and outputs, set
  exit code. No detection logic here.
- **ingest** — turn a path (file or directory) into an ordered stream of
  `(source, line_number, raw_line)`. Enforces the line-length cap from
  `security.md`.
- **parsers** — each converts one raw line of a specific format into a normalized
  `Event` (or signals "unparseable"). Parsers are **pure**: line in, `Event` or
  `None` out, no I/O, no global state.
- **models** — the normalized `Event`, the `Finding`, and the `Severity` enum.
  This is the contract every parser and detector shares.
- **detections/rules** — signature engine. Each signature matches `Event`s and
  yields `Finding`s. Regexes follow `security.md`.
- **detections/statistical** — baselining and anomaly scoring built on the stdlib
  `statistics` module. This is the default and always-available path.
- **detections/statistical/accelerated** — optional vectorized path using
  `numpy`/`pandas` from the `[stats]` extra. Imported lazily; the engine falls
  back to the stdlib path when the extra is absent.
- **aggregator** — deduplicate, group related findings, and rank by severity.
- **outputs** — render findings to console and file. Apply output safety
  (control-char stripping, CSV formula-injection neutralization) and masking from
  `security.md`.
- **security** — shared helpers for input caps, sanitization, and PII/secret
  masking, imported by ingest, detections, and outputs.

## Isolating the optional stats path

Keep the core dependency-free. Never import `numpy`/`pandas` at module top level
in core packages. Gate the accelerated path behind a runtime check:

```python
# detections/statistical/engine.py
def _acceleration_available() -> bool:
    try:
        import numpy  # noqa: F401
        import pandas  # noqa: F401
    except ImportError:
        return False
    return True

def run(events, config):
    if config.use_acceleration and _acceleration_available():
        from .accelerated import run_accelerated
        return run_accelerated(events, config)
    return run_stdlib(events, config)   # statistics-module implementation
```

## Plugin / registration pattern

Parsers, detectors, and outputs are plugins behind a protocol in their package's
`base.py`, registered via decorators in `registry.py`:

```python
from loganalyze.registry import register_parser
from loganalyze.parsers.base import Parser

@register_parser("nginx")
class NginxParser(Parser):
    def parse(self, raw_line: str) -> Event | None:
        ...
```

Adding a new format or detection means adding one module and registering it; no
edits to the pipeline are required.

## Naming conventions

- Modules and packages: `lower_snake_case`; one log format per parser module.
- Classes: `PascalCase` (`NginxParser`, `BruteForceSignature`).
- Registry keys: short lowercase identifiers (`"nginx"`, `"authlog"`).
- Tests mirror the source tree under `tests/`; fixtures live in
  `tests/fixtures/<format>/` and must be sanitized per `security.md`.
