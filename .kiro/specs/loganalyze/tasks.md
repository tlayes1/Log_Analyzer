# Implementation Plan: loganalyze

## Overview

Convert the `loganalyze` design into an incremental, test-driven implementation.
The plan builds the system bottom-up along the design's package layout
(`models → config → registry → security → ingest → parsers → detections (rules +
statistical) → aggregator → outputs → pipeline → cli`), so each task depends only
on components already built and nothing is left orphaned. The implementation is
Python 3.10+, standard-library-only for the core, per `tech.md` and
`coding-conventions.md`. Tests use **pytest** with **Hypothesis** for the
property-based tests, work test-first, and rely solely on synthetic fixtures
(documentation IP ranges, `example.com` emails, non-authenticating credentials)
per `testing-standards.md` and Requirement 11.

Each property test task is annotated with its design property number and the
requirement clause it validates, and is placed next to the code it checks so
regressions surface early. Test sub-tasks are marked optional with `*`; core
implementation tasks are never optional.

## Tasks

- [x] 1. Scaffold package, packaging, and shared models
  - [x] 1.1 Create package skeleton and `pyproject.toml`
    - Create `src/loganalyze/` with `__init__.py` and the empty subpackages
      `parsers/`, `detections/`, `detections/rules/`, `detections/rules/signatures/`,
      `detections/statistical/`, `outputs/`, each with `__init__.py`
    - Create `tests/` mirroring the source tree (`tests/parsers/`,
      `tests/detections/`, `tests/outputs/`, `tests/fixtures/`) with a `conftest.py`
    - Write `pyproject.toml` as the single source of truth: project metadata,
      `requires-python = ">=3.10"`, no core runtime dependencies, the console entry
      point `loganalyze = "loganalyze.cli:main"`, the `[project.optional-dependencies]`
      `stats = ["numpy>=1.24", "pandas>=2.0"]` (future, not imported in core) and
      `dev = ["pytest>=7", "hypothesis>=6", "ruff", "black"]` with pinned lower bounds
    - _Requirements: 1.1; design "Package layout", tech.md Packaging/Dependency management_

  - [x] 1.2 Implement `Severity`, `Event`, and `Finding` models
    - In `src/loganalyze/models.py` define `Severity(IntEnum)` (`INFO=0 … CRITICAL=4`)
      with string forms `info/low/medium/high/critical`, the frozen `Event` dataclass,
      and the `Finding` dataclass exactly per the Data Models section
    - Use `from __future__ import annotations`, modern type hints, module docstring
      and per-class docstrings per coding-conventions.md
    - _Requirements: 3.1, 3.2, 3.3, 5.8, 7.1, 7.2; design "Data Models"_

  - [x]* 1.3 Write unit tests for models
    - Assert `Severity` ordering (`CRITICAL > … > INFO`) and string serialization
    - Assert `Event`/`Finding` field defaults (optional Event fields default `None`,
      `fields` defaults to empty dict)
    - _Requirements: 3.1, 3.2, 5.8, 7.1_

  - [x] 1.4 Implement timestamp normalization helper
    - Add `normalize_timestamp(raw, fmt) -> tuple[datetime, bool]` in `models.py`
      (or `timeutil.py`): offset/`Z` sources convert to UTC (`aware=True`); naive
      sources recorded as local datetime with no offset (`aware=False`)
    - _Requirements: 3.7, 3.8; design "Timestamp normalization helper"_

  - [x]* 1.5 Write property test for timestamp normalization
    - **Property 3: Timestamp normalization is offset-correct**
    - **Validates: Requirements 3.7, 3.8**

- [x] 2. Implement configuration dataclasses
  - [x] 2.1 Implement frozen config models in `config.py`
    - Define `IngestConfig`, `RuleConfig`, `StatisticalConfig`, `DetectionConfig`,
      and `RunConfig` with defaults matching requirements (line cap 65536; brute
      force 5/60s; status spike 20/60s; baseline 60s; z 3.0; rare 0.01; min obs 20)
    - Add pure validation helpers for `max_line_bytes >= 1`,
      `1.0 <= z_threshold <= 10.0`, `0.0 < rare_cutoff < 1.0` (raising on invalid),
      kept free of I/O so the CLI can call them before ingest
    - _Requirements: 2.6, 2.7, 5.4, 5.5, 5.10, 6.2, 6.3, 6.4, 6.7; design "Configuration"_

  - [x]* 2.2 Write unit tests for config validation
    - Assert defaults, and that out-of-range line cap, z-threshold, and rare-cutoff
      each raise; assert boundary values (1, 1.0, 10.0, open interval on cutoff)
    - _Requirements: 2.6, 2.7, 6.3, 6.4_

- [x] 3. Implement Security_Helpers
  - [x] 3.1 Implement `security.py` sanitization and masking helpers
    - Implement `cap_line`, `strip_control` (preserve tab, replace other controls
      with U+FFFD), `csv_safe` (apostrophe-prefix `= + - @`), `mask_secret`,
      `mask_email`, `mask_ip`, all pure and idempotent where specified
    - Precompile the control-character regex at module import; no log-derived data
      passed to `eval`/`exec`/`compile`/`pickle`/shell/dynamic import
    - _Requirements: 8.4, 8.5, 8.7, 8.8, 8.9, 9.3, 9.5; design "security.py"_

  - [x] 3.2 Implement path resolution and atomic write helpers
    - Implement `resolve_output_path(path, *, log_derived)` (canonical absolute real
      path; refuse log-derived paths) and `atomic_write(path, data)` (temp file with
      restrictive permissions + `os.replace`; on failure remove temp and leave any
      existing destination unchanged, then raise)
    - _Requirements: 8.6, 8.11, 8.12, 8.13; design "security.py"_

  - [x]* 3.3 Write property test for control-character stripping
    - **Property 17: Output contains no forbidden control characters**
    - **Validates: Requirements 8.4**

  - [x]* 3.4 Write property test for CSV neutralization
    - **Property 18: CSV fields never begin with a bare formula character**
    - **Validates: Requirements 8.5**

  - [x]* 3.5 Write property test for secret masking
    - **Property 19: Secret masking never reveals more than allowed and is idempotent**
    - **Validates: Requirements 8.7**

  - [x]* 3.6 Write property test for email masking
    - **Property 20: Email masking reveals at most the first local character and the domain**
    - **Validates: Requirements 8.8**

  - [x]* 3.7 Write property test for IP masking
    - **Property 21: IP masking reveals at most the first two octets**
    - **Validates: Requirements 8.9**

  - [x]* 3.8 Write unit tests for path resolution and atomic write
    - Assert canonical absolute resolution, refusal of log-derived paths; simulate a
      replace failure and assert prior destination intact, temp file removed, error raised
    - _Requirements: 8.11, 8.12, 8.13_

- [x] 4. Implement the plugin registry
  - [x] 4.1 Implement `registry.py` with the three registries
    - Implement `RegistryConflictError`, `register_parser/detector/output` decorators
      (raise on duplicate key), and accessors `get_parser(s)/get_detectors/get_outputs`
      that instantiate registered classes in deterministic order
    - _Requirements: 3.10, 3.11, 5.9, 8.14; design "registry.py"_

  - [x]* 4.2 Write unit tests for the registry
    - Assert registration + lookup by key, deterministic ordering, and that a
      duplicate key raises `RegistryConflictError` (no silent override)
    - _Requirements: 3.10, 3.11, 5.9, 8.14_

- [x] 5. Implement ingest and skip counting
  - [x] 5.1 Implement `ingest.py` discovery and capped line iteration
    - Implement `LineRecord`, `IngestError`, `discover_inputs` (file → itself,
      directory → recursive regular files, raise on nonexistent path),
      and `iter_lines` (gzip by magic bytes `1f 8b`, else plaintext; enforce
      `max_line_bytes` via `Security_Helpers.cap_line` before any regex; ascending
      line numbers from 1; preserve source; read-only; `IngestError` on bad gzip)
    - _Requirements: 1.2, 1.3, 1.4, 1.12, 2.1, 2.2, 2.3, 2.4, 2.5, 2.8, 2.9, 9.4; design "ingest.py"_

  - [x] 5.2 Implement the `SkipCounter`
    - Add the `SkipCounter` dataclass (`truncated`, `unparseable`, `total`) counting
      each skipped line at most once; truncated lines are not offered to parsers
    - _Requirements: 4.1, 4.2, 4.5, 9.4; design "Skip counting"_

  - [x]* 5.3 Write property test for ascending line numbers
    - **Property 4: Ingest emits contiguous ascending line numbers**
    - **Validates: Requirements 2.1, 2.9**

  - [x]* 5.4 Write property test for gzip/plaintext agreement
    - **Property 5: Gzip and plaintext ingest agree**
    - **Validates: Requirements 2.2, 2.3**

  - [x]* 5.5 Write property test for the line cap
    - **Property 6: No line longer than the cap is ever handed to a parser**
    - **Validates: Requirements 2.4, 2.5, 9.4**

  - [x]* 5.6 Write unit tests for ingest edge cases
    - Assert directory recursion, nonexistent path raises, bad gzip raises
      `IngestError` and remaining files continue
    - _Requirements: 1.2, 1.3, 2.8_

- [x] 6. Implement the Parser protocol and parsers
  - [x] 6.1 Define the `Parser` protocol in `parsers/base.py`
    - Declare the `runtime_checkable Parser` Protocol with `log_type` and pure
      `parse(raw_line) -> Event | None` (no I/O, never raises, return None on miss)
    - _Requirements: 3.4, 3.5, 3.6; design "parsers/base.py"_

  - [x] 6.2 Implement the nginx parser
    - `parsers/nginx.py`: one precompiled bounded regex at import; populate required
      Event fields, optional fields `None` when absent, `log_type` = registry key;
      register with `@register_parser("nginx")`; normalize timestamp via the helper
    - _Requirements: 3.1, 3.2, 3.3, 3.7, 3.8, 3.12, 9.1, 9.2_

  - [x]* 6.3 Write unit tests for the nginx parser
    - Well-formed line asserts Event fields; malformed line returns None (no
      exception); over-long line truncation handling
    - _Requirements: 3.1, 3.2, 3.4, 3.5_

  - [x] 6.4 Implement the Apache parser
    - `parsers/apache.py`: bounded precompiled regex, same contract and registration
      (`@register_parser("apache")`)
    - _Requirements: 3.1, 3.2, 3.3, 3.7, 3.8, 3.12, 9.1, 9.2_

  - [x]* 6.5 Write unit tests for the Apache parser
    - Well-formed, malformed (None), and over-long cases
    - _Requirements: 3.1, 3.2, 3.4, 3.5_

  - [x] 6.6 Implement the syslog parser
    - `parsers/syslog.py`: bounded precompiled regex, same contract and registration
      (`@register_parser("syslog")`)
    - _Requirements: 3.1, 3.2, 3.3, 3.7, 3.8, 3.12, 9.1, 9.2_

  - [x]* 6.7 Write unit tests for the syslog parser
    - Well-formed, malformed (None), and over-long cases
    - _Requirements: 3.1, 3.2, 3.4, 3.5_

  - [x] 6.8 Implement the auth.log parser
    - `parsers/authlog.py`: bounded precompiled regex; capture fields needed by
      auth detectors (client_ip, user, mechanism); registration
      (`@register_parser("authlog")`)
    - _Requirements: 3.1, 3.2, 3.3, 3.7, 3.8, 3.12, 9.1, 9.2_

  - [x]* 6.9 Write unit tests for the auth.log parser
    - Well-formed, malformed (None), and over-long cases
    - _Requirements: 3.1, 3.2, 3.4, 3.5_

  - [x]* 6.10 Write property tests for parser totality and matched shape
    - **Property 1: Parsers are total and pure over arbitrary input**
    - **Validates: Requirements 3.4, 3.5, 3.6, 4.6**
    - **Property 2: Matched events have the required shape**
    - **Validates: Requirements 3.1, 3.2, 3.3**

- [x] 7. Checkpoint - foundations and parsers
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement synthetic fixtures
  - [x] 8.1 Create benign and signature fixtures with conftest loaders
    - Under `tests/fixtures/<format>/` add well-formed benign lines and recognition
      lines (SQLi/XSS probe paths, scanner user-agents, privilege-escalation and
      failed-login auth.log entries); add `conftest.py` pytest fixtures to load them;
      all IPs in documentation ranges, emails on `example.com`, credentials fake
    - _Requirements: 11.1, 11.2, 11.4, 11.5_

  - [x] 8.2 Create planted brute-force burst and planted request spike fixtures
    - Add a fixture whose failed-auth events for one client_ip reach/exceed the
      brute-force threshold within the window, and a fixture whose bucketed request
      counts reach/exceed the z-score threshold over the Baseline_Window
    - _Requirements: 11.3_

- [x] 9. Implement the Detector protocol and rule engine
  - [x] 9.1 Define the `Detector` protocol in `detections/base.py`
    - Declare `runtime_checkable Detector` Protocol with `rule_id` and pure
      `detect(events, config) -> list[Finding]` (no I/O, no alerting)
    - _Requirements: 7.1, 7.2; design "detections/base.py"_

  - [x] 9.2 Implement web signature detectors (SQLi, XSS, scanner UA)
    - In `detections/rules/signatures/`: `web.sqli.probe` (HIGH), `web.xss.probe`
      (HIGH), `web.scanner.ua` (MEDIUM); each a precompiled bounded regex; Findings
      name the matched signature in `detail` and include `source`, `line_number`,
      and matched value in `metadata`; register each by key
    - _Requirements: 5.1, 5.2, 5.3, 5.8, 5.9, 7.1, 7.2, 9.1, 9.2_

  - [x]* 9.3 Write positive + false-positive tests for web signature detectors
    - Positive: assert rule_id, severity, detail, metadata and no unexpected finding
      against recognition fixtures; guardrail: benign fixture yields zero findings
    - _Requirements: 5.1, 5.2, 5.3, 11.4, 11.5_

  - [x] 9.4 Implement auth.log signature detectors (failed login, privilege escalation)
    - `auth.failed_login` (LOW/MEDIUM) with `client_ip`, `user`, `source`,
      `line_number`; `auth.privesc` (HIGH) with `user`, mechanism, `source`,
      `line_number`; register each by key
    - _Requirements: 5.6, 5.7, 5.8, 5.9, 7.1, 7.2_

  - [x]* 9.5 Write positive + false-positive tests for auth.log detectors
    - Positive assertions on rule_id/severity/detail/metadata; benign guardrail zero
    - _Requirements: 5.6, 5.7, 11.4, 11.5_

  - [x] 9.6 Implement windowed detectors (brute force, status-code spike)
    - `auth.bruteforce` (HIGH): ≥ threshold failed-auth per client_ip within window
      (default 5/60s), deterministic half-open sliding window; metadata has
      client_ip, observed count, threshold, window. `web.status_spike` (MEDIUM):
      ≥ threshold error-status events within window (default 20/60s); metadata has
      count, threshold, window; register each by key
    - _Requirements: 5.4, 5.5, 5.8, 5.9, 5.10, 7.1, 7.2_

  - [x]* 9.7 Write positive + false-positive tests for windowed detectors
    - Positive: planted brute-force burst and status-spike fixtures assert the
      Finding and metadata; guardrail: below-threshold benign traffic yields zero
    - _Requirements: 5.4, 5.5, 5.10, 11.3, 11.4, 11.5_

  - [x] 9.8 Implement `Rule_Engine` in `detections/rules/engine.py`
    - Resolve registered signature detectors from the registry and run each over the
      event list, collecting Findings; each Finding carries exactly one Severity
    - _Requirements: 5.8, 5.9; design "Rule_Engine"_

  - [x]* 9.9 Write property tests for signature and windowed detections
    - **Property 8: Signature matches fire; benign input does not**
    - **Validates: Requirements 5.1, 5.2, 5.3**
    - **Property 9: Brute-force detection respects the window and threshold**
    - **Validates: Requirements 5.4, 5.10**
    - **Property 10: Status-code-spike detection respects the window and threshold**
    - **Validates: Requirements 5.5, 5.10**
    - **Property 11: Every Finding carries exactly one valid Severity**
    - **Validates: Requirements 5.8**

- [x] 10. Implement the statistical engine
  - [x] 10.1 Implement rate-spike detection (`zscore.py`, `rate_spike.py`)
    - Bucket events into `baseline_window_seconds` buckets; compute `statistics.mean`
      and `statistics.pstdev`; flag buckets with `z >= z_threshold`; yield nothing
      when fewer than two buckets or sigma == 0; stdlib `statistics` only
    - _Requirements: 6.1, 6.2, 6.3, 6.6, 6.8, 10.3_

  - [x] 10.2 Implement rare-event detection (`rare_event.py`)
    - Over a categorical series compute relative frequency; flag values strictly
      below `rare_cutoff`; yield nothing when fewer than `min_observations`; stdlib only
    - _Requirements: 6.1, 6.4, 6.7, 6.8, 10.3_

  - [x] 10.3 Implement `Statistical_Engine` and explainable metadata
    - `detections/statistical/engine.py` runs both detectors; every statistical
      Finding includes baseline value, observed value, score, and threshold in metadata
    - _Requirements: 6.5; design "Statistical_Engine"_

  - [x]* 10.4 Write direct stdlib statistics validation tests
    - Assert fixed inputs produce known mean, standard deviation, and z-score within
      absolute tolerance 1e-9; assert no core module imports numpy/pandas
    - _Requirements: 6.1, 6.8, 10.3, 11.6_

  - [x]* 10.5 Write positive + false-positive tests for statistical detectors
    - Positive: planted request-spike fixture scores anomalous; rare value flagged;
      guardrail: steady baseline and sufficiently-frequent values yield zero findings
    - _Requirements: 6.3, 6.4, 6.6, 6.7, 11.3, 11.4, 11.5_

  - [x]* 10.6 Write property tests for statistical math and explainability
    - **Property 12: Rate-spike detection matches the stdlib statistics computation**
    - **Validates: Requirements 6.1, 6.3, 6.6**
    - **Property 13: Rare-event detection matches relative frequency and the observation guard**
    - **Validates: Requirements 6.4, 6.7**
    - **Property 14: Statistical findings are explainable**
    - **Validates: Requirements 6.5**

- [x] 11. Checkpoint - detections complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Implement the aggregator
  - [x] 12.1 Implement `aggregate` in `aggregator.py`
    - Merge findings sharing `(rule_id, dedup_key)` with event union; group by
      rule_id; order by Severity `critical → info` with deterministic secondary sort
      (rule_id, then earliest contributing event `(source, line_number)`)
    - _Requirements: 7.3, 7.4, 7.5, 7.6; design "aggregator.py"_

  - [x]* 12.2 Write property tests for aggregation
    - **Property 15: Aggregation merges duplicates and unions their events**
    - **Validates: Requirements 7.3, 7.6**
    - **Property 16: Aggregation ordering is deterministic and severity-ranked**
    - **Validates: Requirements 7.4, 7.5**

- [x] 13. Implement outputs
  - [x] 13.1 Define the `Output` protocol in `outputs/base.py`
    - Declare the `runtime_checkable Output` Protocol with
      `render(findings, target)`; establish the output boundary where every string
      is masked then control-stripped via Security_Helpers before rendering
    - _Requirements: 8.4, 8.7, 8.8, 8.9, 8.10, 8.14; design "outputs/base.py"_

  - [x] 13.2 Implement the console table output
    - `outputs/console.py`: terminal table to stdout; mask then strip control chars
      on every string; register `@register_output("console")`
    - _Requirements: 8.1, 8.4, 8.7, 8.8, 8.9, 8.10, 8.14_

  - [x] 13.3 Implement the JSON file output
    - `outputs/file_json.py`: structured JSON written via atomic write to the
      resolved, canonical path with restrictive permissions; mask + strip before
      write; register `@register_output("json")`
    - _Requirements: 8.2, 8.4, 8.6, 8.7, 8.8, 8.9, 8.10, 8.11, 8.13, 8.14_

  - [x]* 13.4 Write unit tests for console and JSON outputs
    - Assert control chars stripped, secrets/PII masked, JSON written atomically, no
      raw sensitive value on disk
    - _Requirements: 8.1, 8.2, 8.4, 8.6, 8.10_

  - [x]* 13.5 Write property test for no raw sensitive value reaching a report file
    - **Property 22: No raw sensitive value reaches a report file**
    - **Validates: Requirements 8.10**

  - [x]* 13.6 Implement the optional CSV output
    - `outputs/file_csv.py`: CSV with `csv_safe` formula neutralization, atomic
      write, masking + stripping; register `@register_output("csv")`
    - _Requirements: 8.3, 8.5, 8.6, 8.14_

- [x] 14. Implement the pipeline
  - [x] 14.1 Implement `pipeline.run` in `pipeline.py`
    - Discover inputs → iterate capped lines → select parser (override or
      auto-detect by sampling, deterministic registry order) → parse to Events →
      run Rule_Engine and Statistical_Engine → aggregate; return `RunResult`
      (findings, `SkipCounter`, `mixed_timezones` flag); resolve plugins by key only
    - Emit a single mixed-timezone warning via `logging` when a run produced both
      aware and naive events
    - _Requirements: 1.5, 1.6, 3.9, 3.10, 4.1, 4.2, 4.3, 5.9, 8.14; design "pipeline.py"_

  - [x]* 14.2 Write integration tests for the pipeline
    - Assert auto-detection and `--format`-equivalent override, skipped-line totals
      surfaced in the result, mixed-timezone warning emitted, registry resolution
    - _Requirements: 1.5, 1.6, 3.9, 4.3_

- [x] 15. Implement the CLI and wire everything together
  - [x] 15.1 Implement `cli.main` with argparse and config validation
    - Parse input paths, `--format`, output selection (`--report` JSON, optional
      `--csv`), and detection/line-cap overrides; validate config before ingest
      (line cap, z-threshold, rare-cutoff); reject unknown `--format`; handle
      nonexistent/unreadable/no-input/empty-set paths with stderr errors
    - Build `RunConfig`, call `pipeline.run`, render selected outputs, and map exit
      codes: 0 clean, 1 findings, 2 error
    - _Requirements: 1.1, 1.7, 1.8, 1.9, 1.10, 1.11, 1.13, 1.14, 2.7, 4.3, 6.3, 6.4, 8.2, 8.3, 8.12_

  - [x]* 15.2 Write CLI integration tests
    - Assert the three distinct exit codes, read-only input guarantee, unrecognized
      format and invalid-config errors on stderr, skipped-line count in output
    - _Requirements: 1.7, 1.10, 1.12, 1.13, 1.14, 2.7, 4.3_

- [x] 16. Final checkpoint - full suite green
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional (test tasks and the optional CSV output per
  Requirement 8.3) and can be skipped for a faster MVP; core implementation tasks
  are never optional.
- Each task references the specific requirement sub-clauses and/or design sections
  it implements for traceability.
- Property-based tests use Hypothesis (minimum 100 iterations each) and are placed
  next to the code they validate; each is annotated with its design property number
  and the requirement clause it checks.
- Positive and false-positive guardrail tests accompany every detector; the stdlib
  `statistics` path is validated directly within 1e-9 tolerance (Requirement 11.6).
- Checkpoints provide incremental validation at natural boundaries.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1", "3.1", "3.2", "4.1"] },
    { "id": 2, "tasks": ["1.3", "1.4", "2.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "4.2", "5.1", "5.2", "9.1"] },
    { "id": 3, "tasks": ["1.5", "5.3", "5.4", "5.5", "5.6", "6.1", "6.4", "6.6", "6.8"] },
    { "id": 4, "tasks": ["6.2", "6.3", "6.5", "6.7", "6.9", "8.1", "8.2", "10.1", "10.2"] },
    { "id": 5, "tasks": ["6.10", "9.2", "9.4", "9.6", "10.3", "12.1", "13.1"] },
    { "id": 6, "tasks": ["9.3", "9.5", "9.7", "9.8", "10.4", "10.5", "12.2", "13.2", "13.3", "13.6"] },
    { "id": 7, "tasks": ["9.9", "10.6", "13.4", "13.5", "14.1"] },
    { "id": 8, "tasks": ["14.2", "15.1"] },
    { "id": 9, "tasks": ["15.2"] }
  ]
}
```
