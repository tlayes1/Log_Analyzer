# Requirements Document

## Introduction

`loganalyze` is a batch command-line tool that ingests system and web server logs,
recognizes known-attack signatures and statistical anomalies, and reports
suspicious activity with explainable, safely-rendered findings. A single
invocation analyzes a bounded set of input (one file or a directory tree) and
exits with a code reflecting the outcome, so the tool composes with shell
pipelines and cron.

This document defines v1 requirements. It is derived from and consistent with the
steering files in `.kiro/steering/`:

- **product.md** — execution model, in-scope log families, hybrid detection, and
  non-goals (no streaming, no external alert sinks, no ML, not an exploitation
  tool).
- **tech.md** — Python 3.10+, standard-library-only core (an optional
  `loganalyze[stats]` extra using `numpy`/`pandas` is noted as future work, not
  part of v1), `argparse` CLI, console entry point.
- **structure.md** — the ingest → parse → normalized `Event` → detect
  (rules + statistical) → aggregate → output pipeline, and the parser/detector/
  output plugin registration pattern.
- **security.md** — line-length caps before regex, ReDoS-safe precompiled
  regexes, no dynamic code execution on log-derived data, control-character
  stripping, CSV formula-injection neutralization, safe/atomic file writes, and
  PII/secret masking. These rules are binding and non-negotiable.
- **detection-rules.md** — the normalized `Event` schema, `Severity` levels, the
  explainable `Finding` shape, and the catalog of rule and statistical
  detections.
- **coding-conventions.md** — typing, docstrings, logging, pure parsers, and
  pure detectors.
- **testing-standards.md** — pytest, TDD, synthetic-only fixtures, positive and
  false-positive guardrail coverage, and direct validation of the stdlib
  `statistics` path.

Attack signatures in this project exist only to *recognize* malicious activity in
logs. This tool is not an exploitation tool and contains no payload generators or
offensive tooling (per `product.md` and `detection-rules.md`).

## Glossary

- **LogAnalyze**: The overall batch CLI tool and the top-level system under
  specification.
- **CLI**: The command-line interface component (`cli.py`) that parses arguments,
  resolves input paths, selects formats and outputs, and sets the process exit
  code.
- **Ingest**: The component (`ingest.py`) that turns an input path into an ordered
  stream of `(source, line_number, raw_line)` records, including directory
  discovery, gzip decompression, and line-length capping.
- **Parser**: A pluggable, pure component (one module per log format under
  `parsers/`) that converts a single raw line of a specific format into a
  normalized `Event`, or signals "unparseable".
- **Event**: The normalized record emitted by a Parser, with the fields defined in
  `detection-rules.md` (`timestamp`, `source`, `log_type`, `host`, `client_ip`,
  `user`, `method`, `path`, `status`, `message`, `raw`, `fields`).
- **Rule_Engine**: The signature/rule detection engine (`detections/rules/`) that
  matches `Event`s against predefined patterns and thresholds.
- **Statistical_Engine**: The anomaly detection engine
  (`detections/statistical/`) that computes baselines and anomaly scores using the
  Python standard-library `statistics` module.
- **Detector**: A Rule_Engine signature or Statistical_Engine detector that
  consumes `Event`s and yields `Finding`s.
- **Finding**: The explainable detection result defined in `detection-rules.md`
  (`rule_id`, `title`, `severity`, `events`, `detail`, `metadata`).
- **Severity**: The enumerated level of a Finding: `info`, `low`, `medium`,
  `high`, `critical`.
- **Aggregator**: The component (`aggregator.py`) that deduplicates, groups, and
  ranks Findings by severity.
- **Output_Renderer**: An output plugin (`outputs/`) that renders Findings to a
  destination (console table, JSON file, human-readable report file, or CSV).
- **Security_Helpers**: The shared sanitization and masking module (`security.py`)
  providing line caps, control-character stripping, CSV neutralization, and
  PII/secret masking.
- **MAX_LINE_BYTES**: The configurable line-length cap (default 64 KiB) enforced by
  Ingest before any regex runs.
- **Baseline_Window**: The explicit time-bucket size (e.g. per-minute) over which
  the Statistical_Engine computes counts for baselining.
- **Documentation_IP_Range**: Reserved IP ranges used for synthetic fixtures:
  `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.

## Requirements

### Requirement 1: Command-line invocation and input selection

**User Story:** As an operator, I want to invoke the tool against a file or
directory from the command line, so that I can analyze logs in a single batch run
that fits shell pipelines and cron.

#### Acceptance Criteria

1. THE CLI SHALL parse command-line arguments using the standard-library `argparse` module.
2. WHEN the CLI is invoked with a path to a single file, THE Ingest SHALL read that file as the input set.
3. WHEN the CLI is invoked with a path to a directory, THE Ingest SHALL recursively discover every regular file within that directory tree and use them as the input set.
4. WHEN the CLI is invoked with more than one input path, THE Ingest SHALL process all provided paths within the same run.
5. WHERE the user supplies no `--format` argument, THE CLI SHALL auto-detect the format of each input by attempting each registered Parser and using the first Parser that returns a non-None Event for the input's sampled lines.
6. WHERE the user supplies a `--format` argument naming a registered Parser, THE CLI SHALL use that Parser as an override for all input instead of auto-detecting.
7. IF the user supplies a `--format` argument that names no registered Parser, THEN THE CLI SHALL report an unrecognized-format error on standard error and set the error exit code.
8. IF the CLI is invoked with an input path that does not exist, THEN THE CLI SHALL report a path error on standard error and set the error exit code.
9. IF the CLI is invoked with an input path that exists but cannot be read, THEN THE CLI SHALL report a read error on standard error and set the error exit code.
10. IF the CLI is invoked with no input path, THEN THE CLI SHALL report a usage error on standard error and set the error exit code.
11. IF the resolved input set contains no readable file, THEN THE CLI SHALL report a no-input-found error on standard error and set the error exit code.
12. THE LogAnalyze SHALL treat all input logs as read-only and SHALL NOT modify any file that is read. (Negative form is required: the read-only guarantee is the requirement.)
13. WHEN a run completes without any Finding, THE CLI SHALL set a clean-run exit code distinct from the findings-produced exit code and distinct from the error exit code.
14. WHEN a run completes and at least one Finding is produced, THE CLI SHALL set a findings-produced exit code distinct from the clean-run exit code and distinct from the error exit code.

### Requirement 2: Ingest, decompression, and line-length capping

**User Story:** As a security analyst, I want the tool to read plain and gzipped
logs safely and resist pathological lines, so that a single malformed or oversized
line cannot stall or crash the analysis.

#### Acceptance Criteria

1. THE Ingest SHALL emit a stream of `(source, line_number, raw_line)` records for each input file in ascending `line_number` order, starting at line number 1 and incrementing by 1 for each successive line.
2. WHEN an input file is gzip-compressed, THE Ingest SHALL decompress the file and emit line records from the decompressed content.
3. WHEN an input file is not gzip-compressed, THE Ingest SHALL read the file directly as text and emit its line records.
4. WHILE reading any input line, THE Ingest SHALL enforce the MAX_LINE_BYTES cap before any regex is applied to that line.
5. IF the byte length of an input line exceeds MAX_LINE_BYTES, THEN THE Ingest SHALL mark the line as truncated, and THE LogAnalyze SHALL skip that line and count it among the skipped lines with the reason `truncated`.
6. WHERE the user supplies a line-length-cap configuration value that is an integer of at least 1, THE Ingest SHALL use that value as MAX_LINE_BYTES instead of the 65536-byte (64 KiB) default.
7. IF the user supplies a line-length-cap configuration value that is not an integer of at least 1, THEN THE Ingest SHALL reject the value, report an error indicating the line-length cap is invalid, and SHALL NOT begin ingesting input.
8. IF decompression of a gzip-compressed input file fails, THEN THE Ingest SHALL stop emitting records for that file, report an error indicating the file could not be decompressed, and continue processing the remaining input files.
9. THE Ingest SHALL preserve the originating source path and line number on each emitted record.

### Requirement 3: Pluggable parsers and the normalized event model

**User Story:** As a developer, I want each log format handled by a pure,
registered parser that emits a normalized event, so that detectors share one
contract and new formats are added without editing the pipeline.

#### Acceptance Criteria

1. WHEN a Parser receives a raw line that matches its format, THE Parser SHALL return an Event in which `timestamp`, `source`, `log_type`, `message`, `raw`, and `fields` are populated.
2. WHEN a field among `host`, `client_ip`, `user`, `method`, `path`, and `status` is absent from the matched line, THE Parser SHALL set that field to None on the returned Event.
3. WHEN a Parser returns an Event, THE Parser SHALL set the Event's `log_type` equal to the registry key under which the Parser is registered.
4. WHEN a Parser receives a raw line that does not match its format, THE Parser SHALL return None.
5. IF a Parser receives a malformed line, THEN THE Parser SHALL return None rather than raising an exception.
6. THE Parser SHALL operate as a pure function of its input line, performing no file or network input/output, reading no mutable global state, and returning an identical result for an identical input line.
7. WHEN a Parser normalizes a timestamp that carries an explicit UTC offset or Z designator, THE Parser SHALL convert the timestamp to UTC.
8. WHEN a Parser normalizes a timestamp that carries no timezone information, THE Parser SHALL record the timestamp as a local datetime with no offset applied.
9. WHEN a single run produces both timezone-aware timestamps (converted to UTC) and timezone-naive timestamps (no offset), THE LogAnalyze SHALL emit a warning indicating that mixed timezone-aware and naive timestamps were encountered.
10. WHERE a parser module is registered under a registry key, THE LogAnalyze SHALL make that Parser selectable by its key without changes to the pipeline module.
11. IF two parser modules are registered under the same registry key, THEN THE LogAnalyze SHALL report a registration conflict rather than silently overriding one Parser.
12. THE LogAnalyze SHALL provide Parsers for nginx access logs, Apache access logs, Linux `auth.log`, and syslog in v1.

### Requirement 4: Malformed-line counting

**User Story:** As an analyst, I want malformed lines skipped and counted rather
than fatal, so that a damaged log still produces a usable report with visibility
into how much was skipped.

#### Acceptance Criteria

1. WHEN a line is not parsed by any applicable Parser (every applicable Parser returns None per Requirement 3), THE LogAnalyze SHALL skip that line and continue processing the remaining lines in the same input set.
2. THE LogAnalyze SHALL maintain a per-run counter of skipped malformed lines that is incremented by exactly one for each skipped line, counting each skipped line at most once regardless of how many Parsers were applied to it.
3. WHEN a run completes, THE LogAnalyze SHALL include the final per-run count of skipped malformed lines in the run output.
4. WHEN a run processes no malformed line, THE LogAnalyze SHALL report a skipped-malformed-line count of zero.
5. THE LogAnalyze SHALL count both unparseable lines and lines truncated by the MAX_LINE_BYTES cap among the skipped lines reported for the run.
6. IF a line is malformed, THEN THE LogAnalyze SHALL NOT terminate the run as a result of that line. (Negative form is required: non-fatal handling of malformed input is the requirement.)

### Requirement 5: Rule and signature detections

**User Story:** As an incident responder, I want signature detections for known
attack patterns, so that scanning, injection probes, brute force, and privilege
escalation are surfaced with severity and explanation.

#### Acceptance Criteria

1. WHEN an Event from an nginx or Apache log has a request path matching a precompiled SQL-injection probe signature, THE Rule_Engine SHALL yield a Finding identifying a SQL-injection probe whose `detail` names the matched signature and whose `metadata` includes the `source`, `line_number`, and matched `path`.
2. WHEN an Event from an nginx or Apache log has a request path matching a precompiled cross-site-scripting probe signature, THE Rule_Engine SHALL yield a Finding identifying a cross-site-scripting probe whose `detail` names the matched signature and whose `metadata` includes the `source`, `line_number`, and matched `path`.
3. WHEN an Event from an nginx or Apache log has a user agent matching a precompiled scanner user-agent signature, THE Rule_Engine SHALL yield a Finding identifying scanner activity whose `detail` names the matched signature and whose `metadata` includes the `source`, `line_number`, and matched user-agent value.
4. WHEN the count of failed authentication Events for the same `client_ip` reaches or exceeds the configured brute-force threshold (default 5 failed authentication events) within the configured brute-force window (default 60 seconds), THE Rule_Engine SHALL yield a brute-force Finding whose `metadata` includes the `client_ip`, the observed count, the configured threshold, and the window duration in seconds.
5. WHEN the count of HTTP error-status Events reaches or exceeds the configured status-code-spike threshold (default 20 HTTP error-status events) within the configured status-code-spike window (default 60 seconds), THE Rule_Engine SHALL yield a status-code-spike Finding whose `metadata` includes the observed count, the configured threshold, and the window duration in seconds.
6. WHEN an `auth.log` Event indicates a failed login, THE Rule_Engine SHALL yield a failed-login Finding whose `metadata` includes the `client_ip`, `user`, `source`, and `line_number`.
7. WHEN an `auth.log` Event indicates privilege escalation to root via `sudo` or `su`, THE Rule_Engine SHALL yield a privilege-escalation Finding whose `metadata` includes the `user`, the escalation mechanism (`sudo` or `su`), `source`, and `line_number`.
8. THE Rule_Engine SHALL assign each Finding exactly one Severity drawn from the enumeration `info`, `low`, `medium`, `high`, `critical`.
9. WHERE a signature is registered under a registry key, THE LogAnalyze SHALL apply that signature without changes to the pipeline module.
10. WHERE the user supplies no brute-force threshold or window, THE Rule_Engine SHALL apply a brute-force threshold of 5 failed authentication events over a 60-second window; and WHERE the user supplies no status-code-spike threshold or window, THE Rule_Engine SHALL apply a status-code-spike threshold of 20 HTTP error-status events over a 60-second window.

### Requirement 6: Statistical detections

**User Story:** As an analyst, I want statistical anomaly detection against a
rolling baseline, so that rate spikes and rare events are flagged even when no
signature matches.

#### Acceptance Criteria

1. THE Statistical_Engine SHALL compute baselines and anomaly scores using the standard-library `statistics` module (`mean`, `pstdev`/`stdev`, `quantiles`).
2. THE Statistical_Engine SHALL bucket Events into fixed-duration Baseline_Window buckets whose default duration is 60 seconds and which is configurable.
3. WHEN bucketed Event counts over the Baseline_Window produce a z-score at or above the configured z-score threshold (default 3.0, configurable within the inclusive range 1.0 to 10.0), THE Statistical_Engine SHALL yield a rate-spike Finding.
4. WHEN a categorical value (such as a status code or a user on a host) occurs with a relative frequency strictly below the configured rare-event cutoff (default 0.01, configurable within the exclusive range 0.0 to 1.0), THE Statistical_Engine SHALL yield a rare-event Finding.
5. THE Statistical_Engine SHALL include the baseline value, observed value, score, and threshold in each statistical Finding's metadata.
6. IF fewer than two baseline buckets are available or the baseline standard deviation is zero, THEN THE Statistical_Engine SHALL yield no rate-spike Finding for that series.
7. IF fewer than the configured minimum number of observations are available for a categorical series, THEN THE Statistical_Engine SHALL yield no rare-event Finding for that series.
8. THE Statistical_Engine SHALL compute all statistical detections using only the Python standard library and SHALL NOT require `numpy` or `pandas`. (Negative form is required: the stdlib-only guarantee for v1 is the requirement.)

### Requirement 7: Explainable, aggregated findings

**User Story:** As a reviewer, I want findings that explain what matched and are
deduplicated and ranked, so that I can verify and prioritize them quickly.

#### Acceptance Criteria

1. THE Detector SHALL produce each Finding with the fields `rule_id`, `title`, `severity`, `events`, `detail`, and `metadata` defined in `detection-rules.md`.
2. THE Detector SHALL populate the `detail` field of each Finding with a human-readable statement of what matched, the `metadata` field with the matched values, and the `events` field with the references to the contributing Event records.
3. WHEN two or more Findings share the same `rule_id` and the same deduplication key, THE Aggregator SHALL merge them into a single Finding whose `events` field contains the union of the contributing Event references.
4. THE Aggregator SHALL order Findings by Severity from `critical` to `info` following the enumeration order `critical`, `high`, `medium`, `low`, `info`.
5. IF two or more Findings have equal Severity, THEN THE Aggregator SHALL apply a deterministic secondary ordering so that identical input sets of Findings always yield the same output order.
6. THE Aggregator SHALL group Findings that share the same `rule_id` into a single group.

### Requirement 8: Output rendering and output safety

**User Story:** As an operator, I want findings rendered to a console table and a
structured file with all attacker-controlled text neutralized, so that reports are
usable and cannot inject terminal escapes, spreadsheet formulas, or leaked
secrets.

#### Acceptance Criteria

1. THE Output_Renderer SHALL render Findings as a terminal table on the console.
2. WHEN the user requests a JSON report, THE Output_Renderer SHALL write the Findings to a structured JSON file at the resolved output path.
3. WHERE the user requests CSV output, THE Output_Renderer SHALL write the Findings to a CSV file at the resolved output path.
4. WHEN rendering any Finding text to console or file, THE Output_Renderer SHALL preserve the tab character and SHALL replace every other control character (code points U+0000 through U+0008, U+000B through U+001F, and U+007F) with the Unicode replacement character (U+FFFD).
5. WHEN writing a CSV field whose first character is `=`, `+`, `-`, or `@`, THE Output_Renderer SHALL prefix the field with a single apostrophe so the destination spreadsheet does not evaluate the field as a formula.
6. WHEN writing a report file, THE Output_Renderer SHALL write the complete content to a temporary file and SHALL atomically replace the destination with that temporary file, so an interrupted run leaves either the prior file or the fully written file and never a partial report.
7. WHEN rendering a Finding, THE Output_Renderer SHALL mask credential-like string values (passwords, API keys, tokens, session identifiers, and authorization-header values) at the output boundary such that a masked value of 4 or fewer characters reveals no original characters and a masked value longer than 4 characters reveals at most its first 2 and last 2 characters.
8. WHEN rendering a Finding, THE Output_Renderer SHALL mask email addresses at the output boundary such that a masked email address reveals at most the first character of the local part and the full domain, masking the remainder of the local part.
9. WHEN rendering a Finding, THE Output_Renderer SHALL mask client IP addresses at the output boundary (where policy requires masking) such that a masked client IP address reveals at most its first 2 octets.
10. THE Output_Renderer SHALL NOT write any raw unmasked value of the sensitive categories in criteria 7, 8, and 9 to a report file. (Negative form is required: the no-leak-to-disk guarantee is the requirement.)
11. WHERE an output path is resolved, THE Output_Renderer SHALL resolve the path to its canonical absolute form and SHALL create the file with the most restrictive permissions the platform supports.
12. THE Output_Renderer SHALL NOT follow or write to any output path whose value is derived from log content. (Negative form is required: the prohibition on log-content-derived paths is the requirement.)
13. IF a resolved output path cannot be written (the path is invalid, the location is not writable, or the atomic replace fails), THEN THE Output_Renderer SHALL leave any pre-existing destination file unchanged, SHALL remove the temporary file, and SHALL report a write error to the caller.
14. WHERE an Output_Renderer is registered under a registry key, THE LogAnalyze SHALL make that renderer selectable without changes to the pipeline module.

### Requirement 9: Untrusted-input safety across the pipeline

**User Story:** As a security-conscious maintainer, I want every regex bounded and
no log-derived data executed, so that malicious log content cannot cause denial of
service or code execution.

#### Acceptance Criteria

1. THE LogAnalyze SHALL precompile every regular expression used by Parsers and the Rule_Engine at module import time.
2. THE LogAnalyze SHALL ensure that every regular expression applied to log-derived text uses only bounded quantifiers and contains no nested quantifier that can match the same input position more than one way, so that matching time grows at most linearly in the length of the capped line.
3. THE LogAnalyze SHALL NOT pass log-derived data to `eval`, `exec`, `compile`, `pickle.loads`, `os.system`, a shell, or any dynamic import keyed on log content. (Negative form is required: prohibiting dynamic code execution on untrusted input is the security requirement.)
4. WHEN a line is truncated by the MAX_LINE_BYTES cap, THE LogAnalyze SHALL record that line as skipped with the reason `truncated` and continue processing subsequent lines.
5. THE Security_Helpers SHALL provide the shared line-cap, control-character stripping, CSV neutralization, and PII/secret masking functions used by Ingest, detections, and outputs.

### Requirement 10: Non-goals and defensive scope

**User Story:** As a stakeholder, I want v1 scope boundaries enforced, so that the
tool stays a batch defensive analyzer and does not drift into streaming, alerting,
ML, or offensive tooling.

#### Acceptance Criteria

1. WHEN the LogAnalyze finishes processing a finite input set of one or more files supplied at invocation, THE LogAnalyze SHALL terminate, and SHALL NOT run as a daemon, poll for new input, or tail logs live after the input set is consumed. (Negative form is required: the no-streaming boundary is a product non-goal.)
2. THE LogAnalyze SHALL emit each Finding only to the console and to local files, and SHALL NOT forward any Finding to external alert sinks such as webhook, Slack, email, or SIEM targets. (Negative form is required: the no-external-sink boundary is a product non-goal.)
3. THE Statistical_Engine SHALL compute anomaly scores using only classical statistics (means, standard deviations, z-scores, quantiles), and SHALL NOT train, load, or execute machine-learning models. (Negative form is required: the no-ML boundary is a product non-goal.)
4. THE LogAnalyze SHALL contain attack signatures solely as recognition patterns for detecting matching activity in logs, and SHALL NOT include payload generators or exploitation tooling. (Negative form is required: the defensive-only boundary is a product and detection-authoring non-goal.)

### Requirement 11: Testability and synthetic fixtures

**User Story:** As a developer practicing TDD, I want detectors validated against
synthetic fixtures with positive and false-positive coverage, so that detections
are proven to recognize attacks without firing on benign traffic and without any
real PII or secrets.

#### Acceptance Criteria

1. THE LogAnalyze test suite SHALL use only synthetic fixture data in which every IP address falls within a Documentation_IP_Range, every email address is on `example.com`, and every credential, token, or session value is non-authenticating.
2. THE LogAnalyze test suite SHALL NOT contain real PII or real secrets in any fixture. (Negative form is required: the no-real-data rule is a binding security requirement.)
3. THE LogAnalyze test suite SHALL include a fixture containing a planted brute-force burst that reaches or exceeds the configured brute-force threshold within the configured window, and a fixture containing a planted request spike that reaches or exceeds the configured rate-spike z-score threshold over the Baseline_Window.
4. WHEN a positive-detection test runs a Detector against its malicious or anomalous fixture, THE test SHALL assert the produced Finding's `rule_id`, Severity, `detail`, and `metadata`, and SHALL assert that no unexpected Finding is produced for that Detector.
5. WHEN a false-positive guardrail test runs a Detector against benign fixture traffic that is below every configured threshold for that Detector and matches no signature for that Detector, THE test SHALL assert that the Detector produces zero Findings.
6. THE LogAnalyze test suite SHALL validate the standard-library `statistics` path directly by asserting known inputs produce known mean, standard deviation, and z-score values within an absolute tolerance of 1e-9.
