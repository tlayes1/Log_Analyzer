---
inclusion: fileMatch
fileMatchPattern: '**/detections/**|**/parsers/**|**/rules/**'
---

# Authoring Detections

This guide covers writing parsers, rule/signature detections, and statistical
detections against the normalized event model.

> **Defensive scope.** Attack material in this project — SQLi/XSS patterns,
> scanner signatures, brute-force logic — exists only as **detection patterns and
> sanitized fixture log lines for recognizing attacks in logs.** This project
> never contains exploit tooling, payload generators, or offensive instructions.
> If a change would help *carry out* an attack rather than *detect* one, do not
> make it.

## Normalized event schema

Every parser emits an `Event` with these fields (`models.py`):

| Field       | Type              | Meaning                                        |
|-------------|-------------------|------------------------------------------------|
| `timestamp` | `datetime`        | Event time (UTC-normalized when possible).     |
| `source`    | `str`             | Origin file / path.                            |
| `log_type`  | `str`             | Format key, e.g. `"nginx"`, `"authlog"`.       |
| `host`      | `str \| None`     | Host/service, when present.                    |
| `client_ip` | `str \| None`     | Remote address, when present.                  |
| `user`      | `str \| None`     | Account/username, when present.                |
| `method`    | `str \| None`     | HTTP method (web logs).                         |
| `path`      | `str \| None`     | Request path/URI (web logs).                    |
| `status`    | `int \| None`     | HTTP status (web logs).                          |
| `message`   | `str`             | Human-readable remainder / raw detail.          |
| `raw`       | `str`             | Original (length-capped) line.                  |
| `fields`    | `dict[str, str]`  | Format-specific extras.                          |

Detectors consume `Event`s and never re-parse `raw` unless a signature
specifically targets raw text.

## Severity levels

One line each:

- **info** — noteworthy context, not itself a problem.
- **low** — minor or likely-benign anomaly; worth noting, not acting on alone.
- **medium** — suspicious activity that merits review.
- **high** — likely malicious or clear policy violation; act promptly.
- **critical** — active compromise or severe impact; act immediately.

## Finding output shape

Detectors yield a `Finding` (`models.py`):

```python
@dataclass
class Finding:
    rule_id: str          # stable id, e.g. "web.sqli.probe"
    title: str            # short human summary
    severity: Severity    # enum above
    events: list[Event]   # supporting evidence
    detail: str           # why it matched (explainable)
    metadata: dict        # counts, thresholds, matched token, etc.
```

Findings are **explainable**: `detail`/`metadata` must say what matched and why.
All attacker-controlled strings in a `Finding` are masked and sanitized at the
output boundary per `security.md` (secret/PII masking, control-char stripping,
CSV formula neutralization) — detectors produce findings; `outputs` render them
safely.

## Authoring a rule / signature detection

A signature has: an id, a target (which events), a bounded precompiled pattern
and/or a threshold, a severity, and metadata.

```python
from loganalyze.registry import register_detector
from loganalyze.detections.base import Detector
from loganalyze.models import Event, Finding, Severity

# Bounded, precompiled, non-backtracking (see security.md).
_SQLI = re.compile(
    r"(?i)(?:\bunion\b.{0,40}\bselect\b|\bor\b\s+1=1|;--|/\*|\bsleep\s*\()",
)

@register_detector("web.sqli.probe")
class SqliProbe(Detector):
    """Flag SQL-injection probe strings in web request paths."""

    def detect(self, events: list[Event]) -> list[Finding]:
        out = []
        for e in events:
            if e.log_type in ("nginx", "apache") and e.path and _SQLI.search(e.path):
                out.append(Finding(
                    rule_id="web.sqli.probe",
                    title="Possible SQL-injection probe",
                    severity=Severity.HIGH,
                    events=[e],
                    detail="Request path matched an SQLi probe signature.",
                    metadata={"client_ip": e.client_ip, "path": e.path},
                ))
        return out
```

Web examples to cover: SQLi/XSS probes (recognition patterns), directory/port
scanning (many distinct paths or 404 bursts from one IP), brute force (repeated
auth failures), and status-code spikes (surge of 4xx/5xx). System examples:
failed logins (`auth.log` "Failed password"), privilege escalation (unexpected
`sudo`/`su` to root).

Threshold signatures (brute force) count events per key (e.g. `client_ip`) over a
window and fire when a bound is exceeded — put the count and window in
`metadata`.

## Authoring a statistical detection

Statistical detection is **stdlib-first**: compute baselines and anomaly scores
with the `statistics` module. The optional `[stats]` accelerated path must agree
with this one (see `structure.md`/`tech.md`).

```python
import statistics
from loganalyze.models import Severity

def zscore_anomalies(counts: list[float], threshold: float = 3.0):
    """Flag buckets whose z-score exceeds a threshold.

    counts: per-bucket metric (e.g. requests per minute).
    """
    if len(counts) < 2:
        return []
    mu = statistics.mean(counts)
    sigma = statistics.pstdev(counts)
    if sigma == 0:
        return []
    hits = []
    for i, c in enumerate(counts):
        z = (c - mu) / sigma
        if z >= threshold:
            sev = Severity.HIGH if z >= 5 else Severity.MEDIUM
            hits.append((i, round(z, 2), sev))
    return hits
```

Guidance:

- **Baseline window:** choose an explicit window/bucket size (e.g. per-minute
  request counts) and document it in `metadata`.
- **Rate spikes:** z-score on bucketed counts; `statistics.mean` +
  `statistics.pstdev`.
- **Rare events:** score infrequent categoricals (rare status codes, rare users
  on a host) using frequency; `statistics.quantiles` helps set cutoffs.
- Always include the baseline, observed value, score, and threshold in
  `metadata` so the finding is explainable.

## How findings reach output

`detections/*` yield `Finding`s -> `aggregator` dedupes, groups, and ranks by
severity -> `outputs/` render to **console** and **structured file** (JSON /
human-readable report). Alert sinks are a reserved future extension point; not in
v1.
