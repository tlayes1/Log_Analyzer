---
inclusion: always
---

# Security

Log data is attacker-influenced by nature: a log line can contain whatever a
remote client sent. Treat **every byte of every log as untrusted input**. These
rules apply across ingest, parsers, detections, and outputs, and are
non-negotiable.

## 1. Untrusted-input handling

### Line-length caps

Cap line length in `ingest` before any regex runs. A single pathological line
must not be able to exhaust memory or stall a regex.

```python
MAX_LINE_BYTES = 64 * 1024  # 64 KiB; configurable

def safe_lines(fh):
    for n, line in enumerate(fh, 1):
        if len(line) > MAX_LINE_BYTES:
            line = line[:MAX_LINE_BYTES]  # truncate, mark the event truncated
        yield n, line
```

### ReDoS-safe regexes

Untrusted input + a backtracking regex = denial of service. Required practices:

- **Precompile** every pattern at import time (`re.compile`).
- Use **bounded quantifiers** (`{0,255}`) instead of unbounded `+`/`*` on
  attacker-controlled spans.
- **No nested/ambiguous quantifiers** — the classic catastrophic-backtracking
  shape. Prefer specific character classes and anchors.

```python
# BAD — nested quantifier over untrusted span; catastrophic backtracking.
re.compile(r"^(\w+\s*)+$")

# GOOD — anchored, bounded, specific.
re.compile(r"^[\w.\-]{1,253}\s[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")
```

Keep a per-line regex budget; truncated or budget-exceeding lines are flagged,
not retried forever.

### No dynamic code execution

Never pass log-derived data to `eval`, `exec`, `compile`, `pickle.loads`,
`os.system`, `subprocess` with `shell=True`, or any dynamic import keyed on log
content. Parsers transform text into data; they never execute it.

```python
# BAD
severity = eval(fields["level"])          # log content -> code execution

# GOOD
severity = SEVERITY_MAP.get(fields["level"], Severity.INFO)
```

## 2. Output safety

Findings echo attacker-controlled text back into terminals, files, and
spreadsheets. Sanitize on the way out.

### Strip / escape control characters

Remove control characters (except `\t`) before writing to console or file, so log
content can't inject ANSI escapes, clear the screen, or forge output.

```python
import re
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

def clean(text: str) -> str:
    return _CTRL.sub("\ufffd", text)
```

### CSV / spreadsheet formula injection

A field beginning with `=`, `+`, `-`, or `@` is executed as a formula when opened
in a spreadsheet. Neutralize any exported field starting with those characters.

```python
def csv_safe(value: str) -> str:
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value          # prefix apostrophe disarms the formula
    return value
```

### Safe file writes

- Write to a temp file and atomically replace, so a crash can't leave a partial
  report.
- Resolve and validate output paths; never follow a path derived from log
  content.
- Create files with restrictive permissions where the platform supports it.

## 3. PII and secret masking

Logs contain personal data and credentials. Mask sensitive values in **findings
output** and in **any committed fixture**.

### Mask in findings

Redact or partially mask: passwords, API keys, tokens, session IDs, bearer/auth
headers, email addresses, and client IPs where policy requires. Show enough to be
useful, not enough to leak.

```python
def mask_secret(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:2] + "…" + value[-2:]   # "ab…yz"

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "x.x.x.x"
```

Apply masking at the output boundary so raw values never reach disk unmasked.

### Fixtures carry no real data

- **Never** commit real secrets, tokens, or real PII in `tests/fixtures/` or
  anywhere else.
- Sample logs use synthetic values: documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com` emails,
  and obviously fake tokens (`AKIAEXAMPLE…`).
- A real credential appearing in a diff is a blocking review failure.

## Summary checklist

- [ ] Line length capped before regex.
- [ ] Every regex precompiled, bounded, non-backtracking.
- [ ] No `eval`/`exec`/shell on log-derived data.
- [ ] Control characters stripped from all output.
- [ ] Exported CSV fields neutralized against formula injection.
- [ ] Secrets/PII masked in findings.
- [ ] Fixtures contain only synthetic, non-sensitive data.
