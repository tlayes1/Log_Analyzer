---
inclusion: fileMatch
fileMatchPattern: '*.py|**/*.py'
---

# Coding Conventions

Applies to all Python source (`**/*.py`), including nested modules such as
`src/loganalyze/parsers/nginx.py` and
`src/loganalyze/detections/statistical/zscore.py`.

## Style and formatting

- Follow **PEP 8**.
- Format with **black** (default line length 88). Do not hand-fight the
  formatter.
- Lint with **ruff**; keep the tree warning-clean. Fix lint issues rather than
  blanket-ignoring them. A targeted `# noqa: CODE` with a reason is acceptable
  only when unavoidable.

## Type hints

- Type-annotate **all** public functions, methods, and dataclass fields.
- Use modern syntax: `str | None`, `list[Event]`, `dict[str, int]`.
- Prefer `Protocol` / ABCs for the parser, detector, and output interfaces so
  plugins stay decoupled (see `structure.md`).
- Code should pass a type checker (mypy/pyright) without new errors.

## Docstrings

- Use triple-quoted docstrings on every public module, class, and function.
- First line: an imperative one-liner ("Parse one nginx access-log line.").
- Document args, return value, and what counts as "unparseable" for parsers.

```python
def parse(self, raw_line: str) -> Event | None:
    """Parse one nginx access-log line into an Event.

    Args:
        raw_line: A single raw log line (already length-capped by ingest).

    Returns:
        A normalized Event, or None if the line does not match this format.
    """
```

## Error handling and logging

- Use the stdlib `logging` module via a module-level
  `logger = logging.getLogger(__name__)`. Never `print` for diagnostics.
- Keep the tool's own logging separate from the log content being analyzed.
- Catch narrow, expected exceptions; let unexpected ones surface. Do not wrap
  broad bodies in bare `except:`.
- A single malformed log line must never crash a run: a parser returns `None` for
  input it can't handle rather than raising.
- Never log secrets or unmasked PII; route sensitive values through the masking
  helpers before logging.

## Input validation (see `security.md`)

Security rules in `security.md` are binding for every `.py` file:

- Treat all log content as untrusted.
- Precompile regexes at module load; keep them bounded and non-backtracking.
- Never pass log-derived data to `eval`, `exec`, or a shell.
- Sanitize and mask at output boundaries.

## Keep parsers and detectors pure and testable

- **Parsers** are pure functions of their input line: no file/network I/O, no
  mutable global state. This makes them trivially unit-testable with fixtures.
- **Detectors** take events (and config) and yield findings; side effects
  (writing, alerting) belong in `outputs`, not detectors.
- Inject configuration; don't read environment or files from inside a detector.

## Good vs. bad

```python
# BAD — untyped, prints, I/O inside parser, unbounded regex, mutable global.
PAT = None
def parse(line):
    global PAT
    if PAT is None:
        PAT = re.compile(r"(.*) (.*) (.*)")   # unbounded, ambiguous
    open("debug.txt", "a").write(line)        # side effect in a parser
    print("parsing", line)                    # not logging
    return PAT.match(line).groups()           # crashes on no match

# GOOD — typed, pure, precompiled bounded regex, graceful miss.
logger = logging.getLogger(__name__)

_NGINX = re.compile(
    r"^(?P<ip>[0-9.]{7,15}) \S{1,64} \S{1,64} "
    r"\[(?P<ts>[^\]]{1,40})\] \"(?P<req>[^\"]{0,2048})\" "
    r"(?P<status>[0-9]{3}) (?P<size>[0-9]{1,12})"
)

def parse(raw_line: str) -> Event | None:
    """Parse one nginx access-log line into an Event, or None if it doesn't match."""
    m = _NGINX.match(raw_line)
    if m is None:
        return None
    return Event.from_match(m.groupdict())
```
