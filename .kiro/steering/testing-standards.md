---
inclusion: fileMatch
fileMatchPattern: 'tests/**|**/test_*.py|**/*_test.py'
---

# Testing Standards

## Framework and workflow

- Test with **pytest**.
- Work **test-first (TDD)**: for a new parser, signature, or statistical
  detector, write a failing test against a fixture before the implementation,
  then make it pass.
- Tests mirror the source tree (`tests/parsers/`, `tests/detections/`,
  `tests/outputs/`) as described in `structure.md`.
- Keep tests fast and deterministic. The statistical tests use fixed synthetic
  data, not randomness; if randomness is needed, seed it.

## Fixtures

- Sample logs live in `tests/fixtures/<format>/` and are loaded via pytest
  fixtures defined in `conftest.py`.
- **Fixtures contain only synthetic data per `security.md`:** documentation IP
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com`
  emails, and obviously fake tokens. No real PII or secrets, ever.
- Attack-shaped fixture lines exist to prove the analyzer *recognizes* attacks.
  They are log lines, not runnable exploits.

## Per-component tests

### Parsers

- Feed a fixture line, assert the resulting `Event` fields.
- Cover: a well-formed line, a malformed line (expect `None`, no exception), and
  an over-long line (expect truncation handling).

### Rule / signature engine

- Feed known-malicious sample lines (SQLi/XSS probe strings, brute-force
  sequences, privilege-escalation entries) and assert the expected `Finding`,
  severity, and matched metadata.
- These samples are recognition fixtures only.

### Statistical engine

- Build synthetic baselines (e.g. a steady request rate) and assert that an
  injected spike or rare event scores as anomalous.
- Validate the **stdlib `statistics`** path directly: known inputs -> known
  mean/stdev -> known z-score.
- If the optional `[stats]` accelerated path is present, assert it agrees with
  the stdlib path within tolerance; skip (don't fail) when the extra isn't
  installed (`pytest.importorskip`).

### Outputs

- Assert control characters are stripped, CSV fields with leading
  `= + - @` are neutralized, and secrets/PII are masked in rendered findings.

## Positive and negative coverage

Every detection needs both:

- **Positive:** the malicious/anomalous fixture produces the expected finding.
- **False-positive guardrail:** representative *benign* traffic produces **no**
  finding. This is as important as the positive case — a detector that fires on
  normal traffic is not shippable.

## Coverage expectations

- All parsers, signatures, and statistical detectors carry positive and
  false-positive tests.
- `security.py` helpers (masking, sanitization, formula neutralization, line
  caps) have direct unit tests.
- Aim high on line/branch coverage for `parsers/`, `detections/`, and
  `outputs/`; treat a drop as a regression.
