---
inclusion: always
---

# Product Overview

## What this is

`loganalyze` is a command-line log analyzer for security and operations work. It
ingests system and web server logs, flags anomalies and suspicious patterns, and
produces a report. It runs as a batch tool: you point it at a log file or a
directory, it analyzes the contents, writes its findings, and exits.

## Problem it solves

Logs record attacks and misbehavior, but the signal is buried in volume. Reading
raw access logs or `auth.log` by hand does not scale, and most teams do not have
a full SIEM for every host or side project. `loganalyze` closes that gap: it
applies known-attack signatures and statistical baselining to surface the lines
worth a human's attention, with enough context to act on.

## Who uses it

- Developers and operators triaging a suspicious spike on a server.
- Small teams without a dedicated SIEM who still want signature and anomaly
  coverage over their logs.
- Incident responders doing offline analysis of collected log files.

## Execution model

- **CLI batch tool.** One invocation analyzes a bounded set of input (a file or a
  directory tree) and terminates. It does not run as a daemon.
- Input is read-only. The tool never mutates the logs it reads.
- Exit code reflects outcome (clean vs. findings vs. error) so it composes with
  shell pipelines and cron.

## In scope (v1)

- **Log families:** web server access logs (nginx, Apache) and system logs
  (syslog, `auth.log`), through pluggable per-format parsers.
- **Hybrid detection:**
  - *Rule / signature* — predefined patterns and thresholds for known-bad
    behavior (scanning, brute force, injection probes, privilege escalation).
  - *Statistical* — baselines, rate spikes, and rare-event scoring computed with
    the Python standard library `statistics` module.
- **Output:** a console report plus a structured file (JSON and/or
  human-readable).

## Non-goals (v1)

- **No streaming / live tailing.** Batch only. Live `tail -f`-style monitoring is
  a future direction, not part of v1.
- **No external alert sinks.** Webhook, Slack, email, and SIEM forwarding are a
  reserved future extension point. v1 output is console and file only.
- **No machine-learning model training.** The statistical layer is classical
  (means, standard deviations, z-scores), not trained models.
- **Not an exploitation tool.** Attack signatures exist to *recognize* malicious
  activity in logs, never to generate or carry out attacks.

## Guiding principles

- **Explainable findings.** Every finding says what matched and why, so a human
  can verify it.
- **Safe by default.** All log content is untrusted input; see `security.md`.
- **Dependency-light core.** Core analysis runs on the Python standard library
  alone; heavier libraries are optional extras.
