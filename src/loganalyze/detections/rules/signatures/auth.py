"""Signature detectors for Linux ``auth.log`` authentication events.

This module hosts two pure, registry-wired signature detectors that key off the
normalized ``fields`` markers emitted by
:class:`~loganalyze.parsers.authlog.AuthlogParser` rather than re-parsing
``Event.raw`` (per ``detection-rules.md``):

* :class:`FailedLoginDetector` (``auth.failed_login``) — fires on any auth event
  the parser classified as a failed login (``fields["event"] == "failed_login"``),
  covering sshd "Failed password" lines and PAM authentication-failure lines.
  Severity ``MEDIUM`` (Requirements 5.6, 5.8).
* :class:`PrivilegeEscalationDetector` (``auth.privesc``) — fires on privilege
  escalation via ``sudo`` or ``su`` (``fields.get("mechanism")`` in
  ``{"sudo", "su"}``). Severity ``HIGH`` (Requirements 5.7, 5.8).

Both detectors are pure functions of their inputs: they inspect only the events
and injected configuration, perform no I/O, raise no alerts, and return an
identical result for identical inputs (Requirements 7.1, 7.2). Successful logins
and ordinary sessions produce no findings, so the benign guardrail fixture stays
silent (Requirement 5.9). This is defensive recognition only: the detectors
label activity already present in the logs and never carry out an attack.
"""

from __future__ import annotations

from loganalyze.config import DetectionConfig
from loganalyze.models import Event, Finding, Severity
from loganalyze.registry import register_detector

#: ``Event.fields["mechanism"]`` values that denote a privilege-escalation
#: attempt (``sudo`` or ``su``). The authlog parser sets this marker only on
#: escalation events, so membership is a sufficient discriminator.
_PRIVESC_MECHANISMS = frozenset({"sudo", "su"})


def _line_number(event: Event) -> str | None:
    """Return the event's ``line_number`` marker, if the parser supplied one.

    The :class:`~loganalyze.models.Event` model has no dedicated
    ``line_number`` attribute; provenance is associated by the pipeline. This
    helper surfaces a line number in finding metadata only when it is present on
    ``Event.fields`` and omits the key otherwise.

    Args:
        event: The event whose ``fields`` mapping may carry a ``"line_number"``.

    Returns:
        The line-number string when present on ``event.fields``, else ``None``.
    """
    return event.fields.get("line_number")


@register_detector("auth.failed_login")
class FailedLoginDetector:
    """Flag individual failed authentication attempts in ``auth.log``.

    The detector matches any event the authlog parser classified as a failed
    login (``fields["event"] == "failed_login"``), which the parser emits for
    sshd "Failed password" lines (including ``invalid user``) and for PAM
    authentication-failure lines. Each match yields one
    :class:`~loganalyze.models.Finding` at ``MEDIUM`` severity (Requirement
    5.6); the finding carries exactly one :class:`~loganalyze.models.Severity`
    (Requirement 5.8).

    Attributes:
        rule_id: The stable identifier ``"auth.failed_login"`` carried onto
            every finding this detector produces.
    """

    rule_id = "auth.failed_login"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return a Finding for each failed-login event.

        Pure method: it inspects only ``events`` and ``config``, performs no
        I/O, raises no alerts, and returns an identical result for identical
        inputs (Requirements 7.1, 7.2). ``config`` is unused because this is a
        per-event signature with no threshold or window.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration (unused here).

        Returns:
            A list of zero or more ``MEDIUM``-severity findings, one per failed
            login. An empty list means no failed-login events were present.
        """
        findings: list[Finding] = []
        for event in events:
            if event.fields.get("event") != "failed_login":
                continue

            metadata: dict = {
                "client_ip": event.client_ip,
                "user": event.user,
                "source": event.source,
            }
            line_number = _line_number(event)
            if line_number is not None:
                metadata["line_number"] = line_number

            user = event.user or "unknown user"
            origin = f" from {event.client_ip}" if event.client_ip else ""
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Failed authentication attempt",
                    severity=Severity.MEDIUM,
                    events=[event],
                    detail=(
                        f"auth.log reported a failed login for {user}{origin}."
                    ),
                    metadata=metadata,
                )
            )
        return findings


@register_detector("auth.privesc")
class PrivilegeEscalationDetector:
    """Flag privilege escalation via ``sudo`` or ``su`` in ``auth.log``.

    The detector matches events the authlog parser marked as privilege
    escalation (``fields.get("mechanism")`` in ``{"sudo", "su"}``). Each match
    yields one :class:`~loganalyze.models.Finding` at ``HIGH`` severity
    (Requirement 5.7); the finding carries exactly one
    :class:`~loganalyze.models.Severity` (Requirement 5.8). The invoking account
    is read from ``Event.user`` and the escalation target from
    ``fields["target_user"]``.

    Attributes:
        rule_id: The stable identifier ``"auth.privesc"`` carried onto every
            finding this detector produces.
    """

    rule_id = "auth.privesc"

    def detect(self, events: list[Event], config: DetectionConfig) -> list[Finding]:
        """Return a Finding for each privilege-escalation event.

        Pure method: it inspects only ``events`` and ``config``, performs no
        I/O, raises no alerts, and returns an identical result for identical
        inputs (Requirements 7.1, 7.2). ``config`` is unused because this is a
        per-event signature with no threshold or window.

        Args:
            events: The normalized events to inspect, in pipeline order.
            config: The injected detection configuration (unused here).

        Returns:
            A list of zero or more ``HIGH``-severity findings, one per
            ``sudo``/``su`` escalation. An empty list means no escalation events
            were present.
        """
        findings: list[Finding] = []
        for event in events:
            mechanism = event.fields.get("mechanism")
            if mechanism not in _PRIVESC_MECHANISMS:
                continue

            target_user = event.fields.get("target_user")
            metadata: dict = {
                "user": event.user,
                "mechanism": mechanism,
                "source": event.source,
                "target_user": target_user,
            }
            line_number = _line_number(event)
            if line_number is not None:
                metadata["line_number"] = line_number

            invoker = event.user or "unknown user"
            target = target_user or "another account"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Privilege escalation",
                    severity=Severity.HIGH,
                    events=[event],
                    detail=(
                        f"{invoker} escalated privileges to {target} "
                        f"via {mechanism}."
                    ),
                    metadata=metadata,
                )
            )
        return findings
