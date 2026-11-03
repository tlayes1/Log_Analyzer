"""Output protocol: the shared contract every output renderer implements.

An output consumes the aggregated :class:`~loganalyze.models.Finding` results
produced by the detection engines and renders them to a destination (the
terminal, a JSON report file, an optional CSV file). Outputs are the system's
security boundary: every string placed into any output must first be masked via
the ``Security_Helpers`` ``mask_*`` functions and then control-stripped via
``strip_control`` before it is rendered, so that no raw unmasked secret or PII
and no forbidden control character ever reaches the console or disk
(Requirements 8.4, 8.7, 8.8, 8.9, 8.10). The protocol declared here fixes that
contract; the actual masking and stripping are performed by the concrete
outputs implemented in later tasks (console, JSON file, optional CSV file),
which are resolved by registry key only (Requirement 8.14).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from loganalyze.models import Finding


@dataclass(frozen=True)
class OutputTarget:
    """Destination for a render operation.

    A small, immutable value describing where an output should write. File
    outputs carry the destination ``path``; console (stdout) outputs leave it
    as ``None``.

    Attributes:
        path: The destination file path for file outputs, or ``None`` to render
            to standard output.
    """

    path: Path | None = None


@runtime_checkable
class Output(Protocol):
    """Structural contract for a findings renderer.

    A conforming output exposes a single pure-of-protocol :meth:`render`
    method. Implementations are registered under a registry key and resolved by
    the pipeline without changes to the pipeline module (Requirement 8.14).

    This method is the output boundary: before any value derived from a Finding
    is written, the implementation must mask it with the ``Security_Helpers``
    ``mask_*`` functions and then strip control characters with
    ``strip_control``, so that no raw unmasked secret or PII and no forbidden
    control character reaches the console or disk (Requirements 8.4, 8.7, 8.8,
    8.9, 8.10).
    """

    def render(self, findings: list[Finding], target: OutputTarget) -> None:
        """Render findings to the configured destination.

        Implementations mask then control-strip every string they emit before
        writing, honoring the output boundary described on the protocol.

        Args:
            findings: The aggregated findings to render, in aggregator order.
            target: The destination to render to; its ``path`` selects a file
                destination, while ``None`` selects standard output.

        Returns:
            None. Any rendering failure is raised to the caller.
        """
        ...
