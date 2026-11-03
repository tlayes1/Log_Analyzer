"""Plugin registry for parsers, detectors, and outputs.

Holds three independent registries keyed by short lowercase identifiers and
populated by decorators at import time. The pipeline resolves plugins by key
and never names a concrete plugin class, so adding a new format or detection
means adding one module and registering it, with no pipeline edits
(Requirements 3.10, 5.9, 8.14).

Registering a second plugin under an already-occupied key raises
``RegistryConflictError`` rather than silently overriding an existing entry
(Requirement 3.11).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, TypeVar

if TYPE_CHECKING:
    # These protocol modules are introduced by later tasks. They are imported
    # only for static type checking so this module imports cleanly standalone.
    from loganalyze.detections.base import Detector
    from loganalyze.outputs.base import Output
    from loganalyze.parsers.base import Parser


class RegistryConflictError(Exception):
    """Raised when two plugins register under the same key."""


# Registry key -> plugin class. Insertion order is preserved by ``dict`` and is
# relied upon for deterministic accessor ordering.
_PARSERS: dict[str, type["Parser"]] = {}
_DETECTORS: dict[str, type["Detector"]] = {}
_OUTPUTS: dict[str, type["Output"]] = {}

_P = TypeVar("_P", bound="Parser")
_D = TypeVar("_D", bound="Detector")
_O = TypeVar("_O", bound="Output")


def _register(
    registry: dict[str, type], key: str, kind: str
) -> Callable[[type], type]:
    """Build a class decorator that registers a class under ``key``.

    Args:
        registry: The backing registry mapping keys to plugin classes.
        key: The short lowercase identifier to register the class under.
        kind: Human-readable plugin kind used in the conflict error message.

    Returns:
        A decorator that stores the decorated class and returns it unchanged.

    Raises:
        RegistryConflictError: If ``key`` is already present in ``registry``.
    """

    def decorator(cls: type) -> type:
        if key in registry:
            raise RegistryConflictError(
                f"{kind} key {key!r} is already registered to "
                f"{registry[key].__name__!r}; cannot register {cls.__name__!r}"
            )
        registry[key] = cls
        return cls

    return decorator


def register_parser(key: str) -> Callable[[type[_P]], type[_P]]:
    """Register a Parser class under ``key``.

    Args:
        key: The short lowercase identifier (also the parser's ``log_type``).

    Returns:
        A class decorator that registers and returns the Parser class.

    Raises:
        RegistryConflictError: If a parser is already registered under ``key``.
    """
    return _register(_PARSERS, key, "parser")


def register_detector(key: str) -> Callable[[type[_D]], type[_D]]:
    """Register a Detector class under ``key``.

    Args:
        key: The short lowercase identifier for the detector (its ``rule_id``).

    Returns:
        A class decorator that registers and returns the Detector class.

    Raises:
        RegistryConflictError: If a detector is already registered under ``key``.
    """
    return _register(_DETECTORS, key, "detector")


def register_output(key: str) -> Callable[[type[_O]], type[_O]]:
    """Register an Output class under ``key``.

    Args:
        key: The short lowercase identifier for the output renderer.

    Returns:
        A class decorator that registers and returns the Output class.

    Raises:
        RegistryConflictError: If an output is already registered under ``key``.
    """
    return _register(_OUTPUTS, key, "output")


def get_parser(key: str) -> "Parser | None":
    """Instantiate the Parser registered under ``key``.

    Args:
        key: The parser's registry key.

    Returns:
        A new Parser instance, or ``None`` if no parser is registered under
        ``key``.
    """
    cls = _PARSERS.get(key)
    return cls() if cls is not None else None


def get_parsers() -> dict[str, "Parser"]:
    """Instantiate every registered Parser in deterministic order.

    Returns:
        A mapping of registry key to a fresh Parser instance, ordered by
        registration order.
    """
    return {key: cls() for key, cls in _PARSERS.items()}


def get_detectors() -> dict[str, "Detector"]:
    """Instantiate every registered Detector in deterministic order.

    Returns:
        A mapping of registry key to a fresh Detector instance, ordered by
        registration order.
    """
    return {key: cls() for key, cls in _DETECTORS.items()}


def get_outputs() -> dict[str, "Output"]:
    """Instantiate every registered Output in deterministic order.

    Returns:
        A mapping of registry key to a fresh Output instance, ordered by
        registration order.
    """
    return {key: cls() for key, cls in _OUTPUTS.items()}
