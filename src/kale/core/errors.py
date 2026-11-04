"""Exceptions modules raise on purpose. The engine turns each into a ``ModuleError``."""

from __future__ import annotations

from typing import ClassVar

from kale.core.models import ErrorCode


class KaleError(Exception):
    """Base class. ``code`` tells the engine how to report it."""

    code: ClassVar[ErrorCode] = ErrorCode.FAILED


class InvalidInputError(KaleError):
    """The target or an option cannot be processed (missing file, wrong format, ...)."""

    code = ErrorCode.INVALID_INPUT


class OutOfScopeError(KaleError):
    """An active module was asked to touch a target outside the authorized scope."""

    code = ErrorCode.OUT_OF_SCOPE


class MissingSecretError(KaleError):
    code = ErrorCode.MISSING_SECRET


class ModuleTimeoutError(KaleError):
    code = ErrorCode.TIMEOUT


class UnknownModuleError(KaleError, LookupError):
    """No module with that name is registered."""
