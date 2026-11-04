"""The contract between kale and its modules. Front ends and modules import from here."""

from kale.core.engine import run_module
from kale.core.errors import (
    InvalidInputError,
    KaleError,
    MissingSecretError,
    ModuleTimeoutError,
    OutOfScopeError,
    UnknownModuleError,
)
from kale.core.models import (
    SCHEMA_VERSION,
    ErrorCode,
    Finding,
    Kind,
    ModuleError,
    ModuleOutput,
    ModuleResult,
    Observable,
    Severity,
)
from kale.core.module import Category, Module, ModuleSpec, Option, OptionValue, RunContext
from kale.core.registry import Registry, Unavailable
from kale.core.scope import Scope

__all__ = [
    "SCHEMA_VERSION",
    "Category",
    "ErrorCode",
    "Finding",
    "InvalidInputError",
    "KaleError",
    "Kind",
    "MissingSecretError",
    "Module",
    "ModuleError",
    "ModuleOutput",
    "ModuleResult",
    "ModuleSpec",
    "ModuleTimeoutError",
    "Observable",
    "Option",
    "OptionValue",
    "OutOfScopeError",
    "Registry",
    "RunContext",
    "Scope",
    "Severity",
    "Unavailable",
    "UnknownModuleError",
    "run_module",
]
