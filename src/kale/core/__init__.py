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
    INVESTIGATION_SCHEMA_VERSION,
    SCHEMA_VERSION,
    ErrorCode,
    Finding,
    Investigation,
    Kind,
    ModuleError,
    ModuleOutput,
    ModuleResult,
    Observable,
    Severity,
    Skipped,
)
from kale.core.module import Category, Module, ModuleSpec, Option, OptionValue, RunContext
from kale.core.pipeline import investigate
from kale.core.registry import Registry, Unavailable
from kale.core.scope import Scope

__all__ = [
    "INVESTIGATION_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "Category",
    "ErrorCode",
    "Finding",
    "InvalidInputError",
    "Investigation",
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
    "Skipped",
    "Unavailable",
    "UnknownModuleError",
    "investigate",
    "run_module",
]
