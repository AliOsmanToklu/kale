"""Request and response bodies of the API."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from kale.core import Kind


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetIn(_In):
    kind: Kind
    # Omitted for a file target: the file comes in the request's "file" part.
    value: str | None = None


class RunJobIn(_In):
    kind: Literal["run"]
    module: str
    target: TargetIn
    options: dict[str, str] = {}
    # Omitted: the whole server scope. Given: it may only narrow the server scope.
    scope: list[str] | None = None
    allow_private: bool = False
    lang: Literal["en", "tr"] = "en"


class InvestigateJobIn(_In):
    kind: Literal["investigate"]
    target: TargetIn
    depth: int = 2
    modules: list[str] | None = None
    options: dict[str, dict[str, str]] = {}
    max_runs: int = 50
    scope: list[str] | None = None
    allow_private: bool = False
    lang: Literal["en", "tr"] = "en"


JobIn = Annotated[RunJobIn | InvestigateJobIn, Field(discriminator="kind")]
