"""Schema for check definition YAML files (ADR-0009). Unknown fields are rejected."""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from skyline_core.db.models import Severity

_CHECK_ID = r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,4}$"
_RESOURCE_TYPE: Final = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,4}$")
_TAG: Final = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Reference(_Strict):
    title: str = Field(min_length=3, max_length=200)
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            msg = "references must use https"
            raise ValueError(msg)
        return value


class Remediation(_Strict):
    summary: str = Field(min_length=10, max_length=500)
    steps: list[str] = Field(min_length=1, max_length=20)


class CheckDefinition(_Strict):
    """One check. Text is our own wording; never copied from a vendor or benchmark."""

    id: str = Field(pattern=_CHECK_ID, max_length=120)
    version: int = Field(ge=1)
    title: str = Field(min_length=10, max_length=200)
    severity: Severity
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    resource_types: list[str] = Field(min_length=1, max_length=20)
    evaluator: Literal["python"] = "python"
    description: str = Field(min_length=10, max_length=2000)
    rationale: str = Field(min_length=10, max_length=2000)
    remediation: Remediation
    references: list[Reference] = Field(default_factory=list, max_length=10)
    tags: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("resource_types")
    @classmethod
    def _resource_types(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _RESOURCE_TYPE.match(value):
                msg = f"invalid resource type: {value!r}"
                raise ValueError(msg)
        return values

    @field_validator("tags")
    @classmethod
    def _tags(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _TAG.match(value):
                msg = f"invalid tag: {value!r}"
                raise ValueError(msg)
        return values

    def model_post_init(self, _context: object) -> None:
        if not self.id.startswith(f"{self.provider}."):
            msg = "check id must start with its provider"
            raise ValueError(msg)
        if any(not rt.startswith(f"{self.provider}.") for rt in self.resource_types):
            msg = "resource types must belong to the check's provider"
            raise ValueError(msg)
