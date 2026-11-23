"""Load framework catalogues and mappings, and check their referential integrity."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError

_MAX_FILE_BYTES: Final = 256 * 1024
_REF = r"^[A-Z][A-Z0-9]*(\.[A-Z0-9]+)+$"
_FRAMEWORK_ID = r"^[a-z0-9][a-z0-9.-]{2,62}$"
_CHECK_ID = r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,4}$"


class FrameworkError(ValueError):
    """A catalogue or mapping file is invalid or inconsistent."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ControlDefinition(_Strict):
    ref: str = Field(pattern=_REF, max_length=40)
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=1000)


class Catalogue(_Strict):
    id: str = Field(pattern=_FRAMEWORK_ID)
    name: str = Field(min_length=3, max_length=200)
    version: str = Field(min_length=1, max_length=20)
    source_url: HttpUrl
    description: str = Field(default="", max_length=1000)
    controls: list[ControlDefinition] = Field(min_length=1, max_length=500)


class MappingFile(_Strict):
    framework: str = Field(pattern=_FRAMEWORK_ID)
    mappings: dict[str, list[str]] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FrameworkBundle:
    """A catalogue with its mappings, validated against each other."""

    catalogue: Catalogue
    mappings: Mapping[str, tuple[str, ...]]  # check_id -> control refs


def _load_yaml(path: Traversable) -> object:
    text = path.read_text(encoding="utf-8")
    if len(text.encode()) > _MAX_FILE_BYTES:
        msg = f"{path.name}: file is too large"
        raise FrameworkError(msg)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{path.name}: invalid YAML"
        raise FrameworkError(msg) from exc


def _validate(model: type[_Strict], data: object, source: str) -> _Strict:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        msg = f"{source}: {exc}"
        raise FrameworkError(msg) from exc


def build_bundle(catalogue: Catalogue, mapping: MappingFile | None) -> FrameworkBundle:
    """Pair a catalogue with its mapping file, rejecting unknown or duplicate control refs."""
    refs = [c.ref for c in catalogue.controls]
    if len(refs) != len(set(refs)):
        msg = f"{catalogue.id}: duplicate control references"
        raise FrameworkError(msg)
    mappings: dict[str, tuple[str, ...]] = {}
    if mapping is not None:
        if mapping.framework != catalogue.id:
            msg = f"mapping for {mapping.framework} does not match catalogue {catalogue.id}"
            raise FrameworkError(msg)
        for check_id, control_refs in mapping.mappings.items():
            if not re.match(_CHECK_ID, check_id):
                msg = f"{catalogue.id}: invalid check id {check_id!r}"
                raise FrameworkError(msg)
            unknown = sorted(set(control_refs) - set(refs))
            if unknown:
                msg = f"{catalogue.id}: {check_id} maps to unknown controls {unknown}"
                raise FrameworkError(msg)
            mappings[check_id] = tuple(dict.fromkeys(control_refs))
    return FrameworkBundle(catalogue=catalogue, mappings=mappings)


@cache
def load_frameworks() -> tuple[FrameworkBundle, ...]:
    """Every shipped framework with its mappings."""
    root = resources.files("skyline_frameworks")
    mapping_files: dict[str, MappingFile] = {}
    for path in sorted(root.joinpath("mappings").iterdir(), key=lambda p: p.name):
        if path.name.endswith(".yaml"):
            mapping = _validate(MappingFile, _load_yaml(path), path.name)
            assert isinstance(mapping, MappingFile)  # noqa: S101
            mapping_files[mapping.framework] = mapping
    bundles: list[FrameworkBundle] = []
    for path in sorted(root.joinpath("catalogues").iterdir(), key=lambda p: p.name):
        if path.name.endswith(".yaml"):
            catalogue = _validate(Catalogue, _load_yaml(path), path.name)
            assert isinstance(catalogue, Catalogue)  # noqa: S101
            bundles.append(build_bundle(catalogue, mapping_files.pop(catalogue.id, None)))
    if mapping_files:
        msg = f"mappings without a catalogue: {sorted(mapping_files)}"
        raise FrameworkError(msg)
    return tuple(bundles)


def check_integrity(
    bundles: Iterable[FrameworkBundle], check_ids: Iterable[str]
) -> dict[str, list[str]]:
    """Fail if a mapping names a check that doesn't exist; return unmapped checks per framework.

    Unmapped checks are reported, not hidden (ARCHITECTURE §7).
    """
    known = set(check_ids)
    unmapped: dict[str, list[str]] = {}
    for bundle in bundles:
        missing = sorted(set(bundle.mappings) - known)
        if missing:
            msg = f"{bundle.catalogue.id}: mappings reference unknown checks {missing}"
            raise FrameworkError(msg)
        unmapped[bundle.catalogue.id] = sorted(known - set(bundle.mappings))
    return unmapped
