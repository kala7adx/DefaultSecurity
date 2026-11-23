from __future__ import annotations

import pytest

from skyline_checks.loader import load_checks
from skyline_frameworks.loader import (
    Catalogue,
    FrameworkError,
    MappingFile,
    build_bundle,
    check_integrity,
    load_frameworks,
)

CHECK_IDS = [c.definition.id for c in load_checks()]


def test_shipped_frameworks() -> None:
    bundles = {b.catalogue.id: b for b in load_frameworks()}
    assert set(bundles) == {"cyber-essentials-3.3", "iso27001-2022"}
    ce = bundles["cyber-essentials-3.3"]
    assert [c.ref for c in ce.catalogue.controls] == ["CE.FW", "CE.SC", "CE.SUM", "CE.UAC", "CE.MP"]
    assert str(ce.catalogue.source_url).startswith("https://www.ncsc.gov.uk/")


def test_mappings_reference_real_checks_and_unmapped_are_reported() -> None:
    unmapped = check_integrity(load_frameworks(), CHECK_IDS)
    assert unmapped["iso27001-2022"] == []
    assert unmapped["cyber-essentials-3.3"] == ["fake.storage.bucket_encryption"]


def test_every_check_maps_to_at_least_one_framework() -> None:
    mapped = {check for b in load_frameworks() for check in b.mappings}
    assert set(CHECK_IDS) <= mapped


def test_unknown_check_in_mapping_fails() -> None:
    with pytest.raises(FrameworkError, match="unknown checks"):
        check_integrity(load_frameworks(), ["fake.compute.unsupported_os"])


def _catalogue() -> Catalogue:
    return Catalogue.model_validate(
        {
            "id": "test-1",
            "name": "Test",
            "version": "1",
            "source_url": "https://example.com",
            "controls": [{"ref": "T.1", "title": "One", "description": "A control described."}],
        }
    )


@pytest.mark.parametrize(
    ("mapping", "message"),
    [
        ({"framework": "other", "mappings": {}}, "does not match"),
        ({"framework": "test-1", "mappings": {"fake.a.b": ["T.9"]}}, "unknown controls"),
        ({"framework": "test-1", "mappings": {"Not A Check": ["T.1"]}}, "invalid check id"),
    ],
)
def test_bad_mappings_fail(mapping: dict[str, object], message: str) -> None:
    with pytest.raises(FrameworkError, match=message):
        build_bundle(_catalogue(), MappingFile.model_validate(mapping))


def test_duplicate_refs_fail() -> None:
    catalogue = _catalogue().model_copy(
        update={"controls": [*_catalogue().controls, *_catalogue().controls]}
    )
    with pytest.raises(FrameworkError, match="duplicate"):
        build_bundle(catalogue, None)


def test_duplicate_mapping_refs_are_collapsed() -> None:
    bundle = build_bundle(
        _catalogue(),
        MappingFile.model_validate(
            {"framework": "test-1", "mappings": {"fake.a.b": ["T.1", "T.1"]}}
        ),
    )
    assert bundle.mappings == {"fake.a.b": ("T.1",)}
