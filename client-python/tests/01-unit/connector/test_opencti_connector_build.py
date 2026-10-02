"""Tests for connector build metadata resolution."""

import json

from pycti.connector.opencti_connector_build import resolve


def test_resolve_skips_non_object_json_and_uses_next_source(tmp_path):
    metadata_directory = tmp_path / "__metadata__"
    metadata_directory.mkdir()
    (metadata_directory / "connector_manifest.json").write_text(
        json.dumps([]),
        encoding="utf-8",
    )
    (tmp_path / ".connector_version.json").write_text(
        json.dumps({"version": "1.2.3", "slug": "test-connector"}),
        encoding="utf-8",
    )

    assert resolve(tmp_path) == ("1.2.3", "test-connector", "stamp")


def test_resolve_returns_unknown_for_non_object_json(tmp_path):
    (tmp_path / ".connector_version.json").write_text(
        json.dumps("1.2.3"),
        encoding="utf-8",
    )

    assert resolve(tmp_path) == (None, None, "unknown")
