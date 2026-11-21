# coding: utf-8
"""Regression tests for https://github.com/OpenCTI-Platform/opencti/issues/19491.

A STIX object can carry labels and external references in several locations at
once (top-level, OpenCTI extension, ``x_opencti_*``), for example after the
playbook executor deep-merges two versions of the same object. pycti must read
every location and combine the values without duplicates.
"""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2

OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


@pytest.fixture
def local_api_client():
    """A real OpenCTIApiClient instance, without hitting the network."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


@pytest.fixture
def opencti_stix2(local_api_client, monkeypatch):
    instance = OpenCTIStix2(local_api_client)
    instance.mapping_cache_permanent["vocabularies_definition_fields"] = []
    created_labels = []

    def fake_label(value, color=None):
        created_labels.append((value, color))
        return {"id": "label-" + value}

    monkeypatch.setattr(local_api_client.label, "read_or_create_unchecked", fake_label)
    monkeypatch.setattr(
        local_api_client.external_reference,
        "create",
        lambda **kwargs: {"id": "external-reference-" + kwargs["source_name"]},
    )
    instance.created_labels = created_labels
    return instance


def malware(**fields):
    stix_object = {
        "id": "malware--11111111-1111-4111-8111-111111111111",
        "type": "malware",
        "name": "Example malware",
    }
    stix_object.update(fields)
    return stix_object


def test_labels_are_read_from_extension_and_x_opencti_labels(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = malware(
        extensions={OPENCTI_EXTENSION: {"labels": ["from-extension"]}},
        x_opencti_labels=["from-connector", "from-extension"],
    )

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["object_label"] == [
        "label-from-extension",
        "label-from-connector",
    ]


def test_labels_are_read_from_every_location_without_duplicates(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = malware(
        labels=["top-level", "shared"],
        x_opencti_labels=["shared", "x-opencti"],
        x_opencti_tags=[{"value": "tag", "color": "#ff0000"}, {"value": "shared"}],
    )

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["object_label"] == [
        "label-top-level",
        "label-shared",
        "label-x-opencti",
        "label-tag",
    ]
    assert ("tag", "#ff0000") in opencti_stix2.created_labels


def test_single_location_labels_are_unchanged(opencti_stix2: OpenCTIStix2):
    embedded = opencti_stix2.extract_embedded_relationships(
        malware(labels=["one", "two"])
    )

    assert embedded["object_label"] == ["label-one", "label-two"]


def test_external_references_are_read_from_every_location_without_duplicates(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = malware(
        external_references=[
            {"source_name": "top-level", "url": "https://example.com/top"},
            {"source_name": "shared", "url": "https://example.com/shared"},
        ],
        x_opencti_external_references=[
            {"source_name": "shared", "url": "https://example.com/shared"},
            {"source_name": "x-opencti", "url": "https://example.com/x"},
        ],
    )

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["external_references"] == [
        "external-reference-top-level",
        "external-reference-shared",
        "external-reference-x-opencti",
    ]


def test_external_references_are_read_from_extension_and_top_level(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = malware(
        external_references=[
            {"source_name": "top-level", "url": "https://example.com/top"}
        ],
        extensions={
            OPENCTI_EXTENSION: {
                "external_references": [
                    {"source_name": "extension", "url": "https://example.com/ext"}
                ]
            }
        },
    )

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["external_references"] == [
        "external-reference-top-level",
        "external-reference-extension",
    ]
