import base64
import datetime
from types import SimpleNamespace

import pytest

from pycti.utils.opencti_stix2 import IMPORT_PREFETCH_BATCH_SIZE, OpenCTIStix2
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


@pytest.fixture
def opencti_stix2(api_client):
    return OpenCTIStix2(api_client)


def test_unknown_type(opencti_stix2: OpenCTIStix2, caplog):
    opencti_stix2.unknown_type({"type": "foo"})
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert "Unknown object type, doing nothing..." in caplog.text


def test_convert_markdown(opencti_stix2: OpenCTIStix2):
    # Matched pair is converted to backticks
    result = opencti_stix2.convert_markdown(
        " my <code> is very </special> </code> to me"
    )
    assert " my ` is very </special> ` to me" == result


def test_convert_markdown_multiple_pairs(opencti_stix2: OpenCTIStix2):
    # Multiple matched pairs are all converted
    result = opencti_stix2.convert_markdown("<code>foo</code> and <code>bar</code>")
    assert "`foo` and `bar`" == result


def test_convert_markdown_typo(opencti_stix2: OpenCTIStix2):
    # Malformed opening tag (<code missing closing >) means no valid pair exists; nothing should be replaced
    text = " my <code is very </special> </code> to me"
    result = opencti_stix2.convert_markdown(text)
    assert text == result


def test_convert_markdown_literal_code_tag(opencti_stix2: OpenCTIStix2):
    # A lone <code> without a matching </code> is literal content and must not be altered
    text = 'Run python3 -c "<code>" and pass it to subprocess.run(..., shell=True)'
    result = opencti_stix2.convert_markdown(text)
    assert text == result


def test_convert_markdown_mixed_matched_and_lone(opencti_stix2: OpenCTIStix2):
    # A matched pair is converted, but a trailing lone <code> is left untouched
    result = opencti_stix2.convert_markdown("<code>foo</code> and <code>")
    assert "`foo` and <code>" == result


def test_format_date_with_tz(opencti_stix2: OpenCTIStix2):
    # Test all 4 format_date cases with timestamp + timezone
    my_datetime = datetime.datetime(
        2021, 3, 5, 13, 31, 19, 42621, tzinfo=datetime.timezone.utc
    )
    my_datetime_str = my_datetime.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    assert my_datetime_str == opencti_stix2.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == opencti_stix2.format_date(my_date)
    assert my_datetime_str == opencti_stix2.format_date(my_datetime_str)
    assert (
        str(
            datetime.datetime.now(tz=datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "")
        )
        in opencti_stix2.format_date()
    )
    with pytest.raises(ValueError):
        opencti_stix2.format_date("No time")

    # Test all 4 format_date cases with timestamp w/o timezone
    my_datetime = datetime.datetime(2021, 3, 5, 13, 31, 19, 42621)
    my_datetime_str = (
        my_datetime.replace(tzinfo=datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    assert my_datetime_str == opencti_stix2.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == opencti_stix2.format_date(my_date)
    assert my_datetime_str == opencti_stix2.format_date(my_datetime_str)

    # Test the behavior of format_date() when called without arguments.
    # Since it relies on the current time, avoid flaky results by comparing only up to the seconds, using dates generated immediately before and after the function call.
    my_now_date_1 = (
        datetime.datetime.now(tz=datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "")
    )
    stix_now_date = opencti_stix2.format_date()
    my_now_date_2 = (
        datetime.datetime.now(tz=datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "")
    )
    assert (str(my_now_date_1) in stix_now_date) or (
        str(my_now_date_2) in stix_now_date
    )

    with pytest.raises(ValueError):
        opencti_stix2.format_date("No time")


def test_filter_objects(opencti_stix2: OpenCTIStix2):
    objects = [{"id": "123"}, {"id": "124"}, {"id": "125"}, {"id": "126"}]
    result = opencti_stix2.filter_objects(["123", "124", "126"], objects)
    assert len(result) == 1
    assert "126" not in result


class _EmptyNestedRefCollection:
    @staticmethod
    def list(**_kwargs):
        return []


class _ArtifactFileFetchRecorder:
    def __init__(self, responses):
        self.api_url = "http://localhost/graphql"
        self.stix_nested_ref_relationship = _EmptyNestedRefCollection()
        self.responses = list(responses)
        self.fetch_calls = []

    @staticmethod
    def not_empty(value):
        return value not in (None, "", [], {})

    def fetch_opencti_file(self, url, binary=False, serialize=False):
        self.fetch_calls.append((url, binary, serialize))
        return self.responses.pop(0)


def _artifact_export_helper(responses):
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = _ArtifactFileFetchRecorder(responses)
    return helper


def _artifact_export_entity():
    return {
        "id": "artifact--benchmark",
        "type": "artifact",
        "x_opencti_id": "artifact-internal--benchmark",
        "importFiles": [
            {
                "id": "file--benchmark",
                "name": "payload.bin",
                "metaData": {"mimetype": "application/octet-stream"},
                "objectMarking": [],
            }
        ],
        "importFilesIds": ["file--benchmark"],
    }


def test_prepare_export_reuses_artifact_payload_file_download():
    opencti_stix2 = _artifact_export_helper(["cGF5bG9hZA=="])

    result = opencti_stix2.prepare_export(_artifact_export_entity(), mode="simple")

    artifact = result[-1]
    assert artifact["payload_bin"] == "cGF5bG9hZA=="
    assert artifact["x_opencti_files"][0]["data"] == "cGF5bG9hZA=="
    assert len(opencti_stix2.opencti.fetch_calls) == 1


def test_prepare_export_retries_artifact_file_download_after_failed_payload_read():
    opencti_stix2 = _artifact_export_helper([None, "cGF5bG9hZA=="])

    result = opencti_stix2.prepare_export(_artifact_export_entity(), mode="simple")

    artifact = result[-1]
    assert "payload_bin" not in artifact
    assert artifact["x_opencti_files"][0]["data"] == "cGF5bG9hZA=="
    assert len(opencti_stix2.opencti.fetch_calls) == 2


def _external_reference_export_entity(index):
    return {
        "id": f"indicator-internal--{index}",
        "standard_id": f"indicator--{index}",
        "entity_type": "Indicator",
        "parent_types": ["Stix-Domain-Object"],
        "externalReferences": [
            {
                "source_name": "benchmark",
                "description": "",
                "url": "https://example.test/reference",
                "hash": "",
                "external_id": "REF-1",
                "importFiles": [
                    {
                        "id": "file--benchmark",
                        "name": "payload.bin",
                        "metaData": {"mimetype": "application/octet-stream"},
                    }
                ],
            }
        ],
        "externalReferencesIds": ["external-reference--benchmark"],
    }


def test_export_selected_reuses_external_reference_file_download_across_roots():
    opencti_stix2 = _artifact_export_helper(["cGF5bG9hZA=="])

    result = opencti_stix2.export_selected(
        [_external_reference_export_entity(1), _external_reference_export_entity(2)],
        mode="simple",
    )

    assert len(result["objects"]) == 2
    assert all(
        entity["external_references"][0]["x_opencti_files"][0]["data"] == "cGF5bG9hZA=="
        for entity in result["objects"]
    )
    assert len(opencti_stix2.opencti.fetch_calls) == 1


def test_export_selected_retries_external_reference_file_after_failed_read():
    opencti_stix2 = _artifact_export_helper([None, "cGF5bG9hZA=="])

    result = opencti_stix2.export_selected(
        [_external_reference_export_entity(1), _external_reference_export_entity(2)],
        mode="simple",
    )

    assert (
        result["objects"][0]["external_references"][0]["x_opencti_files"][0]["data"]
        is None
    )
    assert (
        result["objects"][1]["external_references"][0]["x_opencti_files"][0]["data"]
        == "cGF5bG9hZA=="
    )
    assert len(opencti_stix2.opencti.fetch_calls) == 2


def test_resolve_author_lowercases_unmatched_title_once():
    class _LowerCountingTitle(str):
        def __new__(cls, value):
            instance = super().__new__(cls, value)
            instance.lower_calls = 0
            return instance

        def lower(self):
            self.lower_calls += 1
            return super().lower()

    title = _LowerCountingTitle("benchmark external reference")
    opencti_stix2 = OpenCTIStix2(SimpleNamespace())

    assert opencti_stix2.resolve_author(title) is None
    assert title.lower_calls == 1


class _ExternalReferenceRecorder:
    def __init__(self):
        self.create_calls = 0

    @staticmethod
    def generate_id(url, source_name, external_id):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def create(self, **kwargs):
        self.create_calls += 1
        return {
            "id": self.generate_id(
                kwargs["url"], kwargs["source_name"], kwargs["external_id"]
            )
        }


class _ExternalReferenceIdRecorder(_ExternalReferenceRecorder):
    def __init__(self):
        super().__init__()
        self.generate_id_calls = 0

    def generate_id(self, url, source_name, external_id):
        self.generate_id_calls += 1
        return super().generate_id(url, source_name, external_id)

    def create(self, **_kwargs):
        self.create_calls += 1
        return {"id": "internal--external-reference"}


def _external_reference_opencti():
    return SimpleNamespace(
        external_reference=_ExternalReferenceRecorder(),
        app_logger=SimpleNamespace(warning=lambda *args, **kwargs: None),
        get_draft_id=lambda: "",
        get_attribute_in_extension=lambda _attribute, _entity: None,
        query=lambda _query: {"data": {"vocabularyCategories": []}},
        file=lambda name, data, mime_type: SimpleNamespace(
            name=name, data=data, mime=mime_type
        ),
    )


@pytest.mark.parametrize(
    "field_name", ["external_references", "x_opencti_external_references"]
)
def test_extract_embedded_relationships_reuses_external_reference_without_files(
    field_name,
):
    opencti = _external_reference_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    stix_object = {
        "type": "malware",
        field_name: [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
            }
        ],
    }

    first = opencti_stix2.extract_embedded_relationships(dict(stix_object))
    second = opencti_stix2.extract_embedded_relationships(dict(stix_object))

    assert first["external_references"] == second["external_references"]
    assert opencti.external_reference.create_calls == 1


def test_extract_embedded_relationships_keeps_file_upload_external_reference_uncached():
    opencti = _external_reference_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    stix_object = {
        "type": "malware",
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
                "x_opencti_files": [
                    {
                        "name": "payload.txt",
                        "data": base64.b64encode(b"payload").decode("ascii"),
                    }
                ],
            }
        ],
    }

    opencti_stix2.extract_embedded_relationships(dict(stix_object))
    opencti_stix2.extract_embedded_relationships(dict(stix_object))

    assert opencti.external_reference.create_calls == 2


class _SightingImportRecorder:
    def __init__(self):
        self.create_calls = []

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return {
            "id": f"sighting--{len(self.create_calls)}",
            "entity_type": "stix-sighting-relationship",
        }


def test_import_item_reuses_sighting_embedded_relationships_across_targets():
    opencti = _external_reference_opencti()
    opencti.stix_sighting_relationship = _SightingImportRecorder()
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti_stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []

    opencti_stix2.import_item(
        {
            "id": "sighting--shared",
            "type": "sighting",
            "sighting_of_ref": "indicator--source",
            "where_sighted_refs": ["identity--one", "identity--two"],
            "observed_data_refs": ["observed-data--one"],
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": "https://example.test/reference",
                    "x_opencti_files": [
                        {
                            "name": "payload.txt",
                            "data": base64.b64encode(b"payload").decode("ascii"),
                        }
                    ],
                }
            ],
        }
    )

    assert [
        (call["fromId"], call["toId"])
        for call in opencti.stix_sighting_relationship.create_calls
    ] == [
        ("indicator--source", "identity--one"),
        ("indicator--source", "identity--two"),
        ("observed-data--one", "identity--one"),
        ("observed-data--one", "identity--two"),
    ]
    assert opencti.external_reference.create_calls == 1


def test_extract_embedded_relationships_keeps_changed_external_reference_uncached():
    opencti = _external_reference_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    first = {
        "type": "malware",
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
                "description": "first",
            }
        ],
    }
    second = {
        "type": "malware",
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
                "description": "second",
            }
        ],
    }

    opencti_stix2.extract_embedded_relationships(first)
    opencti_stix2.extract_embedded_relationships(second)

    assert opencti.external_reference.create_calls == 2


class _ExternalReferenceReportRecorder:
    def __init__(self):
        self.create_calls = []

    @staticmethod
    def generate_fixed_fake_id(name, published=None):
        return f"report--{name}|{published}"

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return {"id": kwargs["id"]}


class _MarkingDefinitionRecorder:
    def __init__(self):
        self.read_calls = 0

    def read(self, **_kwargs):
        self.read_calls += 1
        return {"id": "marking-definition--tlp-clear"}


def _external_reference_report_opencti():
    opencti = _external_reference_opencti()
    opencti.report = _ExternalReferenceReportRecorder()
    opencti.marking_definition = _MarkingDefinitionRecorder()
    return opencti


def _extract_external_reference_report(opencti_stix2, url, description=None):
    external_reference = {"source_name": "benchmark", "url": url}
    if description is not None:
        external_reference["description"] = description
    return opencti_stix2.extract_embedded_relationships(
        {
            "type": "malware",
            "external_references": [external_reference],
        },
        ["external-reference-as-report"],
    )


def test_extract_embedded_relationships_reuses_exact_external_reference_report(
    monkeypatch,
):
    opencti = _external_reference_report_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    find_dates_calls = []

    def find_dates(*args, **kwargs):
        find_dates_calls.append((args, kwargs))
        return iter(())

    monkeypatch.setattr(
        "pycti.utils.opencti_stix2.datefinder.find_dates",
        find_dates,
    )

    first = _extract_external_reference_report(
        opencti_stix2, "https://example.test/reference"
    )
    second = _extract_external_reference_report(
        opencti_stix2, "https://example.test/reference"
    )

    assert first["reports"] == second["reports"]
    assert len(opencti.report.create_calls) == 1
    assert opencti.marking_definition.read_calls == 1
    assert len(find_dates_calls) == 1


def test_extract_embedded_relationships_keeps_changed_external_reference_report_uncached():
    opencti = _external_reference_report_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)

    _extract_external_reference_report(
        opencti_stix2, "https://example.test/reference", "first"
    )
    _extract_external_reference_report(
        opencti_stix2, "https://example.test/reference", "second"
    )

    assert [call["description"] for call in opencti.report.create_calls] == [
        "first",
        "second",
    ]


def test_extract_embedded_relationships_keeps_different_external_reference_report_uncached():
    opencti = _external_reference_report_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)

    _extract_external_reference_report(opencti_stix2, "https://example.test/one")
    _extract_external_reference_report(opencti_stix2, "https://example.test/two")

    assert [call["externalReferences"][0] for call in opencti.report.create_calls] == [
        "external-reference--https://example.test/one",
        "external-reference--https://example.test/two",
    ]


class _ReportRelationRecorder:
    def __init__(self):
        self.add_calls = []

    def add_stix_object_or_stix_relationship(self, **kwargs):
        self.add_calls.append((kwargs["id"], kwargs["stixObjectOrStixRelationshipId"]))
        return True


class _StixCoreRelationshipImportRecorder:
    @staticmethod
    def import_from_stix2(**kwargs):
        stix_relation = kwargs["stixRelation"]
        return {
            "id": stix_relation["id"],
            "entity_type": "stix-core-relationship",
        }


def _build_report_relation_importer():
    opencti = SimpleNamespace(
        report=_ReportRelationRecorder(),
        stix_core_relationship=_StixCoreRelationshipImportRecorder(),
        get_draft_id=lambda: "",
    )
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti_stix2.extract_embedded_relationships = lambda *_args, **_kwargs: {
        "created_by": None,
        "object_marking": None,
        "object_label": [],
        "open_vocabs": {},
        "granted_refs": [],
        "kill_chain_phases": [],
        "object_refs": [],
        "external_references": ["external-reference--shared"],
        "reports": {"external-reference--shared": {"id": "report--shared"}},
        "sample_refs": [],
    }
    return opencti, opencti_stix2


def test_import_relationship_reuses_report_relation_adds_for_shared_endpoints():
    opencti, opencti_stix2 = _build_report_relation_importer()

    with opencti_stix2._report_object_ref_dedupe_scope():
        for index in range(2):
            opencti_stix2.import_relationship(
                {
                    "id": f"relationship--{index}",
                    "type": "relationship",
                    "source_ref": "malware--shared-source",
                    "target_ref": "indicator--shared-target",
                }
            )

    assert opencti.report.add_calls == [
        ("report--shared", "relationship--0"),
        ("report--shared", "malware--shared-source"),
        ("report--shared", "indicator--shared-target"),
        ("report--shared", "relationship--1"),
    ]


def test_import_relationship_report_relation_dedupe_scope_does_not_leak():
    opencti, opencti_stix2 = _build_report_relation_importer()
    relation = {
        "id": "relationship--shared",
        "type": "relationship",
        "source_ref": "malware--shared-source",
        "target_ref": "indicator--shared-target",
    }

    with opencti_stix2._report_object_ref_dedupe_scope():
        opencti_stix2.import_relationship(relation)
    opencti_stix2.import_relationship(relation)

    assert opencti.report.add_calls == [
        ("report--shared", "relationship--shared"),
        ("report--shared", "malware--shared-source"),
        ("report--shared", "indicator--shared-target"),
        ("report--shared", "relationship--shared"),
        ("report--shared", "malware--shared-source"),
        ("report--shared", "indicator--shared-target"),
    ]


class _ExternalReferencePrefetchRecorder:
    def __init__(self):
        self.list_filters = []
        self.create_calls = []

    @staticmethod
    def generate_id(url, source_name, external_id):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def list(self, **kwargs):
        ids = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(ids)
        return [
            {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "source_name": "benchmark",
                "url": standard_id.removeprefix("external-reference--"),
                "external_id": None,
                "description": None,
            }
            for standard_id in ids
        ]

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        standard_id = self.generate_id(
            kwargs.get("url"), kwargs.get("source_name"), kwargs.get("external_id")
        )
        return {"id": f"internal--{standard_id}"}


def _external_reference_prefetch_opencti():
    opencti = _external_reference_opencti()
    opencti.external_reference = _ExternalReferencePrefetchRecorder()
    opencti.logger_class = lambda _name: SimpleNamespace(warning=lambda *args: None)
    return opencti


def test_import_bundle_prefetches_existing_external_references_before_item_import():
    opencti = _external_reference_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": f"https://example.test/reference/{index}",
                }
            ],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.external_reference.list_filters == [
        [
            "external-reference--https://example.test/reference/0",
            "external-reference--https://example.test/reference/1",
            "external-reference--https://example.test/reference/2",
        ]
    ]
    assert opencti.external_reference.create_calls == []


def test_import_bundle_reuses_external_reference_generated_ids_across_items():
    opencti = _external_reference_opencti()
    opencti.external_reference = _ExternalReferenceIdRecorder()
    opencti.logger_class = lambda _name: SimpleNamespace(warning=lambda *args: None)
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": "https://example.test/reference",
                }
            ],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.external_reference.generate_id_calls == 1
    assert opencti.external_reference.create_calls == 1


def test_external_reference_id_cache_keeps_non_string_inputs_uncached():
    opencti = _external_reference_opencti()
    opencti.external_reference = _ExternalReferenceIdRecorder()
    opencti_stix2 = OpenCTIStix2(opencti)

    first = opencti_stix2._get_external_reference_generated_id(
        123, "benchmark", "REF-1"
    )
    second = opencti_stix2._get_external_reference_generated_id(
        123, "benchmark", "REF-1"
    )

    assert first == second
    assert opencti.external_reference.generate_id_calls == 2


def test_prefetch_import_external_references_probes_repeated_cache_key_once():
    class _CacheProbeCountingOpenCTIStix2(OpenCTIStix2):
        def __init__(self, opencti):
            super().__init__(opencti)
            self.get_in_cache_calls = 0

        def get_in_cache(self, data_id):
            self.get_in_cache_calls += 1
            return super().get_in_cache(data_id)

    opencti_stix2 = _CacheProbeCountingOpenCTIStix2(_external_reference_opencti())
    objects = [
        {
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": "https://example.test/reference",
                }
            ],
        }
        for _ in range(3)
    ]

    opencti_stix2._prefetch_import_external_references(objects)

    assert opencti_stix2.get_in_cache_calls == 1


def test_import_bundle_prefetches_existing_external_references_in_bounded_chunks():
    opencti = _external_reference_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": f"https://example.test/reference/{index}",
                }
            ],
        }
        for index in range(IMPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.external_reference.list_filters[0] == [
        f"external-reference--https://example.test/reference/{index}"
        for index in range(IMPORT_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.external_reference.list_filters[1] == [
        f"external-reference--https://example.test/reference/{IMPORT_PREFETCH_BATCH_SIZE}"
    ]
    assert opencti.external_reference.create_calls == []


def test_import_bundle_keeps_changed_external_reference_metadata_on_per_item_create():
    opencti = _external_reference_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": f"https://example.test/reference/{index}",
                    "description": "changed",
                }
            ],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.external_reference.list_filters == [
        [
            "external-reference--https://example.test/reference/0",
            "external-reference--https://example.test/reference/1",
        ]
    ]
    assert [
        call["description"] for call in opencti.external_reference.create_calls
    ] == [
        "changed",
        "changed",
    ]


def test_import_bundle_falls_back_to_per_item_external_reference_create_when_prefetch_fails():
    opencti = _external_reference_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti.external_reference.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": f"https://example.test/reference/{index}",
                }
            ],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert [call["url"] for call in opencti.external_reference.create_calls] == [
        "https://example.test/reference/0",
        "https://example.test/reference/1",
    ]


class _KillChainPhasePrefetchRecorder:
    def __init__(self):
        self.list_filters = []
        self.list_first = []
        self.create_calls = []

    @staticmethod
    def generate_id(phase_name, kill_chain_name):
        return f"kill-chain-phase--{kill_chain_name}|{phase_name}"

    def list(self, **kwargs):
        ids = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(ids)
        self.list_first.append(kwargs["first"])
        return [
            {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "entity_type": "Kill-Chain-Phase",
                "kill_chain_name": standard_id.removeprefix("kill-chain-phase--").split(
                    "|", 1
                )[0],
                "phase_name": standard_id.removeprefix("kill-chain-phase--").split(
                    "|", 1
                )[1],
                "x_opencti_order": 0,
            }
            for standard_id in ids
        ]

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        standard_id = self.generate_id(kwargs["phase_name"], kwargs["kill_chain_name"])
        return {
            "id": f"internal--{standard_id}",
            "standard_id": standard_id,
            "entity_type": "Kill-Chain-Phase",
        }


def _kill_chain_phase_prefetch_opencti():
    opencti = _external_reference_opencti()
    opencti.kill_chain_phase = _KillChainPhasePrefetchRecorder()
    opencti.logger_class = lambda _name: SimpleNamespace(warning=lambda *args: None)
    return opencti


def test_import_bundle_prefetches_existing_kill_chain_phases_before_item_import():
    opencti = _kill_chain_phase_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "benchmark",
                    "phase_name": f"phase-{index}",
                }
            ],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.kill_chain_phase.list_filters == [
        [
            "kill-chain-phase--benchmark|phase-0",
            "kill-chain-phase--benchmark|phase-1",
            "kill-chain-phase--benchmark|phase-2",
        ]
    ]
    assert opencti.kill_chain_phase.list_first == [3]
    assert opencti.kill_chain_phase.create_calls == []


def test_import_bundle_prefetches_existing_kill_chain_phases_in_bounded_chunks():
    opencti = _kill_chain_phase_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "benchmark",
                    "phase_name": f"phase-{index}",
                }
            ],
        }
        for index in range(IMPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.kill_chain_phase.list_filters[0] == [
        f"kill-chain-phase--benchmark|phase-{index}"
        for index in range(IMPORT_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.kill_chain_phase.list_filters[1] == [
        f"kill-chain-phase--benchmark|phase-{IMPORT_PREFETCH_BATCH_SIZE}"
    ]
    assert opencti.kill_chain_phase.list_first == [IMPORT_PREFETCH_BATCH_SIZE, 1]
    assert opencti.kill_chain_phase.create_calls == []


def test_import_bundle_keeps_changed_kill_chain_phase_order_on_per_item_create():
    opencti = _kill_chain_phase_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "benchmark",
                    "phase_name": f"phase-{index}",
                    "x_opencti_order": 1,
                }
            ],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.kill_chain_phase.list_filters == [
        [
            "kill-chain-phase--benchmark|phase-0",
            "kill-chain-phase--benchmark|phase-1",
        ]
    ]
    assert [
        call["x_opencti_order"] for call in opencti.kill_chain_phase.create_calls
    ] == [
        1,
        1,
    ]


def test_import_bundle_keeps_id_bearing_kill_chain_phase_on_per_item_create():
    opencti = _kill_chain_phase_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "kill_chain_phases": [
                {
                    "id": f"kill-chain-phase--explicit-{index}",
                    "kill_chain_name": "benchmark",
                    "phase_name": f"phase-{index}",
                }
            ],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.kill_chain_phase.list_filters == []
    assert [call["stix_id"] for call in opencti.kill_chain_phase.create_calls] == [
        "kill-chain-phase--explicit-0",
        "kill-chain-phase--explicit-1",
    ]


def test_import_bundle_falls_back_to_per_item_kill_chain_phase_create_when_prefetch_fails():
    opencti = _kill_chain_phase_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti.kill_chain_phase.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "benchmark",
                    "phase_name": f"phase-{index}",
                }
            ],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert [call["phase_name"] for call in opencti.kill_chain_phase.create_calls] == [
        "phase-0",
        "phase-1",
    ]


class _LabelPrefetchRecorder:
    def __init__(self):
        self.list_filters = []
        self.read_or_create_calls = []
        self.create_calls = []
        self.existing_values = None

    def list(self, **kwargs):
        values = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(values)
        return [
            {"id": f"label--{value}", "value": value}
            for value in values
            if self.existing_values is None or value in self.existing_values
        ]

    def read_or_create_unchecked(self, **kwargs):
        value = kwargs["value"]
        self.read_or_create_calls.append(value)
        return {"id": f"label--{value}", "value": value}

    def create(self, **kwargs):
        value = kwargs["value"]
        self.create_calls.append(value)
        return {"id": f"label--{value}", "value": value}


def _label_prefetch_opencti():
    opencti = _external_reference_opencti()
    opencti.label = _LabelPrefetchRecorder()
    opencti.logger_class = lambda _name: SimpleNamespace(warning=lambda *args: None)
    return opencti


def _import_bundle_extracting_relationships(opencti_stix2, objects):
    def import_item_with_retries(item, *_args, **_kwargs):
        opencti_stix2.extract_embedded_relationships(item)
        return None

    opencti_stix2.import_item_with_retries = import_item_with_retries
    opencti_stix2.import_bundle(
        {
            "type": "bundle",
            "id": "bundle--labels",
            "objects": objects,
        }
    )


def test_import_bundle_skips_ref_count_when_limit_is_disabled(monkeypatch):
    opencti = _label_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    compute_calls = []

    monkeypatch.setattr(
        OpenCTIStix2Utils,
        "compute_object_refs_number",
        lambda item: compute_calls.append(item["id"]) or 0,
    )
    opencti_stix2.import_item_with_retries = lambda *_args, **_kwargs: None

    opencti_stix2.import_bundle(
        {
            "type": "bundle",
            "id": "bundle--disabled-max-refs",
            "objects": [{"id": "malware--disabled", "type": "malware"}],
        },
        objects_max_refs=0,
    )

    assert compute_calls == []


def test_import_bundle_counts_refs_when_limit_is_enabled(monkeypatch):
    opencti = _label_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    compute_calls = []

    monkeypatch.setattr(
        OpenCTIStix2Utils,
        "compute_object_refs_number",
        lambda item: compute_calls.append(item["id"]) or 0,
    )
    opencti_stix2.import_item_with_retries = lambda *_args, **_kwargs: None

    opencti_stix2.import_bundle(
        {
            "type": "bundle",
            "id": "bundle--enabled-max-refs",
            "objects": [{"id": "malware--enabled", "type": "malware"}],
        },
        objects_max_refs=1,
    )

    assert compute_calls == ["malware--enabled"]


def test_import_bundle_prefetches_existing_labels_before_item_import():
    opencti = _label_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "labels": [f"label-{index}"],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.label.list_filters == [["label-0", "label-1", "label-2"]]
    assert opencti.label.read_or_create_calls == []


def test_import_bundle_prefetches_existing_labels_in_bounded_chunks():
    opencti = _label_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "labels": [f"label-{index}"],
        }
        for index in range(IMPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.label.list_filters[0] == [
        f"label-{index}" for index in range(IMPORT_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.label.list_filters[1] == [f"label-{IMPORT_PREFETCH_BATCH_SIZE}"]
    assert opencti.label.read_or_create_calls == []


def test_import_bundle_skips_redundant_reads_for_labels_prefetched_as_missing():
    opencti = _label_prefetch_opencti()
    opencti.label.existing_values = set()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "labels": [f"label-{index}"],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.label.list_filters == [["label-0", "label-1", "label-2"]]
    assert opencti.label.read_or_create_calls == []
    assert opencti.label.create_calls == ["label-0", "label-1", "label-2"]


def test_import_bundle_falls_back_to_per_item_label_resolution_when_prefetch_fails():
    opencti = _label_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti.label.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "labels": [f"label-{index}"],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.label.read_or_create_calls == ["label-0", "label-1"]
    assert opencti.label.create_calls == []


class _VocabularyPrefetchRecorder:
    def __init__(self):
        self.list_filters = []
        self.read_or_create_calls = []

    def list(self, **kwargs):
        values = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(values)
        return [{"id": f"vocabulary--{value}", "name": value} for value in values]

    def read_or_create_unchecked_with_cache(self, vocab, cache, field):
        vocab_key = "vocab_" + vocab
        if vocab_key not in cache:
            self.read_or_create_calls.append(
                (vocab, field["required"], cache["category_" + field["key"]])
            )
            cache[vocab_key] = {"id": f"vocabulary--{vocab}", "name": vocab}
        return cache[vocab_key]


def _vocabulary_prefetch_opencti():
    opencti = _external_reference_opencti()
    opencti.vocabulary = _VocabularyPrefetchRecorder()
    opencti.query = lambda _query: {
        "data": {
            "vocabularyCategories": [
                {
                    "key": "malware_type_ov",
                    "fields": [{"key": "malware_types", "required": False}],
                }
            ]
        }
    }
    opencti.logger_class = lambda _name: SimpleNamespace(warning=lambda *args: None)
    return opencti


def test_import_bundle_prefetches_existing_vocabularies_before_item_import():
    opencti = _vocabulary_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "malware_types": [f"vocab-{index}"],
        }
        for index in range(3)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.vocabulary.list_filters == [["vocab-0", "vocab-1", "vocab-2"]]
    assert opencti.vocabulary.read_or_create_calls == []


def test_import_bundle_prefetches_existing_vocabularies_in_bounded_chunks():
    opencti = _vocabulary_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "malware_types": [f"vocab-{index}"],
        }
        for index in range(IMPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.vocabulary.list_filters[0] == [
        f"vocab-{index}" for index in range(IMPORT_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.vocabulary.list_filters[1] == [f"vocab-{IMPORT_PREFETCH_BATCH_SIZE}"]
    assert opencti.vocabulary.read_or_create_calls == []


def test_import_bundle_falls_back_to_per_item_vocabulary_resolution_when_prefetch_fails():
    opencti = _vocabulary_prefetch_opencti()
    opencti_stix2 = OpenCTIStix2(opencti)
    opencti.vocabulary.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )
    objects = [
        {
            "id": f"malware--{index}",
            "type": "malware",
            "malware_types": [f"vocab-{index}"],
        }
        for index in range(2)
    ]

    _import_bundle_extracting_relationships(opencti_stix2, objects)

    assert opencti.vocabulary.read_or_create_calls == [
        ("vocab-0", False, "malware_type_ov"),
        ("vocab-1", False, "malware_type_ov"),
    ]


def test_pick_aliases(opencti_stix2: OpenCTIStix2) -> None:
    stix_object = {}
    assert opencti_stix2.pick_aliases(stix_object) is None
    stix_object["aliases"] = "alias"
    assert opencti_stix2.pick_aliases(stix_object) == "alias"
    stix_object["x_amitt_aliases"] = "amitt_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "amitt_alias"
    stix_object["x_mitre_aliases"] = "mitre_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "mitre_alias"
    stix_object["x_opencti_aliases"] = "opencti_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "opencti_alias"


def test_import_bundle_from_file(opencti_stix2: OpenCTIStix2, caplog) -> None:
    opencti_stix2.import_bundle_from_file("foo.txt")
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert "The bundle file does not exist" in caplog.text


def test_extract_embedded_storage_path_ignores_query_string(
    opencti_stix2: OpenCTIStix2,
):
    uri = "https://remote.example/download?next=/storage/get/embedded/Note/internal-note-id/a.png"

    result = opencti_stix2._extract_embedded_storage_path(uri)

    assert result is None


def test_extract_embedded_storage_path_ignores_fragment(opencti_stix2: OpenCTIStix2):
    uri = "https://remote.example/download#/storage/view/embedded/Note/internal-note-id/a.png"

    result = opencti_stix2._extract_embedded_storage_path(uri)

    assert result is None


def test_extract_embedded_storage_path_from_relative_embedded_path_with_context(
    opencti_stix2: OpenCTIStix2,
):
    uri = "embedded/upload_image_example.png"

    result = opencti_stix2._extract_embedded_storage_path(
        uri,
        entity_type="Report",
        entity_id="internal-report-id",
    )

    assert result == "embedded/Report/internal-report-id/upload_image_example.png"


def test_prepare_export_rewrites_relative_embedded_markdown_image_uri(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2.opencti.stix_nested_ref_relationship,
        "list",
        lambda **kwargs: [],
    )

    fetch_calls = []

    def fake_fetch(url, binary=False, serialize=False):
        fetch_calls.append((url, binary, serialize))
        return "Zm9v"

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    entity = {
        "id": "internal-report-id-embedded",
        "type": "report",
        "entity_type": "Report",
        "x_opencti_id": "internal-report-id-embedded",
        "description": "desc ![img](embedded/upload_image_example.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Report/internal-report-id-embedded/upload_image_example.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def _embedded_markdown_export_entity(index, include_all_fields=True):
    markdown = "![img](embedded/Report/shared/payload.png)"
    entity = {
        "id": f"report--{index}",
        "type": "report",
        "entity_type": "Report",
        "x_opencti_id": f"internal-report-{index}",
        "description": markdown,
    }
    if include_all_fields:
        entity["x_opencti_description"] = markdown
        entity["content"] = markdown
    return entity


def test_prepare_export_reuses_embedded_markdown_image_download_across_fields():
    opencti_stix2 = _artifact_export_helper(["Zm9v"])

    result = opencti_stix2.prepare_export(
        _embedded_markdown_export_entity(1), mode="simple"
    )

    assert all(
        "data:image/png;base64,Zm9v" in result[0][field]
        for field in ("description", "x_opencti_description", "content")
    )
    assert len(opencti_stix2.opencti.fetch_calls) == 1


def test_export_selected_retries_then_reuses_embedded_markdown_image_download():
    opencti_stix2 = _artifact_export_helper([None, "Zm9v"])
    opencti_stix2.generate_export = lambda entity: entity.copy()

    result = opencti_stix2.export_selected(
        [
            _embedded_markdown_export_entity(1, include_all_fields=False),
            _embedded_markdown_export_entity(2, include_all_fields=False),
            _embedded_markdown_export_entity(3, include_all_fields=False),
        ],
        mode="simple",
    )

    assert all(
        "data:image/png;base64,Zm9v" in entity["description"]
        for entity in result["objects"]
    )
    assert len(opencti_stix2.opencti.fetch_calls) == 2


def test_bundle_level_rewrite_rewrites_relative_embedded_markdown_image_uri(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    fetch_calls = []

    def fake_fetch(url, binary=False, serialize=False):
        fetch_calls.append((url, binary, serialize))
        return "Zm9v"

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "report",
                "id": "report--392ef26a-4496-50ae-9828-4c3c72328245",
                "x_opencti_type": "Report",
                "x_opencti_id": "bf8359d6-030a-43b3-9fe2-1ba678ecb3ed",
                "description": "![upload_image_example.png](embedded/upload_image_example.png)",
            }
        ],
    }

    opencti_stix2._rewrite_embedded_image_uris_in_bundle_for_export(bundle)

    description = bundle["objects"][0]["description"]
    assert "data:image/png;base64,Zm9v" in description
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Report/bf8359d6-030a-43b3-9fe2-1ba678ecb3ed/upload_image_example.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_import_observable_passes_embedded_flags_to_create(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2,
        "extract_embedded_relationships",
        lambda stix_object, types=None: {
            "created_by": None,
            "object_marking": None,
            "object_label": None,
            "open_vocabs": {},
            "granted_refs": [],
            "kill_chain_phases": [],
            "object_refs": [],
            "external_references": [],
            "reports": {},
            "sample_refs": [],
        },
    )
    monkeypatch.setattr(
        opencti_stix2.opencti,
        "file",
        lambda name, data, mime_type: {
            "name": name,
            "data": data,
            "mime_type": mime_type,
        },
    )

    captured_kwargs = {}

    def fake_create(**kwargs):
        captured_kwargs.update(kwargs)
        return {"id": "observable--1", "entity_type": "Stix-Cyber-Observable"}

    monkeypatch.setattr(
        opencti_stix2.opencti.stix_cyber_observable,
        "create",
        fake_create,
    )

    stix_object = {
        "id": "ipv4-addr--11111111-1111-4111-8111-111111111111",
        "type": "ipv4-addr",
        "value": "1.2.3.4",
        "x_opencti_files": [
            {
                "name": "img.png",
                "data": "Zm9v",
                "mime_type": "image/png",
                "embedded": True,
            }
        ],
    }

    opencti_stix2.import_observable(stix_object, update=False)

    assert captured_kwargs.get("embedded") == [True]


def test_prepare_export_prefers_x_opencti_type_for_relative_embedded_markdown_image_uri(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2.opencti.stix_nested_ref_relationship,
        "list",
        lambda **kwargs: [],
    )

    fetch_calls = []

    def fake_fetch(url, binary=False, serialize=False):
        fetch_calls.append((url, binary, serialize))
        return "Zm9v"

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    entity = {
        "id": "internal-report-id-embedded",
        "type": "report",
        "entity_type": "Note",
        "x_opencti_type": "Report",
        "x_opencti_id": "internal-report-id-embedded",
        "description": "desc ![img](embedded/upload_image_example.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Report/internal-report-id-embedded/upload_image_example.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_extract_embedded_relationships_resolves_open_vocab_by_entity_type(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    def fake_query(_query):
        return {
            "data": {
                "vocabularyCategories": [
                    {
                        "key": "threat_actor_group_role_ov",
                        "entity_types": ["Threat-Actor-Group"],
                        "fields": [
                            {"key": "roles", "required": False, "multiple": True}
                        ],
                    },
                    {
                        "key": "threat_actor_individual_role_ov",
                        "entity_types": ["Threat-Actor-Individual"],
                        "fields": [
                            {"key": "roles", "required": False, "multiple": True}
                        ],
                    },
                ]
            }
        }

    monkeypatch.setattr(opencti_stix2.opencti, "query", fake_query)

    resolved_categories = []

    def fake_read_or_create_unchecked_with_cache(vocab, cache, field):
        resolved_categories.append(field["category"])
        if field["category"] == "threat_actor_group_role_ov":
            return {"name": vocab}
        return None

    monkeypatch.setattr(
        opencti_stix2.opencti.vocabulary,
        "read_or_create_unchecked_with_cache",
        fake_read_or_create_unchecked_with_cache,
    )

    stix_object = {
        "id": "threat-actor--11111111-1111-4111-8111-111111111111",
        "type": "threat-actor",
        "x_opencti_type": "Threat-Actor-Group",
        "name": "TA_20250505",
        "roles": ["agent", "independent"],
    }

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["open_vocabs"]["roles"] == ["agent", "independent"]
    assert resolved_categories == [
        "threat_actor_group_role_ov",
        "threat_actor_group_role_ov",
    ]


def test_extract_embedded_relationships_resolves_open_vocab_with_lowercase_entity_type(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    def fake_query(_query):
        return {
            "data": {
                "vocabularyCategories": [
                    {
                        "key": "threat_actor_group_role_ov",
                        "entity_types": ["Threat-Actor-Group"],
                        "fields": [
                            {"key": "roles", "required": False, "multiple": True}
                        ],
                    },
                ]
            }
        }

    monkeypatch.setattr(opencti_stix2.opencti, "query", fake_query)

    monkeypatch.setattr(
        opencti_stix2.opencti.vocabulary,
        "read_or_create_unchecked_with_cache",
        lambda vocab, cache, field: {"name": vocab},
    )

    stix_object = {
        "id": "threat-actor--11111111-1111-4111-8111-111111111111",
        "type": "threat-actor",
        "x_opencti_type": "threat-actor-group",
        "name": "TA_20250505",
        "roles": ["agent", "independent"],
    }

    embedded = opencti_stix2.extract_embedded_relationships(stix_object)

    assert embedded["open_vocabs"]["roles"] == ["agent", "independent"]


def test_prepare_export_does_not_rewrite_markdown_image_uri_in_descriptions_list(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2.opencti.stix_nested_ref_relationship,
        "list",
        lambda **kwargs: [],
    )

    fetch_calls = []

    def fake_fetch(url, binary=False, serialize=False):
        fetch_calls.append((url, binary, serialize))
        return "Zm9v"

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    entity = {
        "id": "report--66666666-6666-4666-8666-666666666666",
        "type": "report",
        "x_opencti_id": "internal-report-id-6",
        "descriptions": [
            "first ![img](/storage/view/embedded/Report/internal-report-id-6/a.png)",
            "second no image",
        ],
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert (
        result[0]["descriptions"][0]
        == "first ![img](/storage/view/embedded/Report/internal-report-id-6/a.png)"
    )
    assert result[0]["descriptions"][1] == "second no image"
    assert len(fetch_calls) == 0


def test_prepare_export_does_not_corrupt_malformed_markdown_image_syntax(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2.opencti.stix_nested_ref_relationship,
        "list",
        lambda **kwargs: [],
    )

    # Intentionally malformed markdown image (missing ] before the URL destination).
    malformed = (
        "![02 osint vulnerability triage queue "
        "(/storage/get/embedded/Report/internal-report-id/markdown-image-abc.pngTkSuQmCC)"
    )

    entity = {
        "id": "report--22222222-2222-4222-8222-222222222222",
        "type": "report",
        "x_opencti_id": "internal-report-id",
        "description": malformed,
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert result[0]["description"] == malformed


def test_prepare_export_keeps_non_embedded_markdown_image_uri(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    monkeypatch.setattr(
        opencti_stix2.opencti.stix_nested_ref_relationship,
        "list",
        lambda **kwargs: [],
    )

    fetch_calls = []

    def fake_fetch(url, binary=False, serialize=False):
        fetch_calls.append((url, binary, serialize))
        return "Zm9v"

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    entity = {
        "id": "note--22222222-2222-4222-8222-222222222222",
        "type": "note",
        "x_opencti_id": "internal-note-id-2",
        "description": "desc ![img](/storage/get/import/global/a.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert result[0]["description"] == "desc ![img](/storage/get/import/global/a.png)"
    assert len(fetch_calls) == 0


def test_prepare_export_removes_custom_attributes_when_requested():
    opencti_stix2 = OpenCTIStix2.__new__(OpenCTIStix2)
    opencti_stix2.opencti = SimpleNamespace(
        stix_nested_ref_relationship=SimpleNamespace(list=lambda **kwargs: []),
        api_url="http://localhost/graphql",
    )

    entity = {
        "id": "indicator--22222222-2222-4222-8222-222222222222",
        "type": "indicator",
        "x_opencti_id": "internal-indicator-id",
        "x_opencti_score": 80,
        "name": "indicator",
    }

    result = opencti_stix2.prepare_export(
        entity=entity, mode="simple", no_custom_attributes=True
    )

    assert result == [
        {
            "id": "indicator--22222222-2222-4222-8222-222222222222",
            "type": "indicator",
            "name": "indicator",
        }
    ]
