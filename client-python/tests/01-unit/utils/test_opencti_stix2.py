import datetime

import pytest

from pycti.utils.opencti_stix2 import OpenCTIStix2


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
