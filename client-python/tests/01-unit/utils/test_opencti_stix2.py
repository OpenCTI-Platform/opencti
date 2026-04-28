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


def test_extract_embedded_storage_path_from_get_path(opencti_stix2: OpenCTIStix2):
    uri = "/storage/get/embedded/Note/internal-note-id/a.png"

    result = opencti_stix2._extract_embedded_storage_path(uri)

    assert result == "embedded/Note/internal-note-id/a.png"


def test_extract_embedded_storage_path_from_absolute_view_path(
    opencti_stix2: OpenCTIStix2,
):
    uri = "https://remote.example/storage/view/embedded/Note/internal-note-id/a.png"

    result = opencti_stix2._extract_embedded_storage_path(uri)

    assert result == "embedded/Note/internal-note-id/a.png"


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


def test_prepare_export_rewrites_embedded_markdown_image_uri(
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
        "id": "note--11111111-1111-4111-8111-111111111111",
        "type": "note",
        "x_opencti_id": "internal-note-id",
        "description": "desc ![img](/storage/get/embedded/Note/internal-note-id/a.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_prepare_export_rewrites_embedded_markdown_image_uri_view_path(
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
        "id": "note--55555555-5555-4555-8555-555555555555",
        "type": "note",
        "x_opencti_id": "internal-note-id-5",
        "description": "desc ![img](/storage/view/embedded/Note/internal-note-id-5/a.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-5/a.png"
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


def test_prepare_export_rewrites_embedded_markdown_image_uri_with_escaped_alt_bracket(
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
        "id": "note--12121212-1212-4121-8121-121212121212",
        "type": "note",
        "x_opencti_id": "internal-note-id-12",
        "description": (
            "desc ![A text like \\[this\\]]"
            "(/storage/get/embedded/Note/internal-note-id-12/a.png)"
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert "![A text like \\[this\\]]" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-12/a.png"
    )


def test_prepare_export_rewrites_urlencoded_view_embedded_markdown_image_uri(
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
        "id": "note--77777777-7777-4777-8777-777777777777",
        "type": "note",
        "x_opencti_id": "internal-note-id-7",
        "description": "desc ![img](/storage/view/embedded%2FNote%2Finternal-note-id-7%2Fa.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-7/a.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_prepare_export_rewrites_embedded_markdown_image_uri_with_parentheses_in_filename(
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
        "id": "report--11111111-1111-4111-8111-111111111111",
        "type": "report",
        "x_opencti_id": "internal-report-id-1",
        "description": (
            "desc ![img]("
            "/storage/view/embedded%2FReport%2Finternal-report-id-1%2F"
            "test%20file%20(1)-abc123.png)"
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Report/internal-report-id-1/test file (1)-abc123.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


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


def test_prepare_export_rewrites_embedded_view_url_with_parentheses_and_trailing_text(
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
        "id": "report--33333333-3333-4333-8333-333333333333",
        "type": "report",
        "x_opencti_id": "4279ab6f-2948-4972-b055-6e6f152829af",
        "description": (
            "This is **a test!!**\\n\\n"
            "![02 osint vulnerability triage queue (1).png]("
            "/storage/view/embedded%2FReport%2F4279ab6f-2948-4972-b055-6e6f152829af%2F"
            "02%20osint%20vulnerability%20triage%20queue%20(1)-5f463558.png)\\n\\n"
            "dsfsdfd\\n\\n"
            "![beautiful](https://images.pexels.com/photos/35823637/pexels-photo-35823637.jpeg) "
            "dslfkdsfmf() ()()()()("
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert (
        "https://images.pexels.com/photos/35823637/pexels-photo-35823637.jpeg"
        in result[0]["description"]
    )
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Report/4279ab6f-2948-4972-b055-6e6f152829af/"
        "02 osint vulnerability triage queue (1)-5f463558.png"
    )


def test_prepare_export_retries_with_encoded_storage_path_when_raw_fetch_fails(
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
        if "%20" in url:
            return "Zm9v"
        return None

    monkeypatch.setattr(opencti_stix2.opencti, "fetch_opencti_file", fake_fetch)

    entity = {
        "id": "report--44444444-4444-4444-8444-444444444444",
        "type": "report",
        "x_opencti_id": "4279ab6f-2948-4972-b055-6e6f152829af",
        "description": (
            "![img]("
            "/storage/view/embedded%2FReport%2F4279ab6f-2948-4972-b055-6e6f152829af%2F"
            "02%20osint%20vulnerability%20triage%20queue%20(1)-5f463558.png)"
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 2
    assert "%20" not in fetch_calls[0][0]
    assert "%20" in fetch_calls[1][0]


def test_prepare_export_rewrites_urlencoded_get_embedded_markdown_image_uri(
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
        "id": "note--88888888-8888-4888-8888-888888888888",
        "type": "note",
        "x_opencti_id": "internal-note-id-8",
        "description": "desc ![img](/storage/get/embedded%2FNote%2Finternal-note-id-8%2Fa.png)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-8/a.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


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


def test_prepare_export_rewrites_absolute_embedded_markdown_image_uri(
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
        "id": "note--33333333-3333-4333-8333-333333333333",
        "type": "note",
        "x_opencti_id": "internal-note-id-3",
        "description": (
            "desc ![img](https://remote.example/storage/get/embedded/"
            "Note/internal-note-id-3/a.png)"
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-3/a.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_prepare_export_rewrites_absolute_embedded_markdown_image_uri_view_path(
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
        "id": "note--66666666-6666-4666-8666-666666666666",
        "type": "note",
        "x_opencti_id": "internal-note-id-6",
        "description": (
            "desc ![img](https://remote.example/storage/view/embedded/"
            "Note/internal-note-id-6/a.png)"
        ),
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert "data:image/png;base64,Zm9v" in result[0]["description"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0][0].endswith(
        "/storage/get/embedded/Note/internal-note-id-6/a.png"
    )
    assert fetch_calls[0][1] is True
    assert fetch_calls[0][2] is True


def test_prepare_export_keeps_embedded_non_image_markdown_uri(
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
        "id": "note--44444444-4444-4444-8444-444444444444",
        "type": "note",
        "x_opencti_id": "internal-note-id-4",
        "description": "desc ![doc](/storage/get/embedded/Note/internal-note-id-4/a.pdf)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert (
        result[0]["description"]
        == "desc ![doc](/storage/get/embedded/Note/internal-note-id-4/a.pdf)"
    )
    assert len(fetch_calls) == 1


def test_prepare_export_keeps_embedded_unknown_mime_markdown_uri_after_fetch(
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
        "id": "note--99999999-9999-4999-8999-999999999999",
        "type": "note",
        "x_opencti_id": "internal-note-id-9",
        "description": "desc ![img](/storage/get/embedded/Note/internal-note-id-9/image-without-extension)",
    }

    result = opencti_stix2.prepare_export(entity=entity, mode="simple")

    assert len(result) == 1
    assert (
        result[0]["description"]
        == "desc ![img](/storage/get/embedded/Note/internal-note-id-9/image-without-extension)"
    )
    assert len(fetch_calls) == 1
