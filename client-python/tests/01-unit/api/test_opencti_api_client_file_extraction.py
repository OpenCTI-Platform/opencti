from pycti.api.opencti_api_client import File, OpenCTIApiClient


def _client():
    return OpenCTIApiClient.__new__(OpenCTIApiClient)


def test_extract_files_reuses_non_upload_variable_tree():
    variables = {
        "filters": [
            {
                "key": ["entity_type"],
                "values": ["Indicator", "Report"],
                "nested": {"labels": ["one", "two"]},
            }
        ],
        "search": "benchmark",
    }

    cleaned, files = _client()._extract_files(variables)

    assert cleaned is variables
    assert files == []


def test_extract_files_copies_only_upload_paths_without_mutating_input():
    upload = File("artifact.txt", b"content")
    variables = {
        "input": {
            "name": "artifact",
            "metadata": {"labels": ["one", "two"]},
            "file": upload,
        },
        "unchanged": {"nested": ["value"]},
    }

    cleaned, files = _client()._extract_files(variables)

    assert cleaned is not variables
    assert cleaned["input"] is not variables["input"]
    assert cleaned["input"]["metadata"] is variables["input"]["metadata"]
    assert cleaned["unchanged"] is variables["unchanged"]
    assert cleaned["input"]["file"] is None
    assert variables["input"]["file"] is upload
    assert files == [{"key": "input.file", "file": upload, "multiple": False}]


def test_extract_files_preserves_multiple_and_mixed_upload_paths():
    first_upload = File("first.txt", b"first")
    second_upload = File("second.txt", b"second")
    mixed_upload = File("mixed.txt", b"mixed")
    variables = {
        "files": [first_upload, second_upload],
        "mixed": ["keep", mixed_upload],
    }

    cleaned, files = _client()._extract_files(variables)

    assert cleaned == {"files": [None, None], "mixed": ["keep", None]}
    assert variables == {
        "files": [first_upload, second_upload],
        "mixed": ["keep", mixed_upload],
    }
    assert files == [
        {"key": "files", "file": [first_upload, second_upload], "multiple": True},
        {"key": "mixed.1", "file": mixed_upload, "multiple": False},
    ]
