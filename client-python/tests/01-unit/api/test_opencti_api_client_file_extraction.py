import io

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


class _UploadResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"data": {"ok": True}}


class _TrackingFile(io.BytesIO):
    def __init__(self, payload):
        super().__init__(payload)
        self.read_calls = 0

    def read(self, *args, **kwargs):
        self.read_calls += 1
        return super().read(*args, **kwargs)


class _UploadSession:
    def __init__(self, upload):
        self.upload = upload
        self.body = None
        self.content_type = None
        self.read_calls_before_post = None

    def post(self, *args, **kwargs):
        del args
        self.read_calls_before_post = self.upload.read_calls
        assert "files" not in kwargs
        multipart_stream = kwargs["data"]
        self.content_type = kwargs["headers"]["Content-Type"]
        self.body = b"".join(multipart_stream)
        return _UploadResponse()


def test_query_streams_multipart_file_body():
    upload = _TrackingFile(b"payload")
    client = _client()
    client.api_url = "http://benchmark.invalid/graphql"
    client.request_headers = {}
    client.ssl_verify = False
    client.cert = None
    client.proxies = None
    client.session_requests_timeout = 300
    client.session = _UploadSession(upload)

    result = client.query(
        "mutation Upload($file: Upload!) { uploadImport(file: $file) { id } }",
        {"file": File("artifact.txt", upload, "text/plain")},
    )

    assert result == {"data": {"ok": True}}
    assert client.session.read_calls_before_post == 0
    assert client.session.content_type.startswith("multipart/form-data; boundary=")
    assert b'filename="artifact.txt"' in client.session.body
    assert b"payload" in client.session.body
