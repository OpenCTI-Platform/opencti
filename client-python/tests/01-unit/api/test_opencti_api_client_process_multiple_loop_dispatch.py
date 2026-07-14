from pycti.api.opencti_api_client import OpenCTIApiClient


class _CountingClient(OpenCTIApiClient):
    @property
    def process_multiple_fields(self):
        self.process_multiple_fields_lookups += 1
        return self._process_multiple_fields

    def _process_multiple_fields(self, data):
        self.processed_rows += 1
        return data


def _build_client():
    client = _CountingClient.__new__(_CountingClient)
    client.process_multiple_fields_lookups = 0
    client.processed_rows = 0
    return client


def test_process_multiple_reuses_row_processor_for_paginated_direct_lists():
    client = _build_client()
    rows = [{"id": "one"}, {"id": "two"}, {"id": "three"}]

    assert client.process_multiple(rows, with_pagination=True) == {
        "entities": rows,
        "pagination": {},
    }
    assert client.processed_rows == 3
    assert client.process_multiple_fields_lookups == 1


def test_process_multiple_reuses_row_processor_for_paginated_edges():
    client = _build_client()
    data = {
        "edges": [{"node": {"id": "one"}}, {"node": {"id": "two"}}],
        "pageInfo": {"hasNextPage": False},
    }

    assert client.process_multiple(data, with_pagination=True) == {
        "entities": [{"id": "one"}, {"id": "two"}],
        "pagination": {"hasNextPage": False},
    }
    assert client.processed_rows == 2
    assert client.process_multiple_fields_lookups == 1
