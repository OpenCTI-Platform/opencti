from pycti.api.opencti_api_client import OpenCTIApiClient


class _SizedValue:
    def __init__(self, length):
        self.length = length
        self.len_calls = 0

    def __len__(self):
        self.len_calls += 1
        return self.length


def test_not_empty_stops_after_first_non_empty_list_value():
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    first = _SizedValue(1)
    second = _SizedValue(0)

    assert client.not_empty([first, second]) is True
    assert first.len_calls == 1
    assert second.len_calls == 0
