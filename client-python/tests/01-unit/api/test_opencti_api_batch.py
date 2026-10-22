from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.api.opencti_api_batch import BatchImport, _camel_to_type

INTRUSION_SET_ADD = """
    mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
        intrusionSetAdd(input: $input) { id standard_id entity_type }
    }
"""
OBSERVABLE_ADD = """
    mutation StixCyberObservableAdd($type: String!, $stix_id: StixId) {
        stixCyberObservableAdd(type: $type, stix_id: $stix_id) { id }
    }
"""
EXTERNAL_REFERENCE_ADD = """
    mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
        externalReferenceAdd(input: $input) { id }
    }
"""
LABEL_ADD = """
    mutation LabelAdd($input: LabelAddInput!) { labelAdd(input: $input) { id } }
"""
READ = "query Labels { labels { edges { node { id } } } }"


@pytest.fixture
def api_client():
    """Create an API client instance without performing health check."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


def intrusion_set(stix_id):
    return {"input": {"name": "APT", "stix_id": stix_id}}


class TestCapture:
    """Creates of STIX objects are kept, answered with their STIX id."""

    def test_keeps_a_create_and_answers_with_its_stix_id(self, api_client):
        batch = BatchImport(api_client)
        batch.owner = 7
        answer = batch.capture(INTRUSION_SET_ADD, intrusion_set("intrusion-set--1"))
        assert answer == {
            "data": {
                "intrusionSetAdd": {
                    "id": "intrusion-set--1",
                    "standard_id": "intrusion-set--1",
                    "entity_type": "Intrusion-Set",
                    "parent_types": [],
                    "x_opencti_stix_ids": [],
                }
            }
        }
        assert batch.operations[0]["ref"] == "intrusion-set--1"
        assert batch.owners == [7]

    def test_observable_ref_and_type_come_from_the_variables(self, api_client):
        batch = BatchImport(api_client)
        answer = batch.capture(
            OBSERVABLE_ADD, {"type": "IPv4-Addr", "stix_id": "ipv4-addr--1"}
        )
        assert answer["data"]["stixCyberObservableAdd"]["id"] == "ipv4-addr--1"
        assert answer["data"]["stixCyberObservableAdd"]["entity_type"] == "IPv4-Addr"

    def test_external_reference_without_stix_id_gets_its_generated_id(self, api_client):
        batch = BatchImport(api_client)
        answer = batch.capture(
            EXTERNAL_REFERENCE_ADD,
            {
                "input": {
                    "source_name": "mitre-attack",
                    "url": "https://x",
                    "external_id": "T1",
                }
            },
        )
        ref = answer["data"]["externalReferenceAdd"]["id"]
        assert ref.startswith("external-reference--")

    @pytest.mark.parametrize(
        "query, variables",
        [
            (LABEL_ADD, {"input": {"value": "apt"}}),  # cached across messages
            (READ, {}),  # not a create
            (INTRUSION_SET_ADD, {"input": {"name": "no stix id"}}),  # no ref
        ],
    )
    def test_sends_now_what_it_cannot_keep(self, api_client, query, variables):
        assert BatchImport(api_client).capture(query, variables) is None

    def test_sends_now_a_create_with_files(self, api_client):
        variables = intrusion_set("intrusion-set--1")
        variables["input"]["file"] = api_client.file("a.txt", "data", "text/plain")
        assert BatchImport(api_client).capture(INTRUSION_SET_ADD, variables) is None

    def test_type_from_the_mutation_name(self):
        assert _camel_to_type("intrusionSetAdd") == "Intrusion-Set"
        assert _camel_to_type("attackPatternAdd") == "Attack-Pattern"
        assert _camel_to_type("reportAdd") == "Report"


class TestFlush:
    """Kept creates go in one request; failed ones are recorded per bundle item."""

    def test_records_the_items_whose_creates_failed(self, api_client):
        batch = BatchImport(api_client)
        for owner, stix_id in ((0, "intrusion-set--1"), (1, "intrusion-set--2")):
            batch.owner = owner
            batch.capture(INTRUSION_SET_ADD, intrusion_set(stix_id))
        rows = [
            {"status": "done", "id": "a", "error": None, "code": None},
            {
                "status": "error",
                "id": None,
                "error": "nope",
                "code": "MISSING_REFERENCE_ERROR",
            },
        ]
        with patch.object(
            api_client, "send_query", return_value={"data": {"lockfreeImport": rows}}
        ) as send:
            batch.flush()
        assert send.call_count == 1
        assert len(send.call_args.args[1]["operations"]) == 2
        assert batch.failed == {1: ("nope", "MISSING_REFERENCE_ERROR")}
        assert batch.operations == []

    def test_a_platform_without_batch_import_stops_the_batch(self, api_client):
        batch = BatchImport(api_client)
        batch.owner = 3
        batch.capture(INTRUSION_SET_ADD, intrusion_set("intrusion-set--1"))
        error = ValueError(
            {"error_message": 'Cannot query field "lockfreeImport" on type "Mutation".'}
        )
        with patch.object(api_client, "send_query", side_effect=error):
            batch.flush()
        assert 3 in batch.failed
        assert batch.unsupported
        assert (
            batch.capture(INTRUSION_SET_ADD, intrusion_set("intrusion-set--2")) is None
        )

    def test_a_full_chunk_is_sent_at_once(self, api_client):
        batch = BatchImport(api_client, chunk_size=2)
        with patch.object(
            api_client,
            "send_query",
            return_value={"data": {"lockfreeImport": [{"status": "done"}] * 2}},
        ) as send:
            batch.capture(INTRUSION_SET_ADD, intrusion_set("intrusion-set--1"))
            assert send.call_count == 0
            batch.capture(INTRUSION_SET_ADD, intrusion_set("intrusion-set--2"))
            assert send.call_count == 1


class TestClientBatch:
    """Inside a batch, any other request first sends what was kept, so the order stays pycti's."""

    def test_other_requests_send_the_kept_creates_first(self, api_client):
        calls = []

        def send(query, variables=None, *args, **kwargs):
            calls.append("import" if "lockfreeImport" in query else "read")
            if "lockfreeImport" in query:
                return {"data": {"lockfreeImport": [{"status": "done"}]}}
            return {"data": {"labels": {"edges": []}}}

        with patch.object(api_client, "send_query", side_effect=send):
            with api_client.batch_import():
                api_client.query(INTRUSION_SET_ADD, intrusion_set("intrusion-set--1"))
                api_client.query(READ)
        assert calls == ["import", "read"]

    def test_outside_a_batch_requests_go_as_usual(self, api_client):
        with patch.object(api_client, "send_query", return_value={"data": {}}) as send:
            api_client.query(INTRUSION_SET_ADD, intrusion_set("intrusion-set--1"))
        assert send.call_count == 1
