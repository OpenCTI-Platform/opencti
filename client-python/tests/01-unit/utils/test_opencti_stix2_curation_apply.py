"""Worker side of the CURATION_APPLY background task.

Every bulk acceptance and every policy auto-apply of a curation proposal reaches the
platform through this path: the task manager sends one bundle item per proposal, with
`opencti_operation: curation_apply` (and the policy id when a policy applies it) in the
OpenCTI extension, and the worker turns it into a `curationProposalApply` mutation.
"""

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2

OCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PROPOSAL_STANDARD_ID = "curation-proposal--5f0e8d4b-7c1e-4f55-9b3a-2f6a1d9e7c10"
PROPOSAL_INTERNAL_ID = "1c7a3b5e-9d2f-4e8a-b6c4-0f1e2d3c4b5a"
POLICY_ID = "8e4d2c1b-3a5f-4b6c-9d7e-1f2a3b4c5d6e"


@pytest.fixture
def opencti_stix2():
    api_client = OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )
    return OpenCTIStix2(api_client)


@pytest.fixture
def queries(opencti_stix2, monkeypatch):
    """Record the GraphQL calls instead of sending them."""
    calls = []

    def fake_query(query, variables=None, *args, **kwargs):
        calls.append((query, variables))
        return {"data": {"curationProposalApply": {"id": PROPOSAL_INTERNAL_ID}}}

    monkeypatch.setattr(opencti_stix2.opencti, "query", fake_query)
    return calls


def curation_task_item(**extension):
    """A bundle item as the task manager builds it for a CURATION_APPLY task."""
    return {
        "id": PROPOSAL_STANDARD_ID,
        "type": "curation-proposal",
        "extensions": {
            OCTI_EXTENSION: {
                "id": PROPOSAL_INTERNAL_ID,
                "type": "CurationProposal",
                "opencti_operation": "curation_apply",
                **extension,
            }
        },
    }


def test_curation_apply_sends_the_internal_proposal_id_and_the_policy(
    opencti_stix2: OpenCTIStix2, queries
):
    opencti_stix2.curation_apply(curation_task_item(curation_policy_id=POLICY_ID))

    assert len(queries) == 1
    query, variables = queries[0]
    assert "curationProposalApply(id: $id, policy_id: $policy_id)" in query
    # The internal id of the extension, not the standard id of the bundle item.
    assert variables == {"id": PROPOSAL_INTERNAL_ID, "policy_id": POLICY_ID}


def test_curation_apply_without_policy_sends_a_null_policy(
    opencti_stix2: OpenCTIStix2, queries
):
    # A bulk acceptance carries a null policy id; an older task carries none at all.
    opencti_stix2.curation_apply(curation_task_item(curation_policy_id=None))
    opencti_stix2.curation_apply(curation_task_item())

    assert [variables for _, variables in queries] == [
        {"id": PROPOSAL_INTERNAL_ID, "policy_id": None},
        {"id": PROPOSAL_INTERNAL_ID, "policy_id": None},
    ]


def test_curation_apply_falls_back_to_the_item_id(opencti_stix2: OpenCTIStix2, queries):
    item = {
        "id": PROPOSAL_INTERNAL_ID,
        "type": "curation-proposal",
        "opencti_operation": "curation_apply",
        "curation_policy_id": POLICY_ID,
    }

    opencti_stix2.curation_apply(item)

    assert queries[0][1] == {"id": PROPOSAL_INTERNAL_ID, "policy_id": POLICY_ID}


def test_import_item_dispatches_the_curation_apply_operation(
    opencti_stix2: OpenCTIStix2, queries
):
    assert opencti_stix2.import_item(curation_task_item(curation_policy_id=POLICY_ID))

    assert len(queries) == 1
    query, variables = queries[0]
    assert "mutation CurationProposalApply" in query
    assert variables == {"id": PROPOSAL_INTERNAL_ID, "policy_id": POLICY_ID}


def test_apply_opencti_operation_routes_curation_apply(
    opencti_stix2: OpenCTIStix2, monkeypatch
):
    applied = []
    monkeypatch.setattr(
        opencti_stix2, "curation_apply", lambda item: applied.append(item)
    )
    item = curation_task_item()

    opencti_stix2.apply_opencti_operation(item, "curation_apply", None)

    assert applied == [item]
