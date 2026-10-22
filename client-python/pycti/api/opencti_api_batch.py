import re
from typing import Dict, List, Optional, Tuple

from pycti.entities.opencti_external_reference import ExternalReference

LOCKFREE_IMPORT_QUERY = """
    mutation LockfreeImport($operations: [LockfreeOperationInput!]) {
        lockfreeImport(operations: $operations) {
            status
            id
            error
            code
        }
    }
"""
# The single top-level field of a mutation document
MUTATION_FIELD = re.compile(r"^\s*mutation\b[^{]*\{\s*(\w+)\s*\(", re.S)
# Creates whose result pycti keeps across messages (by label value, kill chain phase...): sent as usual, so that
# its caches only ever hold ids the platform knows
NOT_BATCHED = {"labelAdd", "killChainPhaseAdd", "vocabularyAdd", "markingDefinitionAdd"}


def _camel_to_type(field: str) -> str:
    """intrusionSetAdd -> Intrusion-Set"""
    words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", field[: -len("Add")])
    return "-".join(word[:1].upper() + word[1:] for word in words)


def _has_files(value) -> bool:
    if isinstance(value, dict):
        return any(_has_files(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_files(v) for v in value)
    return hasattr(value, "data") and hasattr(value, "mime")


class BatchImport:
    """Creates of a bundle sent together to the lock-free batch import.

    While a batch is open on a client (:py:meth:`OpenCTIApiClient.batch_import`), each create mutation pycti sends
    for a STIX object, a relationship, a sighting or an external reference is kept instead of sent, and answered
    with a placeholder: its STIX id, which the platform resolves like any other id. Kept creates go to the platform
    in one ``lockfreeImport`` request per chunk, which runs them through their usual resolvers in dependency order
    and writes them with the lock-free path. Any other request first sends what was kept, so the platform sees the
    calls in the order pycti made them.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :param chunk_size: kept creates that trigger a send
    """

    def __init__(self, api, chunk_size: int = 500):
        self.api = api
        self.chunk_size = chunk_size
        self.operations: List[Dict] = []
        self.owners: List[Optional[int]] = []
        self.owner: Optional[int] = None  # the bundle item the kept creates belong to
        self.failed: Dict[int, Tuple[str, Optional[str]]] = {}  # item -> (error, code)
        self.unsupported = (
            False  # the platform has no batch import: nothing more is kept
        )

    def _ref_and_type(self, field: str, variables: Dict) -> Tuple[Optional[str], str]:
        data = (
            variables.get("input") if isinstance(variables.get("input"), dict) else None
        )
        if field == "stixCyberObservableAdd":
            return (
                variables.get("stix_id"),
                variables.get("type") or "Stix-Cyber-Observable",
            )
        if data is None:
            return None, ""
        if field == "stixCoreRelationshipAdd":
            return (
                data.get("stix_id"),
                data.get("relationship_type") or "stix-core-relationship",
            )
        if field == "stixSightingRelationshipAdd":
            return data.get("stix_id"), "stix-sighting-relationship"
        if field == "externalReferenceAdd":
            ref = data.get("stix_id") or ExternalReference.generate_id(
                data.get("url"), data.get("source_name"), data.get("external_id")
            )
            return ref, "External-Reference"
        return data.get("stix_id"), data.get("type") or _camel_to_type(field)

    def capture(self, query: str, variables: Optional[Dict]):
        """Keeps a create and answers it with a placeholder, or returns None for a request to send now."""
        if self.unsupported:
            return None
        match = MUTATION_FIELD.match(query)
        if match is None:
            return None
        field = match.group(1)
        variables = variables or {}
        if not field.endswith("Add") or field in NOT_BATCHED or _has_files(variables):
            return None
        ref, entity_type = self._ref_and_type(field, variables)
        if not ref:
            return None
        self.operations.append({"ref": ref, "query": query, "variables": variables})
        self.owners.append(self.owner)
        if len(self.operations) >= self.chunk_size:
            self.flush()
        placeholder = {
            "id": ref,
            "standard_id": ref,
            "entity_type": entity_type,
            "parent_types": [],
            "x_opencti_stix_ids": [],
        }
        return {"data": {field: placeholder}}

    def flush(self):
        """Sends the kept creates; the bundle items with a create that failed are recorded in ``failed``."""
        if not self.operations:
            return
        operations, owners = self.operations, self.owners
        self.operations, self.owners = [], []
        try:
            result = self.api.send_query(
                LOCKFREE_IMPORT_QUERY, {"operations": operations}
            )
            rows = result["data"]["lockfreeImport"]
        except Exception as ex:  # pylint: disable=broad-except
            # Refused as a whole (no batch import on this platform, or not ready): those items go the usual way
            message = str(ex)
            if "lockfreeImport" in message or "Lock-free ingestion is not" in message:
                self.unsupported = True
            for owner in owners:
                if owner is not None:
                    self.failed.setdefault(owner, (message, None))
            return
        for owner, row in zip(owners, rows):
            if owner is not None and row["status"] == "error":
                self.failed.setdefault(owner, (row.get("error"), row.get("code")))
