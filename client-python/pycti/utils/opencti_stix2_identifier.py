import uuid

from stix2.canonicalization.Canonicalize import canonicalize


def external_reference_generate_id(url=None, source_name=None, external_id=None):
    if url is not None:
        data = {"url": url}
    elif source_name is not None and external_id is not None:
        data = {"source_name": source_name, "external_id": external_id}
    else:
        return None
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "external-reference--" + id


def kill_chain_phase_generate_id(phase_name, kill_chain_name):
    data = {"phase_name": phase_name, "kill_chain_name": kill_chain_name}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "kill-chain-phase--" + id
