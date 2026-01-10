import uuid

from stix2.canonicalization.Canonicalize import canonicalize


def external_reference_generate_id(url=None, source_name=None, external_id=None):
    """Generate a STIX ID for an external reference.

    :param url: URL of the external reference
    :type url: str
    :param source_name: Source name of the external reference
    :type source_name: str
    :param external_id: External ID of the reference
    :type external_id: str
    :return: Generated STIX ID or None if insufficient data
    :rtype: str or None
    """
    if url is not None:
        data = {"url": url}
    elif source_name is not None and external_id is not None:
        data = {"source_name": source_name, "external_id": external_id}
    else:
        return None
    data = canonicalize(data, utf8=False)
    generated_id = str(
        uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data)
    )
    return "external-reference--" + generated_id


def kill_chain_phase_generate_id(phase_name, kill_chain_name):
    """Generate a STIX ID for a kill chain phase.

    :param phase_name: Name of the phase
    :type phase_name: str
    :param kill_chain_name: Name of the kill chain
    :type kill_chain_name: str
    :return: Generated STIX ID
    :rtype: str
    """
    data = {"phase_name": phase_name, "kill_chain_name": kill_chain_name}
    data = canonicalize(data, utf8=False)
    generated_id = str(
        uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data)
    )
    return "kill-chain-phase--" + generated_id
