import json

from pycti import OpenCTIApiClient, OpenCTIStix2


def get_cti_helper():
    client = OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )
    return OpenCTIStix2(client)


def load_test_file():
    with open("tests/data/bundle_ids_sample.json", "r") as content_file:
        content = content_file.read()
    bundle_data = json.loads(content)
    return bundle_data


# !! WARNING !!, this need to be changed along with 01-unit/domain/identifier-test.js
# fmt: off
def test_ids_generation():
    gen_id = get_cti_helper().generate_standard_id_from_stix
    # attack-pattern
    assert gen_id({"type": "attack-pattern", "name": "attack"}) =='attack-pattern--25f21617-8de8-5d5e-8cd4-b7e88547ba76'
    assert gen_id({"type": "attack-pattern", "name": "attack", "x_opencti_external_id": 'MITREID'}) == 'attack-pattern--b74cfee2-7b14-585e-862f-fea45e802da9'
    assert gen_id({"type": "attack-pattern", "name": "Spear phishing messages with malicious links", "x_mitre_id": 'T1368'}) == 'attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890'
    assert gen_id({"type": "attack-pattern", "x_mitre_id": "MITREID"}) == 'attack-pattern--b74cfee2-7b14-585e-862f-fea45e802da9'
    assert gen_id({"type": "attack-pattern", "name": "Evil Pattern!", "description": "Test Attack Pattern!"}) == 'attack-pattern--23a5b210-f675-5936-ae14-21327e9798e2'
    # campaign
    assert gen_id({"type": "campaign", "name": "attack"}) == 'campaign--25f21617-8de8-5d5e-8cd4-b7e88547ba76'
    # note
    assert gen_id({"type": "note", "content": "My note content!"}) == "note--2b4ab5af-2307-58e1-8862-a6a269aae798"
    assert gen_id({"type": "note", "content": "My note content!", "created": "2022-11-25T19:00:05.000Z"}) == "note--10861e5c-049e-54f6-9736-81c106e39a0b"
    # observed-data
    assert gen_id({"type": "observed-data", "object_refs": ["id"]}) == "observed-data--4765c523-81bc-54c8-b1af-ee81d961dad1"
    # opinion
    assert gen_id({"type": "opinion", "opinion": "Good"}) == "opinion--0aef8829-207e-508b-b1f1-9da07f3379cb"
    assert gen_id({"type": "opinion", "opinion": "Good", "created": "2022-11-25T19:00:05.000Z"}) == "opinion--941dbd61-c6b1-5290-b63f-19a38983d7f7"
    # report
    assert gen_id({"type": "report", "name": "Report", "published": "2022-11-25T19:00:05.000Z"}) == "report--761c6602-975f-5e5e-b220-7a2d41f33ce4"
    # course-of-action
    assert gen_id({"type": "course-of-action", "x_mitre_id": "MITREID"}) == "course-of-action--b74cfee2-7b14-585e-862f-fea45e802da9"
    assert gen_id({"type": "course-of-action", "x_mitre_id": "MITREID", "name": "Name"}) == "course-of-action--b74cfee2-7b14-585e-862f-fea45e802da9"
    assert gen_id({"type": "course-of-action", "name": "Name"}) == "course-of-action--e6e2ee8d-e54d-50cd-b77c-df8c8eea7726"
    # identity
    assert gen_id({"type": "identity", "name": "julien", "identity_class": "Individual"}) == "identity--d969b177-497f-598d-8428-b128c8f5f819"
    assert gen_id({"type": "identity", "name": "julien", "identity_class": "Sector"}) == "identity--14ffa2a4-e16a-522a-937a-784c0ac1fab0"
    assert gen_id({"type": "identity", "name": "julien", "identity_class": "System"}) == "identity--8af97482-121d-53f7-a533-9c48f06b5a38"
    assert gen_id({"type": "identity", "name": "organization", "identity_class": "individual"}) == "identity--00f7eb8c-6af2-5ed5-9ede-ede4c623de3b"
    # infrastructure
    assert gen_id({"type": "infrastructure", "name": "infra"}) == "infrastructure--8a20116f-5a41-5508-ae4b-c293ac67c527"
    # intrusion-set
    assert gen_id({"type": "intrusion-set", "name": "intrusion"}) == "intrusion-set--30757026-c4bd-574d-ae52-8d8503b4818e"
    # location
    assert gen_id({"type": "location", "name": "Lyon", "x_opencti_location_type": "City"}) == "location--da430873-42c8-57ca-b08b-a797558c6cbd"
    assert gen_id({"type": "location", "latitude": 5.12, "name": "Position1", "x_opencti_location_type": "Position"}) == "location--56b3fc50-5091-5f2e-bd19-7b40ee3881e4"
    assert gen_id({"type": "location", "longitude": 5.12, "name": 'Position2', "x_opencti_location_type": "Position"}) == "location--dd2cf94c-1d58-58a1-b21f-0ede4059aaf0"
    assert gen_id({"type": "location", "latitude": 5.12, "longitude": 5.12, "x_opencti_location_type": "Position"}) == "location--57acef55-747a-55ef-9c49-06ca85f8d749"
    assert gen_id({"type": "location", "name": 'Position3', "x_opencti_location_type": "Position"}) == "location--a4152781-8721-5d44-ae2d-e492665bc35b"
    # malware
    assert gen_id({"type": "malware", "name": "malware"}) == "malware--92ddf766-b27c-5159-8f46-27002bba2f04"
    # threat-actor-group
    assert gen_id({"type": "threat-actor", "name": "CARD04"}) == "threat-actor--6d458783-df3b-5398-8e30-282655ad7b94"
    assert gen_id({"type": "threat-actor", "name": "CARD04", "x_opencti_type": "Threat-Actor-Group"}) == "threat-actor--6d458783-df3b-5398-8e30-282655ad7b94"
    # tool
    assert gen_id({"type": "tool", "name": "my-tool"}) == "tool--41cd21d0-f50e-5e3d-83fc-447e0def97b7"
    # vulnerability
    assert gen_id({"type": "vulnerability", "name": "vulnerability"}) == "vulnerability--2c690168-aec3-57f1-8295-adf53f4dc3da"
    # incident
    assert gen_id({"type": "incident", "name": "incident", "created": "2022-11-25T19:00:05.000Z"}) == "incident--0e117c15-0a94-5ad3-b090-0395613f5b29"
    # case-incident
    assert gen_id({"type": "case-incident", "name": "case", "created": "2022-11-25T19:00:05.000Z"}) == "case-incident--4838a141-bd19-542c-85d9-cce0382645b5"
    # case-rfi
    assert gen_id({"type": "case-rfi", "name": "case", "created": "2022-11-25T19:00:05.000Z"}) == "case-rfi--4838a141-bd19-542c-85d9-cce0382645b5"
    # case-rft
    assert gen_id({"type": "case-rft", "name": "case", "created": "2022-11-25T19:00:05.000Z"}) == "case-rft--4838a141-bd19-542c-85d9-cce0382645b5"
    # feedback, not supported yet
    # assert gen_id("case-feedback", {"name": "case", "created": "2022-11-25T19:00:05.000Z"}) == "feedback--4838a141-bd19-542c-85d9-cce0382645b5"
    # channel
    assert gen_id({"type": "channel", "name": "channel"}) == "channel--4936cdd5-6b6a-5c92-a756-cae1f09dcd80"
    # data-component
    assert gen_id({"type": "data-component", "name": "data-component"}) == "data-component--32fdc52a-b4c5-5268-af2f-cdf820271f0b"
    # data-source
    assert gen_id({"type": "data-source", "name": "data-source"}) == "data-source--f0925972-35e1-5172-9161-4d7180908339"
    # grouping
    assert gen_id({"type": "grouping", "name": "grouping", "context": "context", "created": "2022-11-25T19:00:05.000Z"}) == "grouping--7c3e3534-9c09-568a-9485-377054b4c588"
    # language
    assert gen_id({"type": "language", "name": "fr"}) == "language--0ef28873-9d49-5cdb-a53a-eb7613391ee9"
    # malware-analysis
    assert gen_id({"type": "malware-analysis", "product": "linux", "result_name": "result"}) == "malware-analysis--3d501241-a4a5-574d-a503-301a6426f8c1"
    assert gen_id({"type": "malware-analysis", "product": "linux", "result_name": "result", "submitted": "2022-11-25T19:00:05.000Z"}) == "malware-analysis--d7ffe68a-0d5f-5fea-a375-3338ba4ea13c"
    # narrative
    assert gen_id({"type": "narrative", "name": "narrative"}) == "narrative--804a7e40-d39c-59b6-9e3f-1ba1bc92b739"
    # task
    assert gen_id({"type": "task", "name": "case", "created": "2022-11-25T19:00:05.000Z"}) == "task--4838a141-bd19-542c-85d9-cce0382645b5"
    # Threat-actor-individual
    assert gen_id({"type": "threat-actor", "name": "CARD04", "x_opencti_type": "Threat-Actor-Individual"}) == "threat-actor--af15b6ae-a3dd-54d3-8fa0-3adfe0391d01"
    # vocabulary
    assert gen_id({"type": "vocabulary", "name": "facebook", "category": "account_type_ov"}) == "vocabulary--85ae7185-ff6f-509b-a011-3069921614aa"
    # relationship
    base_relationship = {"type": "relationship", "relationship_type": "based-on", "source_ref": "from_id", "target_ref": "to_id"}
    assert gen_id(base_relationship) == "relationship--0b11fa67-da01-5d34-9864-67d4d71c3740"
    assert gen_id({**base_relationship, "start_time": "2022-11-25T19:00:05.000Z"}) == "relationship--c5e1e2ce-14d6-535b-911d-267e92119e01"
    assert gen_id({**base_relationship, "start_time": "2022-11-25T19:00:05.000Z", "stop_time": "2022-11-26T19:00:05.000Z"}) == "relationship--a7778a7d-a743-5193-9912-89f88f9ed0b4"
    assert gen_id({"type": "relationship", 'relationship_type': 'uses', 'source_ref': 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714', 'start_time': '2020-02-29T22:30:00.000Z', 'stop_time': '2020-02-29T22:30:00.000Z', 'target_ref': 'attack-pattern--fd8179dd-1632-5ec8-8b93-d2ae121e05a4'}) == 'relationship--67f5f01f-6b15-5154-ae31-019a75fedcff'
    # sighting
    base_sighting = {"type": "sighting", "sighting_of_ref": "from_id", "where_sighted_refs": ["to_id"]}
    assert gen_id(base_sighting) == 'sighting--161901df-21bb-527a-b96b-354119279fe2'
    assert gen_id({**base_sighting, "first_seen": "2022-11-25T19:00:05.000Z"}) == "sighting--3c59ceea-8e41-5adb-a257-d070d19e6d2b"
    assert gen_id({**base_sighting, "first_seen": "2022-11-25T19:00:05.000Z", "last_seen": "2022-11-26T19:00:05.000Z"}) == "sighting--b4d307b6-d22c-5f22-b530-876c298493da"
# fmt: on
