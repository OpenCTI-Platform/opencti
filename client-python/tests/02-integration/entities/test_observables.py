# coding: utf-8
import datetime
import json


def test_windows_registry_key_values_creation(api_client):
    # https://github.com/OpenCTI-Platform/opencti/issues/2574
    with open("tests/data/windows_registry_key_bundle.json", "r") as content_file:
        content = content_file.read()
    bundle = json.loads(content)

    imported_objects, _ = api_client.stix2.import_bundle_from_json(json_data=content)
    assert imported_objects is not None
    assert len(imported_objects) == 2

    key_without_values, key_with_values = bundle["objects"]

    registry_key_1 = api_client.stix_cyber_observable.read(id=key_without_values["id"])
    assert registry_key_1["attribute_key"] == key_without_values["key"]

    registry_key_2 = api_client.stix_cyber_observable.read(id=key_with_values["id"])
    assert registry_key_2["attribute_key"] == key_with_values["key"]

    nested = api_client.query(
        """
            query WindowsRegistryKeyValues($fromOrToId: String) {
                stixNestedRefRelationships(fromOrToId: $fromOrToId, relationship_type: ["values"]) {
                    edges {
                        node {
                            to {
                                ... on WindowsRegistryValueType {
                                    name
                                    data
                                    data_type
                                }
                            }
                        }
                    }
                }
            }
        """,
        {"fromOrToId": registry_key_2["id"]},
    )
    edges = nested["data"]["stixNestedRefRelationships"]["edges"]
    values = {
        (e["node"]["to"]["name"], e["node"]["to"]["data"], e["node"]["to"]["data_type"])
        for e in edges
    }
    expected = {
        (v["name"], v["data"], v["data_type"]) for v in key_with_values["values"]
    }
    assert values == expected


def test_promote_observable_to_indicator_deprecated(api_client):
    # deprecated [>=6.2 & <6.8]
    obs1 = api_client.stix_cyber_observable.create(
        simple_observable_key="IPv4-Addr.value", simple_observable_value="55.55.55.55"
    )
    observable = api_client.stix_cyber_observable.promote_to_indicator(
        id=obs1.get("id")
    )
    assert observable is not None, "Returned observable is NoneType"
    assert observable.get("id") == obs1.get("id")


def test_certificate_creation_mapping(api_client):
    with open("tests/data/certificate.json", "r") as content_file:
        content = json.loads(content_file.read())

    result = api_client.stix_cyber_observable.create(observableData=content)
    assert result is not None

    certificate = api_client.stix_cyber_observable.read(id=result["id"])

    for key in content:
        if key == "type":
            assert certificate["entity_type"] == "X509-Certificate"
        elif key == "hashes":
            assert {
                item["algorithm"]: item["hash"] for item in certificate["hashes"]
            } == content["hashes"]
        elif key in [
            "validity_not_before",
            "validity_not_after",
            "private_key_usage_period_not_before",
            "private_key_usage_period_not_after",
        ]:
            assert datetime.datetime.fromisoformat(
                certificate[key].replace("Z", "+00:00")
            ) == datetime.datetime.fromisoformat(content[key].replace("Z", "+00:00"))

        else:
            assert certificate[key] == content[key]
