# coding: utf-8
import datetime
import json


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
