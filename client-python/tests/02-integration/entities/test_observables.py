# coding: utf-8


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
