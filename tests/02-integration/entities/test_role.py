from tests.cases.entities import RoleTest


def test_role_capabilities(api_client):
    role_test = RoleTest(api_client)
    role_data = role_test.data()
    test_role = role_test.own_class().create(**role_data)
    assert test_role is not None, "Create role response is NoneType"

    capability_id = api_client.capability.list()[0]["id"]

    role_test.own_class().add_capability(
        id=test_role["id"], capability_id=capability_id
    )
    result = role_test.own_class().read(id=test_role["id"])
    assert capability_id in result["capabilitiesIds"]

    role_test.own_class().delete_capability(
        id=test_role["id"], capability_id=capability_id
    )
    result = role_test.own_class().read(id=test_role["id"])
    assert capability_id not in result["capabilitiesIds"]

    role_test.base_class().delete(id=test_role["id"])
