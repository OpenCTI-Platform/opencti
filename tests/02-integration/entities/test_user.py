from tests.cases.entities import GroupTest, IdentityOrganizationTest, UserTest


def test_user_membership(api_client):
    user_test = UserTest(api_client)
    group_test = GroupTest(api_client)

    test_user = user_test.own_class().create(**user_test.data())
    test_group = group_test.own_class().create(**group_test.data())

    try:
        assert test_user is not None, "User create response returned NoneType"
        assert test_group is not None, "Group create response returned NoneType"

        user_test.own_class().add_membership(
            id=test_user["id"], group_id=test_group["id"]
        )
        result = user_test.own_class().read(id=test_user["id"])
        assert test_group["id"] in result["groupsIds"]

        user_test.own_class().delete_membership(
            id=test_user["id"], group_id=test_group["id"]
        )
        result = user_test.own_class().read(id=test_user["id"])
        assert test_group["id"] not in result["groupsIds"]
    finally:
        user_test.base_class().delete(id=test_user["id"])
        group_test.base_class().delete(id=test_group["id"])


def test_user_organization(api_client):
    user_test = UserTest(api_client)
    org_test = IdentityOrganizationTest(api_client)

    test_user = user_test.own_class().create(**user_test.data())
    test_org = org_test.own_class().create(**org_test.data())

    try:
        assert test_user is not None, "User create response returned NoneType"
        assert test_org is not None, "Organization create response returned NoneType"

        user_test.own_class().add_organization(
            id=test_user["id"], organization_id=test_org["id"]
        )
        result = user_test.own_class().read(id=test_user["id"])
        assert test_org["id"] in result["objectOrganizationIds"]

        user_test.own_class().delete_organization(
            id=test_user["id"], organization_id=test_org["id"]
        )
        result = user_test.own_class().read(id=test_user["id"])
        assert test_org["id"] not in result["objectOrganizationIds"]
    finally:
        user_test.base_class().delete(id=test_user["id"])
        org_test.base_class().delete(id=test_org["id"])


def test_user_token_renew(api_client):
    user_test = UserTest(api_client)
    test_user = user_test.own_class().create(**user_test.data(), include_token=True)
    try:
        assert test_user is not None, "User create response returned NoneType"

        old_token = test_user["api_token"]
        result = user_test.own_class().token_renew(
            id=test_user["id"], include_token=True
        )
        assert old_token != result["api_token"]
    finally:
        user_test.own_class().delete(id=test_user["id"])
