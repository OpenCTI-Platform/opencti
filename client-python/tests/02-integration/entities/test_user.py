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


def test_user_admin_token_create_remove(api_client):
    user_test = UserTest(api_client)
    test_user = user_test.own_class().create(**user_test.data(), include_tokens=True)
    try:
        assert test_user is not None, "User create response returned NoneType"
        assert len(test_user["api_tokens"]) == 0
        # Create the token
        result = user_test.own_class().create_token(
            user_id=test_user["id"], token_name="new token"
        )
        token_id = result["token_id"]
        assert result["plaintext_token"] is not None
        # Fetch the user
        read_user = user_test.own_class().read(id=test_user["id"], include_tokens=True)
        assert len(read_user["api_tokens"]) == 1

        # Remove the token
        result = user_test.own_class().remove_token(
            user_id=test_user["id"], token_id=token_id
        )
        assert result is not None
        read_user = user_test.own_class().read(id=test_user["id"], include_tokens=True)
        assert len(read_user["api_tokens"]) == 0

    finally:
        user_test.own_class().delete(id=test_user["id"])
