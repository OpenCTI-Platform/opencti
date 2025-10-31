from tests.cases.entities import GroupTest, MarkingDefinitionTest, RoleTest, UserTest


def test_group_roles(api_client):
    group_data = GroupTest(api_client).data()
    role_data = RoleTest(api_client).data()
    test_group = api_client.group.create(**group_data)
    test_role = api_client.role.create(**role_data)
    assert test_group is not None, "Create group response is NoneType"
    assert test_role is not None, "Create role response is NoneType"

    api_client.group.add_role(id=test_group["id"], role_id=test_role["id"])
    result = api_client.group.read(id=test_group["id"])
    assert result["rolesIds"][0] == test_role["id"]

    api_client.group.delete_role(id=test_group["id"], role_id=test_role["id"])
    result = api_client.group.read(id=test_group["id"])
    assert len(result["rolesIds"]) == 0

    api_client.group.delete(id=test_group["id"])
    api_client.role.delete(id=test_role["id"])


def test_group_default_markings(api_client):
    group_data = GroupTest(api_client).data()
    marking_test = MarkingDefinitionTest(api_client)
    marking_data = marking_test.data()
    test_group = api_client.group.create(**group_data)
    test_marking = marking_test.own_class().create(**marking_data)
    assert test_group is not None, "Create group response is NoneType"
    assert test_marking is not None, "Create marking response is NoneType"

    api_client.group.edit_default_marking(
        id=test_group["id"], marking_ids=[test_marking["id"]]
    )
    result = api_client.group.read(id=test_group["id"])
    assert result["default_marking"][0]["values"][0]["id"] == test_marking["id"]

    api_client.group.edit_default_marking(id=test_group["id"], marking_ids=[])
    result = api_client.group.read(id=test_group["id"])
    assert len(result["default_marking"][0]["values"]) == 0

    api_client.group.delete(id=test_group["id"])
    marking_test.base_class().delete(id=test_marking["id"])


def test_group_membership(api_client):
    group_test = GroupTest(api_client)
    user_test = UserTest(api_client)

    test_group = group_test.own_class().create(**group_test.data())
    test_user = user_test.own_class().create(**user_test.data())

    try:
        assert test_group is not None, "Create group response is NoneType"
        assert test_user is not None, "Create user response is NoneType"

        group_test.own_class().add_member(id=test_group["id"], user_id=test_user["id"])
        result = group_test.own_class().read(id=test_group["id"])
        assert result["membersIds"][0] == test_user["id"]

        group_test.own_class().delete_member(
            id=test_group["id"], user_id=test_user["id"]
        )
        result = group_test.own_class().read(id=test_group["id"])
        assert len(result["membersIds"]) == 0
    finally:
        group_test.base_class().delete(id=test_group["id"])
        user_test.base_class().delete(id=test_user["id"])


def test_group_allowed_markings(api_client):
    group_data = GroupTest(api_client).data()
    marking_test = MarkingDefinitionTest(api_client)
    marking_data = marking_test.data()
    test_group = api_client.group.create(**group_data)
    test_marking = marking_test.own_class().create(**marking_data)
    assert test_group is not None, "Create group response is NoneType"
    assert test_marking is not None, "Create marking response is NoneType"

    api_client.group.add_allowed_marking(
        id=test_group["id"], marking_id=test_marking["id"]
    )
    result = api_client.group.read(id=test_group["id"])
    assert result["allowed_marking"][0]["id"] == test_marking["id"]

    api_client.group.delete_allowed_marking(
        id=test_group["id"], marking_id=test_marking["id"]
    )
    result = api_client.group.read(id=test_group["id"])
    assert len(result["allowed_marking"]) == 0

    api_client.group.delete(id=test_group["id"])
    marking_test.base_class().delete(id=test_marking["id"])
