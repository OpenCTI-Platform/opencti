from pytest_cases import fixture, parametrize_with_cases

from tests.cases.entities import EntityTestCases
from tests.utils import compare_values, is_filters_empty


@fixture
@parametrize_with_cases("entity", cases=EntityTestCases)
def entity_class(entity):
    entity.setup()
    yield entity
    entity.teardown()


def test_entity_create(entity_class):
    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])


def test_read(entity_class):
    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
        assert "standard_id" in test_indicator, "No standard_id (STIX ID) on object"
        test_indicator = entity_class.own_class().read(id=test_indicator["id"])
        compare_values(
            class_data,
            test_indicator,
            entity_class.get_compare_exception_keys(),
        )

    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])


def test_update(entity_class):
    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"

        if len(entity_class.update_data()) > 0:
            function_present = getattr(entity_class.own_class(), "update_field", None)
            if function_present:
                for update_field, update_value in entity_class.update_data().items():
                    class_data[update_field] = update_value
                    input = [{"key": update_field, "value": update_value}]
                    result = entity_class.own_class().update_field(
                        id=test_indicator["id"], input=input
                    )
            else:
                for update_field, update_value in entity_class.update_data().items():
                    class_data[update_field] = update_value
                class_data["update"] = True
                result = entity_class.own_class().create(**class_data)

            result = entity_class.own_class().read(id=result["id"])
            assert (
                result["id"] == test_indicator["id"]
            ), "Updated SDO does not match old ID"
            compare_values(
                class_data, result, entity_class.get_compare_exception_keys()
            )
        else:
            result = test_indicator

    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=result["id"])


def test_delete(entity_class):
    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
        result = entity_class.base_class().delete(id=test_indicator["id"])
        assert result is None, f"Delete returned value '{result}'"
        result = entity_class.own_class().read(id=test_indicator["id"])
        assert result is None, f"Read returned value '{result}' after delete"
    except AssertionError:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])


def test_filter(entity_class):
    if is_filters_empty(entity_class.get_filter()):
        return

    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
        test_indicator = entity_class.own_class().read(
            filters=entity_class.get_filter()
        )
        compare_values(
            class_data,
            test_indicator,
            entity_class.get_compare_exception_keys(),
        )
    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])


def test_search(entity_class):
    if not entity_class.get_search():
        return

    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
        test_indicator = entity_class.own_class().read(search=entity_class.get_search())
        compare_values(
            class_data,
            test_indicator,
            entity_class.get_compare_exception_keys(),
        )
    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])


def test_relation(entity_class):
    if not entity_class.relation_test():
        return
    class_data = entity_class.data()
    class_data2 = entity_class.relation_test()
    test_indicator = entity_class.own_class().create(**class_data)
    test_indicator2 = entity_class.own_class().create(**class_data2)
    try:
        assert test_indicator is not None, "Response is NoneType"
        assert "id" in test_indicator, "No ID on object"
        entity_class.own_class().add_stix_object_or_stix_relationship(
            id=test_indicator["id"],
            stixObjectOrStixRelationshipId=test_indicator2["id"],
        )
        result = entity_class.own_class().read(id=test_indicator["id"])
        assert result["objectsIds"][0] == test_indicator2["id"]
        entity_class.own_class().remove_stix_object_or_stix_relationship(
            id=test_indicator["id"],
            stixObjectOrStixRelationshipId=test_indicator2["id"],
        )
        result = entity_class.own_class().read(id=test_indicator["id"])
        assert len(result["objectsIds"]) == 0
    finally:
        if test_indicator and "id" in test_indicator:
            entity_class.base_class().delete(id=test_indicator["id"])
        if test_indicator2 and "id" in test_indicator2:
            entity_class.base_class().delete(id=test_indicator2["id"])
