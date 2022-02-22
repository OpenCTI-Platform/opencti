from pytest_cases import fixture, parametrize_with_cases

from tests.cases.entities import EntityTestCases
from tests.utils import compare_values


@fixture
@parametrize_with_cases("entity", cases=EntityTestCases)
def entity_class(entity):
    entity.setup()
    yield entity
    entity.teardown()


def test_filter(entity_class):
    if len(entity_class.get_filter()) == 0:
        return

    class_data = entity_class.data()
    test_indicator = entity_class.own_class().create(**class_data)
    assert test_indicator is not None, "Response is NoneType"
    assert "id" in test_indicator, "No ID on object"
    test_indicator = entity_class.own_class().read(filters=entity_class.get_filter())
    compare_values(
        class_data,
        test_indicator,
        entity_class.get_compare_exception_keys(),
    )

    entity_class.base_class().delete(id=test_indicator["id"])
