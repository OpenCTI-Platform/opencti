from pycti.utils.constants import (
    ContainerTypes,
    IdentityTypes,
    LocationTypes,
    StixCyberObservableTypes,
)


def test_for_enum_typos():
    # Test check for typos between enum names and values
    enums = [StixCyberObservableTypes, LocationTypes, IdentityTypes, ContainerTypes]
    for enum in enums:
        for data in enum:
            name = data.name.replace("_", "-")
            value = data.value.upper()
            assert name == value


def test_for_enum_has_value_functionality():
    # Test if the has_value function works as intended
    assert StixCyberObservableTypes.has_value("url") is True
    assert StixCyberObservableTypes.has_value("LRU") is False

    assert LocationTypes.has_value("CITY") is True
    assert LocationTypes.has_value("YTIC") is False

    assert IdentityTypes.has_value("SECTOR") is True
    assert IdentityTypes.has_value("RECTOS") is False

    assert ContainerTypes.has_value("Note") is True
    assert ContainerTypes.has_value("ETON") is False
