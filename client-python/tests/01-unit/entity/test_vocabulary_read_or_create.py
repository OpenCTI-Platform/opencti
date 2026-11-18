# coding: utf-8
"""Unit tests of Vocabulary.read_or_create_unchecked.

A vocabulary name can exist in several categories (malware-analysis is a
grouping context by default, not a report type). The lookup must be scoped
to the requested category, else the value is never created where it is
needed and the platform drops the field value.
"""

from unittest.mock import MagicMock

import pytest

from pycti.entities.opencti_vocabulary import Vocabulary


def _vocab(name, category):
    return {"id": f"{category}-{name}", "name": name, "category": {"key": category}}


@pytest.fixture
def vocabulary():
    instance = Vocabulary(MagicMock())
    instance.read = MagicMock()
    instance.create = MagicMock(
        side_effect=lambda **kwargs: _vocab(kwargs["name"], kwargs["category"])
    )
    return instance


def _read_filters(vocabulary):
    return vocabulary.read.call_args.kwargs["filters"]["filters"]


def test_lookup_is_filtered_on_name_and_category(vocabulary):
    vocabulary.read.return_value = None

    result = vocabulary.read_or_create_unchecked(
        name="malware-analysis", required=False, category="report_types_ov"
    )

    assert _read_filters(vocabulary) == [
        {"key": "name", "values": ["malware-analysis"]},
        {"key": "category", "values": ["report_types_ov"]},
    ]
    vocabulary.create.assert_called_once_with(
        name="malware-analysis", required=False, category="report_types_ov"
    )
    assert result == _vocab("malware-analysis", "report_types_ov")


def test_value_of_another_category_is_not_accepted(vocabulary):
    # A server that ignores the category filter still answers the other entry
    vocabulary.read.return_value = _vocab("malware-analysis", "grouping_context_ov")

    result = vocabulary.read_or_create_unchecked(
        name="malware-analysis", required=False, category="report_types_ov"
    )

    vocabulary.create.assert_called_once_with(
        name="malware-analysis", required=False, category="report_types_ov"
    )
    assert result["category"]["key"] == "report_types_ov"


def test_value_of_the_requested_category_is_found_without_create(vocabulary):
    existing = _vocab("threat-report", "report_types_ov")
    vocabulary.read.return_value = existing

    result = vocabulary.read_or_create_unchecked(
        name="threat-report", required=False, category="report_types_ov"
    )

    assert result is existing
    vocabulary.create.assert_not_called()


def test_lookup_without_category_is_unchanged(vocabulary):
    existing = _vocab("threat-report", "report_types_ov")
    vocabulary.read.return_value = existing

    result = vocabulary.read_or_create_unchecked(name="threat-report")

    assert _read_filters(vocabulary) == [{"key": "name", "values": ["threat-report"]}]
    assert result is existing
    vocabulary.create.assert_not_called()


def test_cached_lookup_stores_the_requested_category(vocabulary):
    vocabulary.read.return_value = _vocab("malware-analysis", "grouping_context_ov")
    cache = {}
    field = {"key": "report_types", "required": False, "category": "report_types_ov"}

    first = vocabulary.read_or_create_unchecked_with_cache(
        "malware-analysis", cache, field
    )
    second = vocabulary.read_or_create_unchecked_with_cache(
        "malware-analysis", cache, field
    )

    assert first["category"]["key"] == "report_types_ov"
    assert cache["vocab_report_types_ov_malware-analysis"] is first
    assert second is first
    vocabulary.create.assert_called_once()
