from pycti.entities.opencti_stix_nested_ref_relationship import (
    StixNestedRefRelationship,
)


class _NoOpLogger:
    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class _PagedClient:
    def __init__(self):
        self.app_logger = _NoOpLogger()
        self.pages = [
            {
                "items": [{"id": "relationship--1"}, {"id": "relationship--2"}],
                "pageInfo": {"endCursor": "0", "hasNextPage": True},
            },
            {
                "items": [{"id": "relationship--3"}],
                "pageInfo": {"endCursor": "1", "hasNextPage": False},
            },
        ]

    def query(self, query, variables):
        after = variables["after"]
        page_index = 0 if after is None else int(after) + 1
        return {"data": {"stixNestedRefRelationships": self.pages[page_index]}}

    def process_multiple(self, page, with_pagination=False):
        return page["items"]


def test_list_get_all_preserves_page_order():
    entity = StixNestedRefRelationship(_PagedClient())

    result = entity.list(getAll=True)

    assert [item["id"] for item in result] == [
        "relationship--1",
        "relationship--2",
        "relationship--3",
    ]
