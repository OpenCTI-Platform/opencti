from pycti.entities.opencti_stix_core_object import StixCoreObject


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
                "items": [{"id": "indicator--1"}, {"id": "indicator--2"}],
                "pageInfo": {"endCursor": "0", "hasNextPage": True},
            },
            {
                "items": [{"id": "indicator--3"}],
                "pageInfo": {"endCursor": "1", "hasNextPage": False},
            },
        ]

    def query(self, query, variables):
        after = variables["after"]
        page_index = 0 if after is None else int(after) + 1
        return {"data": {"stixCoreObjects": self.pages[page_index]}}

    def process_multiple(self, page, with_pagination=False):
        return page["items"]


def test_list_get_all_preserves_page_order():
    entity = StixCoreObject(_PagedClient())

    result = entity.list(getAll=True)

    assert [item["id"] for item in result] == [
        "indicator--1",
        "indicator--2",
        "indicator--3",
    ]
