import sys

if sys.version_info >= (3, 11):
    import typing as t
else:
    import typing_extensions as t

__all__ = [
    "Entities",
    "Filter",
    "FilterGroup",
    "FilterMode",
    "OrderMode",
    "PaginatedResponse",
    "Pagination",
]

OrderMode = t.Literal["asc", "desc"]

FilterMode = t.Literal["and", "or"]


class Filter(t.TypedDict):
    key: str
    values: t.List[t.Any]
    operator: t.NotRequired[str]
    mode: t.NotRequired[FilterMode]


class FilterGroup(t.TypedDict):
    mode: FilterMode
    filters: t.List[Filter]
    filterGroups: t.List["FilterGroup"]


Entities = t.List[t.Dict[str, t.Any]]


class Pagination(t.TypedDict):
    startCursor: str
    endCursor: str
    hasNextPage: bool
    hasPreviousPage: bool
    globalCount: int


PaginatedResponse = t.Dict[str, t.Union[Entities, Pagination]]
