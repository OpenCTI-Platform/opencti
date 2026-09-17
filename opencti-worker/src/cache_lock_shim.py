"""Thread-safe pycti mapping cache (A8).

pycti keeps one `LRUCache(maxsize=50000)` per client (`OpenCTIStix2.mapping_cache`) and
reads it as `if key in cache: return cache[key]`, with no lock. The stock worker never
imports two bundles at once on one client, so nothing races. This worker does (parallel
bundle import, two messages in flight per queue): once a client has evicted, two threads
evicting at the same time can leave a key in the LRU order with no data behind it
(`LRUCache.__touch` re-adds on a concurrent delete), and from the moment that key reaches
the head every insertion raises KeyError: the bundle in hand is retried until the worker
stops (full mix, one worker, 2026-09-16: 1,332 failed imports, 4 objects lost).

The shim replaces the cache class pycti instantiates with a re-entrant-locked subclass
and makes the read a single atomic `get`.
"""

import os
import threading
from typing import Any, Iterator, List

from cachetools import LRUCache


class LockedLRUCache(LRUCache):  # type: ignore[type-arg]
    """cachetools LRUCache whose every access holds one re-entrant lock."""

    def __init__(self, maxsize: int, getsizeof: Any = None) -> None:
        super().__init__(maxsize, getsizeof)
        self._lock = threading.RLock()

    def __getitem__(self, key: Any) -> Any:
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key: Any, value: Any) -> None:
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key: Any) -> None:
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: Any) -> bool:
        with self._lock:
            return super().__contains__(key)

    def __iter__(self) -> Iterator[Any]:
        with self._lock:
            return iter(list(super().__iter__()))

    def __len__(self) -> int:
        with self._lock:
            return super().__len__()

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return super().get(key, default)

    def pop(self, key: Any, *args: Any) -> Any:
        with self._lock:
            return super().pop(key, *args)

    def popitem(self) -> Any:
        with self._lock:
            return super().popitem()

    def clear(self) -> None:
        with self._lock:
            super().clear()

    def keys(self) -> List[Any]:  # type: ignore[override]
        with self._lock:
            return list(super().keys())

    def values(self) -> List[Any]:  # type: ignore[override]
        with self._lock:
            return list(super().values())

    def items(self) -> List[Any]:  # type: ignore[override]
        with self._lock:
            return list(super().items())


def _get_in_cache(self: Any, data_id: str) -> Any:
    # one atomic read instead of pycti's `in` then `[]` (a concurrent eviction between the
    # two raised KeyError inside a bundle import)
    return self.mapping_cache.get(data_id + self.opencti.get_draft_id())


def install_cache_lock_shim(logger: Any) -> None:
    if os.getenv("WORKER_CACHE_LOCK", "true").lower() != "true":
        return
    try:
        import pycti.utils.opencti_stix2 as stix2_module

        stix2_module.LRUCache = LockedLRUCache
        stix2_module.OpenCTIStix2.get_in_cache = _get_in_cache
        logger.info("pycti mapping cache lock shim installed")
    except Exception as e:  # pylint: disable=broad-except
        logger.error("pycti mapping cache lock shim failed", {"reason": str(e)})
