"""A8: pycti's mapping cache under concurrent bundle imports.

The stock cache (cachetools LRUCache, no lock) corrupts its LRU order when two threads
evict at once; the locked subclass must survive a hammering from many threads with
evictions on every insertion, and the atomic read must never raise on a key evicted
between a membership test and a read.
"""

import threading
from unittest.mock import MagicMock

from cache_lock_shim import LockedLRUCache, _get_in_cache, install_cache_lock_shim


def hammer(cache, threads=8, rounds=4000, keyspace=300):
    errors = []

    def run(seed):
        try:
            for i in range(rounds):
                key = f"k{(seed * 7919 + i) % keyspace}"
                cache[key] = {"id": f"id-{key}"}
                if key in cache:
                    cache.get(key)
                if i % 5 == 0:
                    try:
                        del cache[f"k{(i * 31 + seed) % keyspace}"]
                    except KeyError:
                        pass
                if i % 11 == 0:
                    list(cache.keys())
        except Exception as e:  # pylint: disable=broad-except
            errors.append(repr(e))

    workers = [threading.Thread(target=run, args=(n,)) for n in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    return errors


def test_locked_cache_survives_concurrent_evictions():
    cache = LockedLRUCache(maxsize=64)
    errors = hammer(cache)
    assert errors == []
    assert len(cache) <= 64
    # the LRU order and the data agree: every ordered key is readable
    for key in cache.keys():
        assert cache.get(key) is not None


def test_atomic_get_in_cache_reads_without_raising():
    stix2 = MagicMock()
    stix2.mapping_cache = LockedLRUCache(maxsize=2)
    stix2.opencti.get_draft_id.return_value = ""
    stix2.mapping_cache["a"] = {"id": "1"}
    assert _get_in_cache(stix2, "a") == {"id": "1"}
    assert _get_in_cache(stix2, "missing") is None


def test_install_patches_pycti_class(monkeypatch):
    monkeypatch.setenv("WORKER_CACHE_LOCK", "true")
    import pycti.utils.opencti_stix2 as stix2_module

    logger = MagicMock()
    install_cache_lock_shim(logger)
    assert stix2_module.LRUCache is LockedLRUCache
    assert stix2_module.OpenCTIStix2.get_in_cache is _get_in_cache
    logger.info.assert_called()


def test_install_is_opt_out(monkeypatch):
    monkeypatch.setenv("WORKER_CACHE_LOCK", "false")
    logger = MagicMock()
    install_cache_lock_shim(logger)
    logger.info.assert_not_called()
