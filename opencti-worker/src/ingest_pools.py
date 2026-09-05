"""Chunked ingest pools (plan 0009 s9.12.1 successor; design + decisions in the
work-kb note opencti-worker-chunked-ingest-pools).

One pool = 1 coordinator thread (the in-memory-queue thread) + chunk_size request
threads; each pool owns its in-memory FIFO of chunk jobs. ALL chunks of a bundle go
to ONE pool (bundle-to-pool affinity, picked round-robin or least-full): pool FIFO +
ordering rules below preserve the splitter's dependency order end to end without any
cross-thread coordination. The RabbitMQ ack stays bundle-terminal: the queue handler
blocks on its bundle tracker until every chunk reported terminal, exactly like the
historic handler blocked on the import itself.

V1 (default): the coordinator dispatches a full chunk and waits for every object to
reach a terminal outcome before pulling the next job (barrier; lockstep at chunk
granularity, directly comparable to today's waves).

V2 (pipelined=True): the coordinator admits the next chunk as soon as request
threads free up (in-flight objects gated below chunk_size), whatever bundle the
chunk belongs to: cross-bundle admission is what keeps the pool saturated (measured
+11% over the old shared executor, ladder run 4). DEPENDENCY-AWARE ADMISSION (fix
of run 4's failure cascades): an object whose declared in-bundle producers sit in
an EARLIER chunk is held in a pool-level pending list until those producers are
TERMINAL (created or definitively failed: failure counts as terminal, exactly like
the V1 barrier, so dependents fail fast instead of deadlocking). Same-chunk
producer/dependent pairs still fly together (the platform planner orders them
in-batch, as under V1); other bundles' objects are never held (no cross-bundle
||M|| dependency exists).
"""

import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

ImportResult = Tuple[List[Any], List[Any]]  # (imported_items, too_large_bundles)


@dataclass
class ChunkEntry:
    """One mini-bundle (single object) of a chunk, with its ordering metadata."""

    mini_bundle: Dict[str, Any]
    # The object's own id (None when the mini-bundle carries no id: never held,
    # never tracked as a producer).
    object_id: Optional[str]
    # Member ids this object references that live in an EARLIER chunk of the same
    # bundle: the only deps that can be inverted by pipelined admission. Same-chunk
    # deps are excluded on purpose (they co-batch platform-side, as under V1).
    blocking_deps: Set[str] = field(default_factory=set)


@dataclass
class ChunkJob:
    """One chunk travelling to a pool, with its callbacks.

    import_one runs ON a request thread and must be self-contained (it closes over
    the owning handler's pycti client: one bundle in flight per handler at
    prefetch=1, so the client's header state is stable for the bundle's lifetime).
    Request threads own their object's retry loop through pycti (decision Q2-A).
    bundle_terminal is the per-BUNDLE set of terminal object ids, shared by all of
    the bundle's chunk jobs; with bundle-to-pool affinity it is only ever touched
    under this pool's lock.
    """

    entries: List[ChunkEntry]
    bundle_terminal: Set[str]
    import_one: Callable[[Dict[str, Any]], ImportResult]
    on_object_error: Callable[[Exception], None]
    on_chunk_done: Callable[[List[Any], List[Any]], None]


class _ChunkState:
    """Per-chunk completion accounting for the pipelined path."""

    __slots__ = ("job", "remaining", "items", "too_large")

    def __init__(self, job: ChunkJob) -> None:
        self.job = job
        self.remaining = len(job.entries)
        self.items: List[Any] = []
        self.too_large: List[Any] = []


class IngestPool:
    def __init__(
        self,
        index: int,
        chunk_size: int,
        queue_bound: int,
        pipelined: bool,
        dep_admission: bool,
        logger: Any,
    ) -> None:
        self.index = index
        self.chunk_size = max(1, chunk_size)
        self.pipelined = pipelined
        self.dep_admission = dep_admission
        self.logger = logger
        # 0 = unbounded; a bound turns pool stalls into clean backpressure on the
        # emitting queue handler (its prefetch window stays occupied upstream).
        self.jobs: "queue.Queue[ChunkJob]" = queue.Queue(maxsize=max(0, queue_bound))
        self.executor = ThreadPoolExecutor(
            max_workers=self.chunk_size, thread_name_prefix=f"ipt-{index}"
        )
        # Pipelined accounting: in-flight objects + entries held for their
        # producers. All guarded by _cond.
        self._inflight = 0
        self._pending: List[Tuple[ChunkEntry, _ChunkState]] = []
        self._cond = threading.Condition()
        self.coordinator = threading.Thread(
            target=self._run, name=f"ingest-imqt-{index}", daemon=True
        )
        self.coordinator.start()

    def submit(self, job: ChunkJob) -> None:
        self.jobs.put(job)  # blocks when the pool queue is at its bound

    def depth(self) -> int:
        return self.jobs.qsize()

    # --- V1 barrier path ---------------------------------------------------

    def _run_barrier(self, job: ChunkJob) -> None:
        futures = [
            self.executor.submit(job.import_one, entry.mini_bundle)
            for entry in job.entries
        ]
        items: List[Any] = []
        too_large: List[Any] = []
        for future in as_completed(futures):
            try:
                objects, rejected = future.result()
                items.extend(objects)
                too_large.extend(rejected)
            except Exception as err:  # pylint: disable=broad-except
                # Same isolation contract as the inline path: pycti reports and
                # drops failed objects internally; an exception escaping here is
                # transport/format and must not abort the rest of the chunk.
                job.on_object_error(err)
        job.on_chunk_done(items, too_large)

    # --- V2 pipelined path ---------------------------------------------------

    def _deps_satisfied(self, entry: ChunkEntry, job: ChunkJob) -> bool:
        if not self.dep_admission or not entry.blocking_deps:
            return True
        return entry.blocking_deps <= job.bundle_terminal

    def _dispatch(self, entry: ChunkEntry, state: _ChunkState) -> None:
        # called OUTSIDE _cond (reentrancy: the done callback can run inline);
        # _inflight was already incremented by the caller
        future = self.executor.submit(state.job.import_one, entry.mini_bundle)
        future.add_done_callback(
            lambda fut, e=entry, s=state: self._entry_done(fut, e, s)
        )

    def _run_pipelined(self, job: ChunkJob) -> None:
        state = _ChunkState(job)
        if not job.entries:
            job.on_chunk_done([], [])
            return
        for entry in job.entries:
            dispatch_now = False
            with self._cond:
                while self._inflight >= self.chunk_size:
                    self._cond.wait()
                if self._deps_satisfied(entry, job):
                    self._inflight += 1
                    dispatch_now = True
                else:
                    # held until its earlier-chunk producers are terminal;
                    # released by _entry_done, permit taken at release time
                    self._pending.append((entry, state))
            if dispatch_now:
                # outside the lock: a future can complete synchronously enough for
                # add_done_callback to run _entry_done on THIS thread, which takes
                # the (non-reentrant) condition again
                self._dispatch(entry, state)
        # the coordinator returns to the FIFO immediately: chunk completion is
        # driven by _entry_done callbacks (the whole point of V2)

    def _entry_done(self, future: Any, entry: ChunkEntry, state: _ChunkState) -> None:
        try:
            objects, rejected = future.result()
        except Exception as err:  # pylint: disable=broad-except
            objects, rejected = [], []
            state.job.on_object_error(err)
        release: List[Tuple[ChunkEntry, _ChunkState]] = []
        chunk_done = False
        with self._cond:
            self._inflight -= 1
            # terminal = ok OR failed (a dead producer must free its dependents,
            # which then fail fast platform-side: V1-barrier semantics)
            if entry.object_id:
                state.job.bundle_terminal.add(entry.object_id)
            state.items.extend(objects)
            state.too_large.extend(rejected)
            state.remaining -= 1
            chunk_done = state.remaining == 0
            # release now-satisfied pending entries within the freed budget
            still_pending: List[Tuple[ChunkEntry, _ChunkState]] = []
            for pending_entry, pending_state in self._pending:
                if (
                    self._inflight < self.chunk_size
                    and self._deps_satisfied(pending_entry, pending_state.job)
                ):
                    self._inflight += 1
                    release.append((pending_entry, pending_state))
                else:
                    still_pending.append((pending_entry, pending_state))
            self._pending = still_pending
            self._cond.notify_all()
        # dispatch outside the lock (same reentrancy caveat as _run_pipelined)
        for released_entry, released_state in release:
            self._dispatch(released_entry, released_state)
        if chunk_done:
            state.job.on_chunk_done(state.items, state.too_large)

    # --- coordinator ---------------------------------------------------------

    def _run(self) -> None:
        while True:
            job = self.jobs.get()
            try:
                if self.pipelined:
                    self._run_pipelined(job)
                else:
                    self._run_barrier(job)
            except Exception as err:  # pylint: disable=broad-except
                # A coordinator must never die: fail the chunk and keep serving.
                self.logger.error(
                    "Ingest pool chunk failed wholesale",
                    {"pool": self.index, "error": str(err)},
                )
                try:
                    job.on_chunk_done([], [])
                except Exception:  # pylint: disable=broad-except
                    pass


# One registry per worker process, created by the first handler (all handlers of a
# process share one worker config), like the s9.11 shared executor before it.
_pools: Optional[List[IngestPool]] = None
_pools_lock = threading.Lock()
_round_robin = 0


def get_ingest_pools(
    count: int,
    chunk_size: int,
    queue_bound: int,
    pipelined: bool,
    dep_admission: bool,
    logger: Any,
) -> List[IngestPool]:
    global _pools  # pylint: disable=global-statement
    if _pools is None:
        with _pools_lock:
            if _pools is None:
                _pools = [
                    IngestPool(
                        i, chunk_size, queue_bound, pipelined, dep_admission, logger
                    )
                    for i in range(max(1, count))
                ]
    return _pools


def pick_pool(pools: List[IngestPool], mode: str) -> IngestPool:
    """Bundle-to-pool pick (decision Q3): round_robin or least_full at pick time."""
    global _round_robin  # pylint: disable=global-statement
    if mode == "round_robin":
        with _pools_lock:
            picked = pools[_round_robin % len(pools)]
            _round_robin += 1
        return picked
    return min(pools, key=lambda pool: (pool.depth(), pool.index))
