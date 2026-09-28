# POC ingestion sequencer, study 0011 (work-kb note opencti-worker-gil-profile): the
# per-process issue-rate ceiling (~72 obj/s) is the DEFAULT urllib3 pool: pycti's
# requests.session() keeps at most 10 keep-alive connections per host, every request
# beyond 10 in flight discards its connection on return ("Connection pool is full,
# discarding connection", 24k+ warnings/run at w2) and the next one pays a fresh TCP
# handshake. 10 lanes x ~140 ms commit RTT ~= 71 obj/s/process, the measured ceiling.
# Env-gated (WORKER_HTTP_POOL=<size>): remounts the session adapters with a pool sized
# for the ingest concurrency (P x CS in-flight requests per process).
import os

from requests.adapters import HTTPAdapter


def tune_session_pool(session, logger) -> None:
    size_raw = os.getenv("WORKER_HTTP_POOL", "")
    if not size_raw:
        return
    size = int(size_raw)
    adapter = HTTPAdapter(pool_connections=size, pool_maxsize=size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    logger.info("HTTP session pool tuned", {"pool_maxsize": size})
