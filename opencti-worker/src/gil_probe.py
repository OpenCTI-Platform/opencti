# POC ingestion sequencer, study 0011 step 2b (work-kb): GIL/scheduler convoy probe.
# A daemon thread sleeps a fixed 10 ms and measures the OVERSLEEP: the time between the
# expected and the actual wake-up. Under a convoyed GIL (many threads re-acquiring after
# I/O), the oversleep distribution fattens; on an idle interpreter it stays near the OS
# timer slack. Percentiles are logged every 30 s: the number to read is p95/p99 (ms).
# Enabled by WORKER_GIL_PROBE=true; zero cost otherwise.
import os
import threading
import time


def start_gil_probe(logger) -> None:
    if os.getenv("WORKER_GIL_PROBE", "false").lower() != "true":
        return

    def probe() -> None:
        samples: list[float] = []
        last_report = time.monotonic()
        while True:
            t0 = time.monotonic()
            time.sleep(0.01)
            oversleep_ms = (time.monotonic() - t0 - 0.01) * 1000.0
            samples.append(oversleep_ms)
            now = time.monotonic()
            if now - last_report >= 30.0:
                samples.sort()
                n = len(samples)
                logger.info(
                    "GIL probe oversleep (ms)",
                    {
                        "n": n,
                        "p50": round(samples[n // 2], 3),
                        "p95": round(samples[int(n * 0.95)], 3),
                        "p99": round(samples[int(n * 0.99)], 3),
                        "max": round(samples[-1], 3),
                    },
                )
                samples = []
                last_report = now

    threading.Thread(target=probe, name="gil-probe", daemon=True).start()
