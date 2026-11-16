import functools
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Callable, Dict, Literal

import pika

# Consumption is reported as one summary log per queue and per interval
# instead of one log per message, to keep log volume low on busy queues.
STATS_LOG_INTERVAL_SECONDS = 60


@dataclass
class ConsumptionStats:
    processed: int = 0
    acked: int = 0
    nacked: int = 0
    requeued: int = 0
    total_processing_ms: float = 0.0
    max_processing_ms: float = 0.0

    def record(
        self, result: Literal["ack", "nack", "requeue"], duration_ms: float
    ) -> None:
        self.processed += 1
        if result == "ack":
            self.acked += 1
        elif result == "nack":
            self.nacked += 1
        elif result == "requeue":
            self.requeued += 1
        self.total_processing_ms += duration_ms
        self.max_processing_ms = max(self.max_processing_ms, duration_ms)

    def as_log_meta(self) -> Dict[str, Any]:
        return {
            "processed": self.processed,
            "acked": self.acked,
            "nacked": self.nacked,
            "requeued": self.requeued,
            "avg_processing_ms": round(self.total_processing_ms / self.processed),
            "max_processing_ms": round(self.max_processing_ms),
        }


@dataclass(unsafe_hash=True)
class MessageQueueConsumer:  # pylint: disable=too-many-instance-attributes
    logger: Any
    consumer_type: Literal["listen", "push"]
    queue_name: str
    pika_parameters: pika.ConnectionParameters
    submit_fn: Callable[[Callable[[], None]], Future[None]]
    handle_message: Callable[[str], Literal["ack", "nack", "requeue"]]
    should_stop: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self._init_stats(time.monotonic())
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=1)
        self.thread = Thread(target=self.consume_queue, name=self.queue_name)
        self.thread.start()

    def _init_stats(self, now: float) -> None:
        # Stats are written by the pool thread (consume_message) and read by
        # the consumer thread (_maybe_log_stats), hence the lock.
        self._stats_lock = threading.Lock()
        self._stats = ConsumptionStats()
        self._stats_window_start = now

    def _maybe_log_stats(self, now: float) -> None:
        if now - self._stats_window_start >= STATS_LOG_INTERVAL_SECONDS:
            self._flush_stats(now)

    def _flush_stats(self, now: float) -> None:
        with self._stats_lock:
            stats = self._stats
            self._stats = ConsumptionStats()
        interval_seconds = round(now - self._stats_window_start)
        self._stats_window_start = now
        if stats.processed > 0:
            self.logger.info(
                "Queue consumption summary",
                {
                    "consumer_type": self.consumer_type,
                    "queue": self.queue_name,
                    "interval_seconds": interval_seconds,
                    **stats.as_log_meta(),
                },
            )

    def nack_message(self, delivery_tag: int, requeue: bool) -> None:
        if self.channel.is_open:
            self.logger.debug(
                "Message rejected", {"tag": delivery_tag, "requeue": requeue}
            )
            self.channel.basic_nack(delivery_tag, requeue=requeue)
        else:
            self.logger.warning(
                "Message NOT rejected (channel closed)",
                {"queue": self.queue_name, "tag": delivery_tag},
            )

    def ack_message(self, delivery_tag: int) -> None:
        if self.channel.is_open:
            self.logger.debug("Message acknowledged", {"tag": delivery_tag})
            self.channel.basic_ack(delivery_tag)
        else:
            self.logger.warning(
                "Message NOT acknowledged (channel closed)",
                {"queue": self.queue_name, "tag": delivery_tag},
            )

    def consume_message(self, delivery_tag: int, body: str) -> None:
        start = time.monotonic()
        try:
            result = self.handle_message(body)
        except Exception as e:
            # Truncate to avoid flooding logs / leaking large payloads; enough
            # to identify the message (ids, type) without dumping full content.
            body_excerpt = body[:2000] if isinstance(body, str) else str(body)[:2000]
            self.logger.error(
                "Unhandled exception while processing message, acking to avoid stalling the queue",
                {"exception": e, "body_excerpt": body_excerpt},
            )
            result = "ack"
        duration_ms = (time.monotonic() - start) * 1000
        match result:
            case "ack":
                cb = functools.partial(self.ack_message, delivery_tag)
                self.pika_connection.add_callback_threadsafe(cb)
            case "nack":
                cb = functools.partial(self.nack_message, delivery_tag, False)
                self.pika_connection.add_callback_threadsafe(cb)
            case "requeue":
                cb = functools.partial(self.nack_message, delivery_tag, True)
                self.pika_connection.add_callback_threadsafe(cb)
        # Recorded after the ack/nack is scheduled: stats must never prevent
        # a message from being resolved (prefetch_count=1 would stall the queue).
        with self._stats_lock:
            self._stats.record(result, duration_ms)

    def consume_queue(self) -> None:
        try:
            self.logger.info(
                "Thread for queue started",
                {"consumer_type": self.consumer_type, "queue": self.queue_name},
            )

            # Consume the queue with a generator
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self.should_stop:
                    break
                # inactivity_timeout=1 guarantees this runs at least every second
                self._maybe_log_stats(time.monotonic())
                if not all(message):
                    continue
                method, properties, body = message
                self.logger.debug(
                    "Processing a new message, launching a thread...",
                    {
                        "consumer_type": self.consumer_type,
                        "queue": self.queue_name,
                        "tag": method.delivery_tag,
                    },
                )
                consume = functools.partial(
                    self.consume_message, method.delivery_tag, body
                )
                task_future = self.submit_fn(consume)
                while task_future.running():  # Loop while the thread is processing
                    self.pika_connection.sleep(0.05)
                self.logger.debug("Message processed, thread terminated")
        except Exception as e:
            self.logger.error("Unhandled exception", {"exception": e})
        finally:
            self._flush_stats(time.monotonic())
            self.logger.info(
                "Thread for queue terminated",
                {"consumer_type": self.consumer_type, "queue": self.queue_name},
            )

    def is_alive(self) -> bool:
        return self.thread.is_alive()

    def request_stop(self) -> None:
        self.should_stop = True

    def wait_for_completion(self) -> None:
        self.request_stop()
        self.thread.join()
