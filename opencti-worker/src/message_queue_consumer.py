import functools
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Callable, Literal

import pika
from opentelemetry import metrics as otel_metrics

# Time between two consecutive RabbitMQ deliveries on one push queue (user ask
# 2026-09-07): the "fetch cost" seen by a queue thread. At prefetch=1 this is
# ack-to-redelivery latency + broker RTT; spikes reveal convoy gaps.
consumer_meter = otel_metrics.get_meter(__name__)
delivery_gap_seconds = consumer_meter.create_histogram(
    name="opencti_worker_delivery_gap_seconds",
    unit="s",
    description="Gap between consecutive deliveries on a push queue (includes handler wait at prefetch=1)",
)


@dataclass(unsafe_hash=True)
class MessageQueueConsumer:  # pylint: disable=too-many-instance-attributes
    logger: Any
    consumer_type: Literal["listen", "push"]
    queue_name: str
    pika_parameters: pika.ConnectionParameters
    submit_fn: Callable[[Callable[[], None]], Future[None]]
    handle_message: Callable[[str], Literal["ack", "nack", "requeue"]]
    # POC (plan 0009 worker v0): >1 lets several messages of the SAME queue be in flight in
    # the execution pool (the broker caps unacked deliveries at this value). 1 = historic
    # behavior: one message per queue at a time.
    prefetch_count: int = 1
    should_stop: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=max(1, self.prefetch_count))
        self.thread = Thread(target=self.consume_queue, name=self.queue_name)
        self.thread.start()

    def nack_message(self, delivery_tag: int, requeue: bool) -> None:
        if self.channel.is_open:
            self.logger.info("Message rejected", {"tag": delivery_tag})
            self.channel.basic_nack(delivery_tag, requeue=requeue)
        else:
            self.logger.info(
                "Message NOT rejected (channel closed)", {"tag": delivery_tag}
            )

    def ack_message(self, delivery_tag: int) -> None:
        if self.channel.is_open:
            self.logger.info("Message acknowledged", {"tag": delivery_tag})
            self.channel.basic_ack(delivery_tag)
        else:
            self.logger.info(
                "Message NOT acknowledged (channel closed)",
                {"tag": delivery_tag},
            )

    def consume_message(self, delivery_tag: int, body: str) -> None:
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

    def consume_queue(self) -> None:
        try:
            self.logger.info(
                "Thread for queue started",
                {"consumer_type": self.consumer_type, "queue": self.queue_name},
            )

            # Consume the queue with a generator
            last_delivery = None
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self.should_stop:
                    break
                if not all(message):
                    continue
                method, properties, body = message
                if self.consumer_type == "push":
                    now = time.monotonic()
                    if last_delivery is not None:
                        delivery_gap_seconds.record(now - last_delivery)
                    last_delivery = now
                self.logger.info(
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
                if self.prefetch_count <= 1:
                    while task_future.running():  # Loop while the thread is processing
                        self.pika_connection.sleep(0.05)
                    self.logger.info("Message processed, thread terminated")
                # prefetch_count > 1: do NOT wait, keep consuming up to the QoS window; acks
                # flow through add_callback_threadsafe and are processed by the IO loop that
                # the consume generator pumps (inactivity_timeout). In-flight execution stays
                # bounded by the shared execution pool.
        except Exception as e:
            self.logger.error("Unhandled exception", {"exception": e})
        finally:
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
