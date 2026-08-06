import functools
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Callable, List, Literal, Optional, Tuple

import pika


@dataclass(unsafe_hash=True)
class MessageQueueConsumer:  # pylint: disable=too-many-instance-attributes
    logger: Any
    consumer_type: Literal["listen", "push"]
    queue_name: str
    pika_parameters: pika.ConnectionParameters
    submit_fn: Callable[[Callable[[], None]], Future[None]]
    handle_message: Callable[[str], Literal["ack", "nack", "requeue"]]
    # Optional/unused by default: existing single-message consumers are unaffected.
    handle_message_batch: Optional[
        Callable[[List[str]], List[Literal["ack", "nack", "requeue"]]]
    ] = field(default=None, hash=False)
    is_batchable: Optional[Callable[[str], bool]] = field(default=None, hash=False)
    batch_size: int = field(default=1)
    batch_timeout: float = field(default=1.0)
    should_stop: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        # Batching needs enough in-flight messages for RabbitMQ to actually deliver a
        # full window before an ack is sent back.
        batching_enabled = (
            self.handle_message_batch is not None and self.is_batchable is not None
        )
        prefetch_count = max(1, self.batch_size) if batching_enabled else 1
        self.channel.basic_qos(prefetch_count=prefetch_count)
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

    def dispatch_result(
        self, delivery_tag: int, result: Literal["ack", "nack", "requeue"]
    ) -> None:
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

    def consume_message(self, delivery_tag: int, body: str) -> None:
        result = self.handle_message(body)
        self.dispatch_result(delivery_tag, result)

    def consume_message_batch(self, pending: List[Tuple[int, str]]) -> None:
        bodies = [body for _, body in pending]
        results = self.handle_message_batch(bodies)
        for (delivery_tag, _), result in zip(pending, results):
            self.dispatch_result(delivery_tag, result)

    def submit_and_wait(self, task: Callable[[], None]) -> None:
        task_future = self.submit_fn(task)
        while task_future.running():  # Loop while the thread is processing
            self.pika_connection.sleep(0.05)

    def consume_queue(self) -> None:
        # In-memory accumulator, scoped to this consumer/queue instance only. Lost on
        # crash, but that's fine: messages stay unacked and AMQP redelivery resends them.
        pending: List[Tuple[int, str]] = []
        pending_started_at: Optional[float] = None
        batching_enabled = (
            self.handle_message_batch is not None and self.is_batchable is not None
        )

        def flush_pending() -> None:
            nonlocal pending, pending_started_at
            if not pending:
                return
            self.logger.info(
                "Flushing accumulated batch",
                {
                    "consumer_type": self.consumer_type,
                    "queue": self.queue_name,
                    "size": len(pending),
                },
            )
            self.submit_and_wait(functools.partial(self.consume_message_batch, pending))
            pending = []
            pending_started_at = None

        try:
            self.logger.info(
                "Thread for queue started",
                {"consumer_type": self.consumer_type, "queue": self.queue_name},
            )

            # Consume the queue with a generator
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self.should_stop:
                    # Force-flush before stopping: nothing accumulated is silently lost,
                    # unflushed messages simply stay unacked for AMQP redelivery.
                    flush_pending()
                    break
                if not all(message):
                    # Inactivity tick - also the hook to check the time-based flush
                    # trigger.
                    if (
                        pending
                        and pending_started_at is not None
                        and (time.monotonic() - pending_started_at)
                        >= self.batch_timeout
                    ):
                        flush_pending()
                    continue
                method, properties, body = message
                if batching_enabled and self.is_batchable(body):
                    pending.append((method.delivery_tag, body))
                    if pending_started_at is None:
                        pending_started_at = time.monotonic()
                    if len(pending) >= self.batch_size:
                        flush_pending()
                    continue
                # Not batchable (or batching disabled): flush any pending batch first so
                # relative message ordering on the queue is preserved.
                flush_pending()
                self.logger.info(
                    "Processing a new message, launching a thread...",
                    {
                        "consumer_type": self.consumer_type,
                        "queue": self.queue_name,
                        "tag": method.delivery_tag,
                    },
                )
                self.submit_and_wait(
                    functools.partial(self.consume_message, method.delivery_tag, body)
                )
                self.logger.info("Message processed, thread terminated")
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
