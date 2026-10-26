import functools
from concurrent.futures import Future
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Callable, List, Literal, Optional, Tuple

import pika

MessageResult = Literal["ack", "nack", "requeue"]
# A message received and not settled yet: (delivery tag, body)
Delivery = Tuple[int, str]


@dataclass(unsafe_hash=True)
class MessageQueueConsumer:  # pylint: disable=too-many-instance-attributes
    logger: Any
    consumer_type: Literal["listen", "push"]
    queue_name: str
    pika_parameters: pika.ConnectionParameters
    submit_fn: Callable[[Callable[[], None]], Future[None]]
    handle_message: Callable[[str], Literal["ack", "nack", "requeue"]]
    # Messages handled together (handle_batch): up to batch_size, or what arrived within batch_wait seconds
    handle_batch: Optional[Callable[[List[str]], List[MessageResult]]] = None
    batch_size: int = 1
    batch_wait: float = 0.05
    should_stop: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=max(1, self.batch_size))
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

    def settle(self, delivery_tag: int, result: str) -> None:
        """Ack, reject or requeue the message, from the connection's thread."""
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

    def consume_batch(self, messages: List[Delivery]) -> None:
        """Handle messages together, then settle each one with its own result."""
        try:
            results = self.handle_batch([body for _, body in messages])
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                "Unhandled exception while processing messages together, acking to avoid stalling the queue",
                {"exception": e, "messages": len(messages)},
            )
            results = ["ack"] * len(messages)
        for (delivery_tag, _), result in zip(messages, results):
            self.settle(delivery_tag, result)

    def consume_queue_batched(self) -> None:
        """Consume the queue in batches: batch_size messages, or fewer when no other one arrived within
        batch_wait seconds."""
        pending: List[Delivery] = []
        for message in self.channel.consume(
            self.queue_name, inactivity_timeout=self.batch_wait
        ):
            if self.should_stop:
                break
            # (None, None, None) when nothing arrived within batch_wait seconds
            if all(message):
                method, _, body = message
                pending.append((method.delivery_tag, body))
                if len(pending) < self.batch_size:
                    continue
            elif not pending:
                continue
            # A full batch, or the queue went quiet: process what came
            batch, pending = pending, []
            self.process_batch(batch)

    def process_batch(self, messages: List[Delivery]) -> None:
        """Handle a batch in the thread pool and wait for it: one batch at a time per queue."""
        self.logger.info(
            "Processing messages together, launching a thread...",
            {"queue": self.queue_name, "messages": len(messages)},
        )
        task_future = self.submit_fn(functools.partial(self.consume_batch, messages))
        while not task_future.done():
            self.pika_connection.sleep(0.05)

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
        self.settle(delivery_tag, result)

    def consume_queue(self) -> None:
        try:
            self.logger.info(
                "Thread for queue started",
                {"consumer_type": self.consumer_type, "queue": self.queue_name},
            )
            if self.handle_batch is not None and self.batch_size > 1:
                self.consume_queue_batched()
                return

            # Consume the queue with a generator
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self.should_stop:
                    break
                if not all(message):
                    continue
                method, properties, body = message
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
                while task_future.running():  # Loop while the thread is processing
                    self.pika_connection.sleep(0.05)
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
