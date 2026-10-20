"""Queue loop benchmark: the overhead of the worker's RabbitMQ consumer loop per message.

Runs the real MessageQueueConsumer from opencti-worker/src on a temporary durable queue, with a handler
that sleeps a fixed time. Anything above that time per message is the loop's own cost: the wait for the
handler, the ack and the next delivery (prefetch_count=1). A second consumer, identical except that it waits
on done() with a 1 ms tick instead of running() with a 50 ms tick, shows whether that wait matters.

The queue is deleted at the end of each run.
"""

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pika

HANDLER_MS = (0, 10, 25, 33)


class QuietLogger:
    def info(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, message, meta=None):
        print("ERROR", message, meta, file=sys.stderr)


def build_consumers(worker_src):
    sys.path.insert(0, worker_src)
    from message_queue_consumer import (  # pylint: disable=import-outside-toplevel
        MessageQueueConsumer,
    )

    class FineGrainedWaitConsumer(MessageQueueConsumer):
        """The worker's loop, waiting on done() with a 1 ms tick."""

        def consume_queue(self) -> None:
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self.should_stop:
                    break
                if not all(message):
                    continue
                method, _properties, body = message
                future = self.submit_fn(
                    lambda tag=method.delivery_tag, b=body: self.consume_message(tag, b)
                )
                while not future.done():
                    self.pika_connection.sleep(0.001)

    return {
        "current_loop": MessageQueueConsumer,
        "done_1ms_loop": FineGrainedWaitConsumer,
    }


def run(parameters, consumer_class, handler_ms, messages):
    queue = f"bench-queue-loop-{int(time.time() * 1000)}"
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    try:
        for i in range(messages):
            channel.basic_publish(
                exchange="",
                routing_key=queue,
                body=json.dumps({"i": i}),
                properties=pika.BasicProperties(delivery_mode=2),
            )
        handled = []
        all_handled = threading.Event()

        def handle(_body):
            if handler_ms:
                time.sleep(handler_ms / 1000)
            handled.append(1)
            if len(handled) == messages:
                all_handled.set()
            return "ack"

        executor = ThreadPoolExecutor(max_workers=2)
        start = time.perf_counter()
        consumer = consumer_class(
            QuietLogger(), "push", queue, parameters, executor.submit, handle
        )
        all_handled.wait(timeout=600)
        wall = (time.perf_counter() - start) * 1000
        consumer.wait_for_completion()
        executor.shutdown()
        left = channel.queue_declare(queue=queue, passive=True).method.message_count
    finally:
        channel.queue_delete(queue=queue)
        connection.close()
    per_message = wall / messages
    return {
        "handler_ms": handler_ms,
        "messages": messages,
        "handled": len(handled),
        "left_in_queue": left,
        "per_message_ms": round(per_message, 2),
        "loop_overhead_ms": round(per_message - handler_ms, 2),
        "throughput_per_s": round(messages / wall * 1000, 1),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--worker-src", required=True, help="path to opencti-worker/src"
    )
    parser.add_argument("--messages", type=int, default=200)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5672)
    parser.add_argument("--vhost", default="/")
    parser.add_argument("--user", default="guest")
    parser.add_argument("--password", default="guest")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    parameters = pika.ConnectionParameters(
        host=args.host,
        port=args.port,
        virtual_host=args.vhost,
        credentials=pika.PlainCredentials(args.user, args.password),
    )
    results = {"params": {"messages": args.messages}}
    for name, consumer_class in build_consumers(args.worker_src).items():
        for handler_ms in HANDLER_MS:
            results[f"{name}_handler{handler_ms}ms"] = run(
                parameters, consumer_class, handler_ms, args.messages
            )
    with open(args.out, "w", encoding="utf-8") as output:
        json.dump({"scenario": "queue-loop", "results": results}, output, indent=1)


if __name__ == "__main__":
    main()
