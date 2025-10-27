from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor


@dataclass(unsafe_hash=True)
class ThreadPoolSelector:  # pylint: disable=too-many-instance-attributes
    default_pool_size: int
    default_execution_pool: ThreadPoolExecutor
    realtime_pool_size: int
    realtime_execution_pool: ThreadPoolExecutor

    def __post_init__(self) -> None:
        self.default_active_threads = set()
        self.realtime_active_threads = set()

    def submit_to_default_pool(self, consume_message_fn, delivery_tag, body):
        task_future = self.default_execution_pool.submit(
            consume_message_fn, delivery_tag, body
        )
        self.default_active_threads.add(task_future)
        task_future.add_done_callback(self.default_active_threads.remove)
        return task_future

    def submit_to_realtime_pool(self, consume_message_fn, delivery_tag, body):
        task_future = self.realtime_execution_pool.submit(
            consume_message_fn, delivery_tag, body
        )
        self.realtime_active_threads.add(task_future)
        task_future.add_done_callback(self.realtime_active_threads.remove)
        return task_future

    def submit(self, is_realtime, consume_message_fn, delivery_tag, body):
        if is_realtime:
            if (
                len(self.default_active_threads) <= self.default_pool_size
                and len(self.realtime_active_threads) > self.realtime_pool_size
            ):
                return self.submit_to_default_pool(
                    consume_message_fn, delivery_tag, body
                )
            else:
                return self.submit_to_realtime_pool(
                    consume_message_fn, delivery_tag, body
                )
        else:
            if (
                len(self.realtime_active_threads) <= self.realtime_pool_size
                and len(self.default_active_threads) > self.default_pool_size
            ):
                return self.submit_to_realtime_pool(
                    consume_message_fn, delivery_tag, body
                )
            else:
                return self.submit_to_default_pool(
                    consume_message_fn, delivery_tag, body
                )
