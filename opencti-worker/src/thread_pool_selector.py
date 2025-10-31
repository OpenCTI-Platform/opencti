from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading
from typing import Any, Callable


@dataclass(unsafe_hash=True)
class ThreadPoolSelector:  # pylint: disable=too-many-instance-attributes
    default_pool_size: int
    default_execution_pool: ThreadPoolExecutor
    realtime_pool_size: int
    realtime_execution_pool: ThreadPoolExecutor

    def __post_init__(self) -> None:
        self.default_active_threads_count = 0
        self.realtime_active_threads_count = 0
        self.count_lock = threading.Lock()

    def decrement_default_count(self, _future):
        with self.count_lock:
            self.default_active_threads_count -= 1

    def decrement_realtime_count(self, _future):
        with self.count_lock:
            self.realtime_active_threads_count -= 1

    def submit_to_default_pool(self, consume_message_fn, delivery_tag, body):
        task_future = self.default_execution_pool.submit(
            consume_message_fn, delivery_tag, body
        )
        with self.count_lock:
            self.default_active_threads_count += 1
        task_future.add_done_callback(self.decrement_default_count)
        return task_future

    def submit_to_realtime_pool(self, fn: Callable[..., Any], *args: Any, **kwargs: Any):
        task_future = self.realtime_execution_pool.submit(
            fn, args, kwargs
        )
        with self.count_lock:
            self.realtime_active_threads_count += 1
        task_future.add_done_callback(self.decrement_realtime_count)
        return task_future

    def submit(self, is_realtime, fn: Callable[..., Any], *args: Any, **kwargs: Any):
        is_default_pool_full = (
            self.default_active_threads_count >= self.default_pool_size
        )
        is_realtime_pool_full = (
            self.realtime_active_threads_count >= self.realtime_pool_size
        )
        if is_realtime:
            if is_realtime_pool_full and not is_default_pool_full:
                return self.submit_to_default_pool(fn, args, kwargs)
            else:
                return self.submit_to_realtime_pool(fn, args, kwargs)
        else:
            if is_default_pool_full and not is_realtime_pool_full:
                return self.submit_to_realtime_pool(fn, args, kwargs)
            else:
                return self.submit_to_default_pool(fn, args, kwargs)
