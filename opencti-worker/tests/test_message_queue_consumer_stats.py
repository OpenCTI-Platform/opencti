"""Unit tests for MessageQueueConsumer logging: per-message logs stay at debug
level and consumption is reported as one periodic summary per queue
(log the batch, not the item).

Like the resilience tests, the consumer is built without running __post_init__
(which opens a real pika connection).
"""

from unittest.mock import MagicMock, patch

from message_queue_consumer import STATS_LOG_INTERVAL_SECONDS, MessageQueueConsumer


def make_consumer(handle_message=lambda _body: "ack") -> MessageQueueConsumer:
    consumer = MessageQueueConsumer.__new__(MessageQueueConsumer)
    consumer.logger = MagicMock()
    consumer.consumer_type = "push"
    consumer.queue_name = "push_connector_1"
    consumer.handle_message = handle_message
    consumer.pika_connection = MagicMock()
    consumer.channel = MagicMock()
    consumer._init_stats(now=0.0)
    return consumer


def summary_calls(consumer: MessageQueueConsumer):
    return [
        call
        for call in consumer.logger.info.call_args_list
        if call[0][0] == "Queue consumption summary"
    ]


class TestStatsRecording:
    def test_each_result_is_counted(self):
        results = iter(["ack", "nack", "requeue", "ack"])
        consumer = make_consumer(lambda _body: next(results))

        for tag in range(4):
            consumer.consume_message(delivery_tag=tag, body="body")

        assert consumer._stats.processed == 4
        assert consumer._stats.acked == 2
        assert consumer._stats.nacked == 1
        assert consumer._stats.requeued == 1

    def test_unhandled_exception_is_counted_as_acked(self):
        def handle_message_raises(_body):
            raise RuntimeError("boom")

        consumer = make_consumer(handle_message_raises)

        consumer.consume_message(delivery_tag=1, body="body")

        assert consumer._stats.processed == 1
        assert consumer._stats.acked == 1

    def test_processing_duration_is_recorded(self):
        consumer = make_consumer()

        # Two messages: 0.1s then 0.3s of processing
        with patch(
            "message_queue_consumer.time.monotonic",
            side_effect=[10.0, 10.1, 20.0, 20.3],
        ):
            consumer.consume_message(delivery_tag=1, body="body")
            consumer.consume_message(delivery_tag=2, body="body")

        assert round(consumer._stats.total_processing_ms) == 400
        assert round(consumer._stats.max_processing_ms) == 300


class TestPeriodicSummary:
    def test_no_summary_before_interval(self):
        consumer = make_consumer()
        consumer.consume_message(delivery_tag=1, body="body")

        consumer._maybe_log_stats(now=STATS_LOG_INTERVAL_SECONDS - 1)

        assert summary_calls(consumer) == []
        assert consumer._stats.processed == 1

    def test_summary_after_interval_then_counters_reset(self):
        results = iter(["ack", "ack", "nack"])
        consumer = make_consumer(lambda _body: next(results))
        with patch(
            "message_queue_consumer.time.monotonic",
            side_effect=[0.0, 0.1, 1.0, 1.2, 2.0, 2.6],
        ):
            for tag in range(3):
                consumer.consume_message(delivery_tag=tag, body="body")

        consumer._maybe_log_stats(now=STATS_LOG_INTERVAL_SECONDS)

        calls = summary_calls(consumer)
        assert len(calls) == 1
        meta = calls[0][0][1]
        assert meta["consumer_type"] == "push"
        assert meta["queue"] == "push_connector_1"
        assert meta["interval_seconds"] == STATS_LOG_INTERVAL_SECONDS
        assert meta["processed"] == 3
        assert meta["acked"] == 2
        assert meta["nacked"] == 1
        assert meta["requeued"] == 0
        assert meta["avg_processing_ms"] == 300
        assert meta["max_processing_ms"] == 600

        # Counters reset and a new window starts
        assert consumer._stats.processed == 0
        consumer._maybe_log_stats(now=STATS_LOG_INTERVAL_SECONDS * 2 - 1)
        assert len(summary_calls(consumer)) == 1

    def test_idle_queue_logs_nothing(self):
        consumer = make_consumer()

        consumer._maybe_log_stats(now=STATS_LOG_INTERVAL_SECONDS * 10)

        consumer.logger.info.assert_not_called()

    def test_flush_on_stop_logs_partial_window(self):
        consumer = make_consumer()
        consumer.consume_message(delivery_tag=1, body="body")

        consumer._flush_stats(now=5.0)

        calls = summary_calls(consumer)
        assert len(calls) == 1
        assert calls[0][0][1]["processed"] == 1
        assert calls[0][0][1]["interval_seconds"] == 5


class TestPerMessageLogLevels:
    def test_ack_and_nack_log_at_debug_only(self):
        consumer = make_consumer()
        consumer.channel.is_open = True

        consumer.ack_message(1)
        consumer.nack_message(2, requeue=False)

        consumer.logger.info.assert_not_called()
        assert consumer.logger.debug.call_count == 2
        consumer.channel.basic_ack.assert_called_once_with(1)
        consumer.channel.basic_nack.assert_called_once_with(2, requeue=False)

    def test_closed_channel_logs_warning(self):
        consumer = make_consumer()
        consumer.channel.is_open = False

        consumer.ack_message(1)
        consumer.nack_message(2, requeue=True)

        consumer.logger.info.assert_not_called()
        assert consumer.logger.warning.call_count == 2


class TestConsumeQueueWiring:
    def test_loop_logs_per_message_at_debug_and_summary_on_stop(self):
        consumer = make_consumer()
        consumer.should_stop = False

        def run_now(fn):
            fn()
            done = MagicMock()
            done.running.return_value = False
            return done

        consumer.submit_fn = run_now
        method = MagicMock(delivery_tag=1)
        consumer.channel.consume.return_value = iter(
            [(None, None, None), (method, MagicMock(), "body")]
        )

        consumer.consume_queue()

        info_messages = [call[0][0] for call in consumer.logger.info.call_args_list]
        assert info_messages == [
            "Thread for queue started",
            "Queue consumption summary",
            "Thread for queue terminated",
        ]
        assert summary_calls(consumer)[0][0][1]["processed"] == 1


class TestShutdownAndResilience:
    def test_wait_for_completion_stops_and_joins_thread(self):
        # Called by Worker.stop() on shutdown
        consumer = make_consumer()
        consumer.should_stop = False
        consumer.thread = MagicMock()

        consumer.wait_for_completion()

        assert consumer.should_stop is True
        consumer.thread.join.assert_called_once()

    def test_stats_failure_does_not_prevent_ack(self):
        consumer = make_consumer()
        consumer._stats = MagicMock()
        consumer._stats.record.side_effect = RuntimeError("stats boom")

        try:
            consumer.consume_message(delivery_tag=3, body="body")
        except RuntimeError:
            pass

        consumer.pika_connection.add_callback_threadsafe.assert_called_once()
        scheduled_callback = consumer.pika_connection.add_callback_threadsafe.call_args[
            0
        ][0]
        assert scheduled_callback.func == consumer.ack_message
