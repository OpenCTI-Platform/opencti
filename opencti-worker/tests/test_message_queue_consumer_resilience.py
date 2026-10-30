"""Unit tests for MessageQueueConsumer.consume_message's resilience to
unexpected exceptions raised by handle_message.

These tests build a MessageQueueConsumer without running __post_init__ (which
opens a real pika connection), since consume_message only touches
self.logger, self.handle_message and self.pika_connection.add_callback_threadsafe.
"""

from unittest.mock import MagicMock

from message_queue_consumer import MessageQueueConsumer


def make_consumer(handle_message) -> MessageQueueConsumer:
    consumer = MessageQueueConsumer.__new__(MessageQueueConsumer)
    consumer.logger = MagicMock()
    consumer.handle_message = handle_message
    consumer.pika_connection = MagicMock()
    return consumer


class TestConsumeMessageAcksOnUnhandledException:
    def test_unhandled_exception_still_acks_the_message(self):
        def handle_message_raises(_body):
            raise RuntimeError("boom")

        consumer = make_consumer(handle_message_raises)

        consumer.consume_message(delivery_tag=42, body="irrelevant body")

        # The message must be resolved (never left neither ack'd nor nack'd),
        # otherwise a prefetch_count=1 channel stalls forever.
        consumer.pika_connection.add_callback_threadsafe.assert_called_once()
        scheduled_callback = (
            consumer.pika_connection.add_callback_threadsafe.call_args[0][0]
        )
        assert scheduled_callback.func == consumer.ack_message
        assert scheduled_callback.args == (42,)

    def test_unhandled_exception_is_logged_with_body_excerpt(self):
        def handle_message_raises(_body):
            raise RuntimeError("boom")

        consumer = make_consumer(handle_message_raises)

        consumer.consume_message(delivery_tag=1, body="x" * 5000)

        consumer.logger.error.assert_called_once()
        message, meta = consumer.logger.error.call_args[0]
        assert "Unhandled exception" in message
        assert "body_excerpt" in meta
        # Excerpt must be bounded, not the full (potentially huge/sensitive) body.
        assert len(meta["body_excerpt"]) <= 2000

    def test_normal_ack_result_still_acks(self):
        consumer = make_consumer(lambda _body: "ack")

        consumer.consume_message(delivery_tag=7, body="body")

        consumer.logger.error.assert_not_called()
        scheduled_callback = (
            consumer.pika_connection.add_callback_threadsafe.call_args[0][0]
        )
        assert scheduled_callback.func == consumer.ack_message

    def test_normal_nack_result_still_nacks(self):
        consumer = make_consumer(lambda _body: "nack")

        consumer.consume_message(delivery_tag=7, body="body")

        consumer.logger.error.assert_not_called()
        scheduled_callback = (
            consumer.pika_connection.add_callback_threadsafe.call_args[0][0]
        )
        assert scheduled_callback.func == consumer.nack_message
        assert scheduled_callback.args == (7, False)
