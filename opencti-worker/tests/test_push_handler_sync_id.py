"""Unit test pinning that the push handler exposes its queue id to the API
client as sync_id, sent when attaching staged sync files.
"""

from unittest.mock import MagicMock, patch

from push_handler import PushHandler


def test_post_init_sets_sync_id_on_api():
    with patch("push_handler.OpenCTIApiClient", return_value=MagicMock()):
        handler = PushHandler(
            logger=MagicMock(),
            log_level="info",
            json_logging=False,
            opencti_url="http://localhost:4000",
            opencti_token="token",
            ssl_verify=False,
            connector_id="sync-id",
            push_exchange="push-exchange",
            listen_exchange="listen-exchange",
            push_routing="push-routing",
            dead_letter_routing="dead-letter-routing",
            pika_parameters=MagicMock(),
            bundles_global_counter=MagicMock(),
            bundles_processing_time_gauge=MagicMock(),
            objects_max_refs=0,
        )

    assert handler.api.sync_id == "sync-id"
