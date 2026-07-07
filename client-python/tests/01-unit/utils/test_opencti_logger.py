import logging
from unittest.mock import Mock

from pycti.utils.opencti_logger import logger


def test_info_skips_lazy_metadata_when_info_is_disabled():
    app_logger = logger("ERROR", json_logging=False)("test")
    app_logger.local_logger = Mock()
    app_logger.local_logger.isEnabledFor.return_value = False
    build_meta = Mock(return_value={"filters": '{"mode": "and"}'})

    app_logger.info("Listing Campaigns with filters", build_meta)

    app_logger.local_logger.isEnabledFor.assert_called_once_with(logging.INFO)
    build_meta.assert_not_called()
    app_logger.local_logger.info.assert_not_called()


def test_info_resolves_lazy_metadata_when_info_is_enabled():
    app_logger = logger("INFO", json_logging=False)("test")
    app_logger.local_logger = Mock()
    app_logger.local_logger.isEnabledFor.return_value = True
    build_meta = Mock(return_value={"filters": '{"mode": "and"}'})

    app_logger.info("Listing Campaigns with filters", build_meta)

    app_logger.local_logger.isEnabledFor.assert_called_once_with(logging.INFO)
    build_meta.assert_called_once_with()
    app_logger.local_logger.info.assert_called_once_with(
        "Listing Campaigns with filters",
        extra={"attributes": {"filters": '{"mode": "and"}'}},
    )
