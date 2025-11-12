import logging
from datetime import datetime, timezone

from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging."""

    def add_fields(self, log_record, record, message_dict):
        """Add custom fields to the log record.

        :param log_record: The log record dictionary
        :param record: The LogRecord instance
        :param message_dict: The message dictionary
        """
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get("timestamp"):
            # This doesn't use record.created, so it is slightly off
            now = datetime.now(tz=timezone.utc)
            log_record["timestamp"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if log_record.get("level"):
            log_record["level"] = log_record["level"].upper()
        else:
            log_record["level"] = record.levelname


def logger(level, json_logging=True):
    """Create a logger with JSON or standard formatting.

    :param level: Logging level (e.g., logging.INFO, logging.DEBUG)
    :param json_logging: Whether to use JSON formatting for logs
    :type json_logging: bool
    :return: AppLogger class
    :rtype: class
    """
    # Exceptions
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("pika").setLevel(logging.ERROR)
    # Exceptions
    if json_logging:
        log_handler = logging.StreamHandler()
        log_handler.setLevel(level)
        formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
        log_handler.setFormatter(formatter)
        logging.basicConfig(handlers=[log_handler], level=level, force=True)
    else:
        logging.basicConfig(level=level)

    class AppLogger:
        def __init__(self, name):
            self.local_logger = logging.getLogger(name)

        @staticmethod
        def prepare_meta(meta=None):
            """Prepare metadata for logging.

            :param meta: Metadata dictionary or None
            :type meta: dict or None
            :return: Formatted metadata or None
            :rtype: dict or None
            """
            return None if meta is None else {"attributes": meta}

        @staticmethod
        def setup_logger_level(lib, log_level):
            """Set the logging level for a specific library.

            :param lib: Library name
            :type lib: str
            :param log_level: Logging level to set
            """
            logging.getLogger(lib).setLevel(log_level)

        def debug(self, message, meta=None):
            """Log a debug message.

            :param message: Message to log
            :type message: str
            :param meta: Optional metadata to include
            :type meta: dict or None
            """
            self.local_logger.debug(message, extra=AppLogger.prepare_meta(meta))

        def info(self, message, meta=None):
            """Log an info message.

            :param message: Message to log
            :type message: str
            :param meta: Optional metadata to include
            :type meta: dict or None
            """
            self.local_logger.info(message, extra=AppLogger.prepare_meta(meta))

        def warning(self, message, meta=None):
            """Log a warning message.

            :param message: Message to log
            :type message: str
            :param meta: Optional metadata to include
            :type meta: dict or None
            """
            self.local_logger.warning(message, extra=AppLogger.prepare_meta(meta))

        def error(self, message, meta=None):
            """Log an error message with exception info.

            :param message: Message to log
            :type message: str
            :param meta: Optional metadata to include
            :type meta: dict or None
            """
            # noinspection PyTypeChecker
            self.local_logger.error(
                message, exc_info=1, extra=AppLogger.prepare_meta(meta)
            )

    return AppLogger
