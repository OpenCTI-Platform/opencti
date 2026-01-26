"""OpenCTI Connector Helper module.

This module provides the main helper class and utilities for building OpenCTI
connectors. It handles connector registration, message queue communication,
stream listening, scheduling, and STIX2 bundle processing.

Key components:
    - OpenCTIConnectorHelper: Main class for connector development
    - ListenQueue: Handles RabbitMQ message consumption
    - ListenStream: Handles SSE stream consumption
    - PingAlive: Maintains connector heartbeat with the platform
    - ConnectorInfo: Stores connector runtime information

Example:
    >>> from pycti import OpenCTIConnectorHelper
    >>> helper = OpenCTIConnectorHelper(config)
    >>> helper.listen(callback_function)
"""

import asyncio
import base64
import copy
import datetime
import json
import os
import queue
import re
import sched
import signal
import ssl
import sys
import tempfile
import threading
import time
import uuid
from enum import Enum
from queue import Queue
from typing import Callable, Dict, List, Optional, Union

import boto3
import pika
import uvicorn
from botocore.config import Config as BotoConfig
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from filigran_sseclient import SSEClient
from pika.exceptions import NackError, UnroutableError
from pydantic import TypeAdapter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector import OpenCTIConnector
from pycti.connector.opencti_metric_handler import OpenCTIMetricHandler
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

TRUTHY: List[str] = ["yes", "true", "True"]
"""List of string values considered as boolean True."""

FALSY: List[str] = ["no", "false", "False"]
"""List of string values considered as boolean False."""

app = FastAPI()


def killProgramHook(etype, value, tb) -> None:
    """Exception hook to terminate the program on unhandled exceptions.

    This function is used as a system exception hook to ensure the program
    terminates cleanly when an unhandled exception occurs, particularly
    useful for background threads.

    :param etype: The exception type (class)
    :type etype: type
    :param value: The exception instance
    :type value: BaseException
    :param tb: The traceback object
    :type tb: types.TracebackType
    """
    os.kill(os.getpid(), signal.SIGTERM)


def start_loop(loop) -> None:
    """Start an asyncio event loop and run it forever.

    Sets the given event loop as the current loop for the thread and
    runs it indefinitely until stopped.

    :param loop: The asyncio event loop to start
    :type loop: asyncio.AbstractEventLoop
    """
    asyncio.set_event_loop(loop)
    loop.run_forever()


def get_config_variable(
    env_var: str,
    yaml_path: List,
    config: Optional[Dict] = None,
    isNumber: Optional[bool] = False,
    default=None,
    required=False,
) -> Union[bool, int, None, str]:
    """Retrieve a configuration variable from environment or YAML config.

    Looks up configuration values with the following precedence:
    1. Environment variable (highest priority)
    2. YAML configuration file
    3. Default value (lowest priority)

    Boolean string values ("yes", "true", "True", "no", "false", "False")
    are automatically converted to Python bool.

    :param env_var: Name of the environment variable to check
    :type env_var: str
    :param yaml_path: Two-element list specifying [section, key] in YAML config
    :type yaml_path: List[str]
    :param config: Configuration dictionary loaded from YAML file
    :type config: Dict
    :param isNumber: If True, convert the value to integer
    :type isNumber: bool
    :param default: Default value if not found in env or config
    :type default: any
    :param required: If True and no value found, raise ValueError
    :type required: bool

    :return: The configuration value as bool, int, str, or None
    :rtype: Union[bool, int, None, str]

    :raises ValueError: If required=True and no value is found

    Example:
        >>> get_config_variable("OPENCTI_URL", ["opencti", "url"], config)
        'http://localhost:8080'
        >>> get_config_variable("CONNECTOR_LOG_LEVEL", ["connector", "log_level"],
        ...                     config, default="INFO")
        'INFO'
    """
    if config is None:
        config = {}

    if os.getenv(env_var) is not None:
        result = os.getenv(env_var)
    elif yaml_path is not None:
        if yaml_path[0] in config and yaml_path[1] in config[yaml_path[0]]:
            result = config[yaml_path[0]][yaml_path[1]]
        else:
            return default
    else:
        return default

    if result in TRUTHY:
        return True
    if result in FALSY:
        return False
    if isNumber:
        return int(result)

    if (
        required
        and default is None
        and (result is None or (isinstance(result, str) and len(result) == 0))
    ):
        raise ValueError("The configuration " + env_var + " is required")

    if isinstance(result, str) and len(result) == 0:
        return default

    return result


def normalize_email_prefix(email: str) -> str:
    """Normalize the local part of an email address by replacing invalid characters.

    Replaces any characters not valid in email prefixes with hyphens.
    Valid characters include: a-z, A-Z, 0-9, and special chars: . _ + -
    Consecutive hyphens are collapsed and leading/trailing hyphens are removed.

    :param email: Email address to normalize
    :type email: str

    :return: Normalized email address with valid local part
    :rtype: str

    :raises ValueError: If the email address does not contain an '@' symbol

    Example:
        >>> normalize_email_prefix("john.doe@example.com")
        'john.doe@example.com'
        >>> normalize_email_prefix("john@doe@example.com")
        'john-doe@example.com'
        >>> normalize_email_prefix("user!name@domain.com")
        'user-name@domain.com'
    """
    if "@" not in email:
        raise ValueError("Invalid email: missing '@' symbol")

    # Split email into prefix and domain
    parts = email.split("@")
    if len(parts) != 2:
        # Multiple @ signs - treat first @ as the separator
        prefix = parts[0]
        domain = "@".join(parts[1:])
    else:
        prefix, domain = parts

    # Replace invalid characters with hyphen
    # Valid chars: alphanumeric, dot, underscore, plus, hyphen
    normalized_prefix = re.sub(r"[^a-zA-Z0-9._+-]", "-", prefix)

    # Optional: Remove consecutive hyphens and leading/trailing hyphens
    normalized_prefix = re.sub(r"-+", "-", normalized_prefix)
    normalized_prefix = normalized_prefix.strip("-")

    return f"{normalized_prefix}@{domain}"


def is_memory_certificate(certificate: str) -> bool:
    """Check if a certificate is provided as a PEM string in memory.

    Determines whether the certificate data is an in-memory PEM-formatted
    string (starting with "-----BEGIN") rather than a file path.

    :param certificate: The certificate data to check (PEM string or file path)
    :type certificate: str

    :return: True if the certificate is a PEM string, False if it's a file path
    :rtype: bool

    Example:
        >>> is_memory_certificate("-----BEGIN CERTIFICATE-----\\n...")
        True
        >>> is_memory_certificate("/path/to/cert.pem")
        False
    """
    return certificate.startswith("-----BEGIN")


def ssl_verify_locations(ssl_context: ssl.SSLContext, certdata: Optional[str]) -> None:
    """Load CA certificate verification locations into an SSL context.

    Configures the SSL context with certificate authority (CA) certificates
    for verifying peer certificates. Supports both file paths and in-memory
    PEM-formatted certificates.

    :param ssl_context: The SSL context to configure
    :type ssl_context: ssl.SSLContext
    :param certdata: CA certificate data as file path or PEM string, or None to skip
    :type certdata: str or None

    Example:
        >>> ssl_ctx = ssl.create_default_context()
        >>> ssl_verify_locations(ssl_ctx, "/path/to/ca-bundle.crt")
        >>> ssl_verify_locations(ssl_ctx, "-----BEGIN CERTIFICATE-----\\n...")
    """
    if certdata is None:
        return

    if is_memory_certificate(certdata):
        ssl_context.load_verify_locations(cadata=certdata)
    else:
        ssl_context.load_verify_locations(cafile=certdata)


def data_to_temp_file(data: str) -> str:
    """Write data to a temporary file securely.

    Creates a temporary file with secure permissions (readable and writable
    only by the creating user). The file descriptor is not inherited by
    child processes.

    .. note::
        The caller is responsible for deleting the temporary file when
        it is no longer needed.

    :param data: The string data to write to the temporary file
    :type data: str

    :return: Absolute path to the created temporary file
    :rtype: str

    Example:
        >>> path = data_to_temp_file("-----BEGIN PRIVATE KEY-----\\n...")
        >>> # Use the file...
        >>> os.unlink(path)  # Clean up when done
    """
    # The file is readable and writable only by the creating user ID.
    # If the operating system uses permission bits to indicate whether a
    # file is executable, the file is executable by no one. The file
    # descriptor is not inherited by children of this process.
    file_descriptor, file_path = tempfile.mkstemp()
    with os.fdopen(file_descriptor, "w") as open_file:
        open_file.write(data)
    return file_path


def ssl_cert_chain(
    ssl_context: ssl.SSLContext,
    cert_data: Optional[str],
    key_data: Optional[str],
    passphrase: Optional[str],
) -> None:
    """Load a certificate chain and private key into an SSL context.

    Configures the SSL context with a client certificate and private key
    for mutual TLS authentication. Supports both file paths and in-memory
    PEM-formatted certificates/keys. Temporary files are created and
    cleaned up automatically when using in-memory data.

    :param ssl_context: The SSL context to configure
    :type ssl_context: ssl.SSLContext
    :param cert_data: Certificate data as file path or PEM string, or None to skip
    :type cert_data: str or None
    :param key_data: Private key data as file path or PEM string, or None
    :type key_data: str or None
    :param passphrase: Passphrase for encrypted private key, or None if unencrypted
    :type passphrase: str or None

    Example:
        >>> ssl_ctx = ssl.create_default_context()
        >>> ssl_cert_chain(ssl_ctx, "/path/to/cert.pem", "/path/to/key.pem", None)
    """
    if cert_data is None:
        return

    cert_file_path = None
    key_file_path = None

    # Cert loading
    if cert_data is not None and is_memory_certificate(cert_data):
        cert_file_path = data_to_temp_file(cert_data)
    cert = cert_file_path if cert_file_path is not None else cert_data

    # Key loading
    if key_data is not None and is_memory_certificate(key_data):
        key_file_path = data_to_temp_file(key_data)
    key = key_file_path if key_file_path is not None else key_data

    # Load cert
    ssl_context.load_cert_chain(cert, key, passphrase)
    # Remove temp files
    if cert_file_path is not None:
        os.unlink(cert_file_path)
    if key_file_path is not None:
        os.unlink(key_file_path)


def create_callback_ssl_context(config: Dict) -> ssl.SSLContext:
    """Create an SSL context for the API callback server.

    Creates and configures an SSL context suitable for the HTTPS callback
    server used in API listen protocol mode. Loads certificate chain from
    configuration.

    Configuration keys used:
        - LISTEN_PROTOCOL_API_SSL_KEY: Path or PEM string for SSL private key
        - LISTEN_PROTOCOL_API_SSL_CERT: Path or PEM string for SSL certificate
        - LISTEN_PROTOCOL_API_SSL_PASSPHRASE: Optional passphrase for private key

    :param config: Configuration dictionary containing SSL settings
    :type config: Dict

    :return: Configured SSL context for client authentication
    :rtype: ssl.SSLContext
    """
    listen_protocol_api_ssl_key = get_config_variable(
        "LISTEN_PROTOCOL_API_SSL_KEY",
        ["connector", "listen_protocol_api_ssl_key"],
        config,
        default="",
    )
    listen_protocol_api_ssl_cert = get_config_variable(
        "LISTEN_PROTOCOL_API_SSL_CERT",
        ["connector", "listen_protocol_api_ssl_cert"],
        config,
        default="",
    )
    listen_protocol_api_ssl_passphrase = get_config_variable(
        "LISTEN_PROTOCOL_API_SSL_PASSPHRASE",
        ["connector", "listen_protocol_api_ssl_passphrase"],
        config,
        default="",
    )
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_cert_chain(
        ssl_context,
        listen_protocol_api_ssl_cert,
        listen_protocol_api_ssl_key,
        listen_protocol_api_ssl_passphrase,
    )
    return ssl_context


def create_mq_ssl_context(config: Dict) -> ssl.SSLContext:
    """Create an SSL context for RabbitMQ message queue connections.

    Creates and configures an SSL context for secure connections to RabbitMQ.
    Supports CA verification, client certificates, and optional certificate
    verification bypass.

    Configuration keys used:
        - MQ_USE_SSL_CA: CA certificate for server verification
        - MQ_USE_SSL_CERT: Client certificate for mutual TLS
        - MQ_USE_SSL_KEY: Client private key for mutual TLS
        - MQ_USE_SSL_REJECT_UNAUTHORIZED: Whether to verify server certificate
        - MQ_USE_SSL_PASSPHRASE: Optional passphrase for private key

    :param config: Configuration dictionary containing MQ SSL settings
    :type config: Dict

    :return: Configured SSL context for RabbitMQ connections
    :rtype: ssl.SSLContext
    """
    use_ssl_ca = get_config_variable("MQ_USE_SSL_CA", ["mq", "use_ssl_ca"], config)
    use_ssl_cert = get_config_variable(
        "MQ_USE_SSL_CERT", ["mq", "use_ssl_cert"], config
    )
    use_ssl_key = get_config_variable("MQ_USE_SSL_KEY", ["mq", "use_ssl_key"], config)
    use_ssl_reject_unauthorized = get_config_variable(
        "MQ_USE_SSL_REJECT_UNAUTHORIZED",
        ["mq", "use_ssl_reject_unauthorized"],
        config,
        False,
        False,
    )
    use_ssl_passphrase = get_config_variable(
        "MQ_USE_SSL_PASSPHRASE", ["mq", "use_ssl_passphrase"], config
    )
    ssl_context = ssl.create_default_context()
    # If no rejection allowed, use private function to generate unverified context
    if not use_ssl_reject_unauthorized:
        # noinspection PyUnresolvedReferences,PyProtectedMember
        ssl_context = ssl._create_unverified_context()
    ssl_verify_locations(ssl_context, use_ssl_ca)
    # Thanks to https://bugs.python.org/issue16487 is not possible today to easily use memory pem
    # in SSL context. We need to write it to a temporary file before
    ssl_cert_chain(ssl_context, use_ssl_cert, use_ssl_key, use_ssl_passphrase)
    return ssl_context


class ListenQueue(threading.Thread):
    """Thread class for consuming messages from RabbitMQ or HTTP API.

    Handles message consumption from either RabbitMQ (AMQP protocol) or
    an HTTP API endpoint, depending on the configured listen protocol.
    Messages are processed through a callback function provided at initialization.

    This class supports two listen protocols:
        - AMQP: Connects to RabbitMQ and consumes messages from a queue
        - API: Starts an HTTP server and receives messages via POST requests

    :param helper: The OpenCTIConnectorHelper instance
    :type helper: OpenCTIConnectorHelper
    :param opencti_token: Authentication token for OpenCTI API
    :type opencti_token: str
    :param config: Global configuration dictionary
    :type config: Dict
    :param connector_config: Connector-specific configuration from registration
    :type connector_config: Dict
    :param applicant_id: ID of the user/connector making requests
    :type applicant_id: str
    :param listen_protocol: Protocol to use ("AMQP" or "API")
    :type listen_protocol: str
    :param listen_protocol_api_ssl: Whether to use SSL for API protocol
    :type listen_protocol_api_ssl: bool
    :param listen_protocol_api_path: URL path for API endpoint
    :type listen_protocol_api_path: str
    :param listen_protocol_api_port: Port for API server
    :type listen_protocol_api_port: int
    :param callback: Function to call when processing messages
    :type callback: Callable[[Dict], str]
    """

    def __init__(
        self,
        helper,
        opencti_token: str,
        config: Dict,
        connector_config: Dict,
        applicant_id: str,
        listen_protocol: str,
        listen_protocol_api_ssl: bool,
        listen_protocol_api_path: str,
        listen_protocol_api_port: int,
        callback: Callable[[Dict], str],
    ) -> None:
        """Initialize the ListenQueue thread.

        :param helper: The OpenCTIConnectorHelper instance
        :type helper: OpenCTIConnectorHelper
        :param opencti_token: Authentication token for OpenCTI API
        :type opencti_token: str
        :param config: Global configuration dictionary
        :type config: Dict
        :param connector_config: Connector configuration from registration
        :type connector_config: Dict
        :param applicant_id: ID of the user/connector making requests
        :type applicant_id: str
        :param listen_protocol: Protocol to use ("AMQP" or "API")
        :type listen_protocol: str
        :param listen_protocol_api_ssl: Whether to use SSL for API protocol
        :type listen_protocol_api_ssl: bool
        :param listen_protocol_api_path: URL path for API endpoint
        :type listen_protocol_api_path: str
        :param listen_protocol_api_port: Port for API server
        :type listen_protocol_api_port: int
        :param callback: Function to process received messages
        :type callback: Callable[[Dict], str]
        """
        threading.Thread.__init__(self)
        self.pika_credentials = None
        self.pika_parameters = None
        self.pika_connection = None
        self.channel = None
        self.helper = helper
        self.callback = callback
        self.config = config
        self.opencti_token = opencti_token
        self.listen_protocol = listen_protocol
        self.listen_protocol_api_ssl = listen_protocol_api_ssl
        self.listen_protocol_api_path = listen_protocol_api_path
        self.listen_protocol_api_port = listen_protocol_api_port
        self.connector_applicant_id = applicant_id
        self.host = connector_config["connection"]["host"]
        self.vhost = connector_config["connection"]["vhost"]
        self.use_ssl = connector_config["connection"]["use_ssl"]
        self.port = connector_config["connection"]["port"]
        self.user = connector_config["connection"]["user"]
        self.password = connector_config["connection"]["pass"]
        self.queue_name = connector_config["listen"]
        self.exit_event = threading.Event()
        self.thread = None

    # noinspection PyUnusedLocal
    def _process_message(self, channel, method, properties, body) -> None:
        """Process a message from the RabbitMQ queue.

        Acknowledges the message immediately before processing to prevent
        infinite re-delivery if the connector fails. Spawns a separate thread
        for data handling and maintains the connection alive during processing.

        :param channel: The RabbitMQ channel instance
        :type channel: pika.channel.Channel
        :param method: Message delivery method with routing info and delivery tag
        :type method: pika.spec.Basic.Deliver
        :param properties: Message properties (unused)
        :type properties: pika.spec.BasicProperties
        :param body: The message body containing JSON data
        :type body: bytes
        """
        json_data = json.loads(body)
        # Message should be ack before processing as we don't own the processing
        # Not ACK the message here may lead to infinite re-deliver if the connector is broken
        # Also ACK, will not have any impact on the blocking aspect of the following functions
        channel.basic_ack(delivery_tag=method.delivery_tag)
        self.helper.connector_logger.info("Message ack", {"tag": method.delivery_tag})

        self.thread = threading.Thread(target=self._data_handler, args=[json_data])
        self.thread.start()
        five_minutes = 60 * 5
        time_wait = 0
        # Wait for end of execution of the _data_handler
        while self.thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(0.05)
            if (
                self.helper.work_id is not None and time_wait > five_minutes
            ):  # Ping every 5 minutes
                self.helper.api.work.ping(self.helper.work_id)
                time_wait = 0
            else:
                time_wait += 1
            time.sleep(1)
        self.helper.connector_logger.info(
            "Message processed, thread terminated",
            {"tag": method.delivery_tag},
        )

    def _set_draft_id(self, draft_id):
        """Set the draft ID for the helper and API instances.

        :param draft_id: The draft ID to set
        :type draft_id: str
        """
        self.helper.draft_id = draft_id
        self.helper.api.set_draft_id(draft_id)
        self.helper.api_impersonate.set_draft_id(draft_id)

    def _data_handler(self, json_data: Dict) -> None:
        """Process incoming message data and execute the callback.

        Handles the full message processing workflow including:
        - Extracting event data and entity information
        - Setting up draft and work contexts
        - Resolving enrichment entity data for enrichment connectors
        - Handling playbook execution context
        - Managing organization sharing propagation
        - Executing the user-provided callback function

        :param json_data: The parsed JSON message data containing event and internal info
        :type json_data: Dict
        """
        work_id = None
        # Execute the callback
        try:
            event_data = json_data["event"]
            entity_id = event_data.get("entity_id")
            entity_type = event_data.get("entity_type")
            stix_entity = (
                json.loads(event_data.get("stix_entity"))
                if event_data.get("stix_entity")
                else None
            )
            stix_objects = (
                json.loads(event_data.get("stix_objects"))
                if event_data.get("stix_objects")
                else None
            )
            validation_mode = event_data.get("validation_mode", "workbench")
            force_validation = event_data.get("force_validation", False)
            # Set the API headers
            internal_data = json_data["internal"]
            work_id = internal_data["work_id"]
            draft_id = internal_data.get("draft_id", "")
            self.helper.work_id = work_id

            self.helper.validation_mode = validation_mode
            self.helper.force_validation = force_validation

            self._set_draft_id(draft_id)

            self.helper.playbook = None
            self.helper.enrichment_shared_organizations = None
            if self.helper.connect_type == "INTERNAL_ENRICHMENT":
                # For enrichment connectors only, pre resolve the information
                if entity_id is None:
                    raise ValueError(
                        "Internal enrichment must be based on a specific id"
                    )
                do_read = self.helper.api.stix2.get_reader(
                    entity_type if entity_type is not None else "Stix-Core-Object"
                )
                opencti_entity = do_read(id=entity_id, withFiles=True)
                if opencti_entity is None:
                    raise ValueError(
                        "Unable to read/access the entity, please check the connector permissions"
                    )
                event_data["enrichment_entity"] = opencti_entity
                # Handle action vs playbook behavior
                is_playbook = "playbook" in json_data["internal"]
                # If playbook, compute object on data bundle
                if is_playbook:
                    execution_start = self.helper.date_now()
                    event_id = json_data["internal"]["playbook"].get("event_id")
                    execution_id = json_data["internal"]["playbook"].get("execution_id")
                    playbook_id = json_data["internal"]["playbook"].get("playbook_id")
                    data_instance_id = json_data["internal"]["playbook"].get(
                        "data_instance_id"
                    )
                    previous_bundle = json.dumps((json_data["event"]["bundle"]))
                    step_id = json_data["internal"]["playbook"]["step_id"]
                    previous_step_id = json_data["internal"]["playbook"][
                        "previous_step_id"
                    ]
                    playbook_data = {
                        "event_id": event_id,
                        "execution_id": execution_id,
                        "execution_start": execution_start,
                        "playbook_id": playbook_id,
                        "data_instance_id": data_instance_id,
                        "previous_step_id": previous_step_id,
                        "previous_bundle": previous_bundle,
                        "step_id": step_id,
                    }
                    self.helper.playbook = playbook_data
                    bundle = event_data["bundle"]
                    stix_objects = bundle["objects"]
                    event_data["stix_objects"] = stix_objects
                    stix_entity = [e for e in stix_objects if e["id"] == entity_id][0]
                    event_data["stix_entity"] = stix_entity
                else:
                    # If not playbook but enrichment, compute object on enrichment_entity
                    opencti_entity = event_data["enrichment_entity"]
                    if stix_objects is None:
                        stix_objects = self.helper.api.stix2.prepare_export(
                            entity=self.helper.api.stix2.generate_export(
                                copy.copy(opencti_entity)
                            )
                        )
                        stix_entity = [
                            e
                            for e in stix_objects
                            if e["id"] == opencti_entity["standard_id"]
                            or e["id"] == "x-opencti-" + opencti_entity["standard_id"]
                        ][0]
                    event_data["stix_objects"] = stix_objects
                    event_data["stix_entity"] = stix_entity
                # Handle organization propagation
                # Keep the sharing to be re-apply automatically at send_stix_bundle stage
                if "x_opencti_granted_refs" in event_data["stix_entity"]:
                    self.helper.enrichment_shared_organizations = event_data[
                        "stix_entity"
                    ]["x_opencti_granted_refs"]
                else:
                    self.helper.enrichment_shared_organizations = (
                        self.helper.get_attribute_in_extension(
                            "granted_refs", event_data["stix_entity"]
                        )
                    )

            # Handle applicant_id for impersonation
            self.helper.applicant_id = self.connector_applicant_id
            self.helper.api_impersonate.set_applicant_id_header(
                self.connector_applicant_id
            )
            applicant_id = json_data["internal"]["applicant_id"]
            if applicant_id is not None:
                self.helper.applicant_id = applicant_id
                self.helper.api_impersonate.set_applicant_id_header(applicant_id)

            if work_id:
                self.helper.api.work.to_received(
                    work_id, "Connector ready to process the operation"
                )
            # Send the enriched to the callback
            message = self.callback(event_data)
            if work_id:
                self.helper.api.work.to_processed(work_id, message)
            self._set_draft_id("")

        except Exception as e:  # pylint: disable=broad-except
            self.helper.metric.inc("error_count")
            self.helper.connector_logger.error(
                "Error in message processing, reporting error to API"
            )
            self._set_draft_id("")
            if work_id:
                try:
                    self.helper.api.work.to_processed(work_id, str(e), True)
                except Exception:  # pylint: disable=broad-except
                    self.helper.metric.inc("error_count")
                    self.helper.connector_logger.error(
                        "Failing reporting the processing"
                    )

    async def _http_process_callback(self, request: Request) -> JSONResponse:
        """Handle incoming HTTP POST requests for API listen protocol.

        Validates the request authentication using Bearer token and processes
        the JSON payload through the data handler.

        :param request: The incoming FastAPI request object
        :type request: Request

        :return: JSON response with status code and message
        :rtype: JSONResponse

        Response codes:
            - 202: Message successfully received and queued for processing
            - 400: Invalid JSON payload
            - 401: Invalid or missing authentication credentials
            - 500: Error occurred during message processing
        """
        # 01. Check the authentication
        authorization: str = request.headers.get("Authorization", "")
        items = authorization.split() if isinstance(authorization, str) else []
        if (
            len(items) != 2
            or items[0].lower() != "bearer"
            or items[1] != self.opencti_token
        ):
            return JSONResponse(
                status_code=401, content={"error": "Invalid credentials"}
            )
        # 02. Parse the data and execute
        try:
            data = await request.json()  # Get the JSON payload
        except json.JSONDecodeError as e:
            self.helper.connector_logger.error(
                "Invalid JSON payload", {"cause": str(e)}
            )
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid JSON payload"},
            )
        try:
            self._data_handler(data)
        except Exception as e:
            self.helper.connector_logger.error(
                "Error processing message", {"cause": str(e)}
            )
            return JSONResponse(
                status_code=500,
                content={"error": "Error processing message"},
            )
        # all good
        return JSONResponse(
            status_code=202, content={"message": "Message successfully received"}
        )

    def run(self) -> None:
        """Execute the message listening thread.

        Starts the appropriate listener based on the configured protocol:
        - AMQP: Connects to RabbitMQ and consumes messages from the queue
        - API: Starts a FastAPI/Uvicorn HTTP server to receive messages

        The thread runs until stopped via the stop() method or an error occurs.

        :raises ValueError: If an unsupported listen protocol is configured
        """
        if self.listen_protocol == "AMQP":
            self.helper.connector_logger.info("Starting ListenQueue thread")
            while not self.exit_event.is_set():
                try:
                    self.helper.connector_logger.info(
                        "ListenQueue connecting to RabbitMQ."
                    )
                    # Connect the broker
                    self.pika_credentials = pika.PlainCredentials(
                        self.user, self.password
                    )
                    self.pika_parameters = pika.ConnectionParameters(
                        heartbeat=10,
                        blocked_connection_timeout=30,
                        host=self.host,
                        port=self.port,
                        virtual_host=self.vhost,
                        credentials=self.pika_credentials,
                        ssl_options=(
                            pika.SSLOptions(
                                create_mq_ssl_context(self.config), self.host
                            )
                            if self.use_ssl
                            else None
                        ),
                    )
                    self.pika_connection = pika.BlockingConnection(self.pika_parameters)
                    self.channel = self.pika_connection.channel()
                    try:
                        # confirm_delivery is only for cluster mode RabbitMQ
                        # when not in cluster mode this line raise an exception
                        self.channel.confirm_delivery()
                    except Exception as err:  # pylint: disable=broad-except
                        self.helper.connector_logger.debug(str(err))
                    self.channel.basic_qos(prefetch_count=1)
                    assert self.channel is not None
                    self.channel.basic_consume(
                        queue=self.queue_name, on_message_callback=self._process_message
                    )
                    self.channel.start_consuming()
                except Exception as err:  # pylint: disable=broad-except
                    try:
                        self.pika_connection.close()
                    except Exception as errInException:
                        self.helper.connector_logger.debug(
                            type(errInException).__name__,
                            {"reason": str(errInException)},
                        )
                    self.helper.connector_logger.error(
                        type(err).__name__, {"reason": str(err)}
                    )
                    # Wait some time and then retry ListenQueue again.
                    time.sleep(10)
        elif self.listen_protocol == "API":
            self.helper.connector_logger.info("Starting Listen HTTP thread")
            app.add_api_route(
                self.listen_protocol_api_path,
                self._http_process_callback,
                methods=["POST"],
            )
            config = uvicorn.Config(
                app,
                host="0.0.0.0",
                port=self.listen_protocol_api_port,
                reload=False,
                log_config=None,
                log_level=None,
            )
            config.load()  # Manually calling the .load() to trigger needed actions outside HTTPS
            if self.listen_protocol_api_ssl:
                ssl_ctx = create_callback_ssl_context(self.config)
                config.ssl = ssl_ctx
            server = uvicorn.Server(config)
            server.run()

        else:
            raise ValueError("Unsupported listen protocol type")

    def stop(self):
        """Stop the ListenQueue thread and close connections.

        This method sets the exit event, closes the RabbitMQ connection,
        and waits for the processing thread to complete.
        """
        self.helper.connector_logger.info("Preparing ListenQueue for clean shutdown")
        self.exit_event.set()
        self.pika_connection.close()
        if self.thread:
            self.thread.join()


class PingAlive(threading.Thread):
    """Daemon thread that maintains connector heartbeat with OpenCTI platform.

    Periodically pings the OpenCTI API to indicate the connector is alive
    and synchronizes connector state between local and remote instances.

    :param connector_logger: Logger instance for the connector
    :type connector_logger: logging.Logger
    :param connector_id: Unique identifier of the connector
    :type connector_id: str
    :param api: OpenCTI API client instance
    :type api: OpenCTIApiClient
    :param get_state: Function to retrieve current connector state
    :type get_state: Callable[[], Optional[Dict]]
    :param set_state: Function to update connector state
    :type set_state: Callable[[str], None]
    :param metric: Metric handler for recording ping statistics
    :type metric: OpenCTIMetricHandler
    :param connector_info: ConnectorInfo instance with runtime details
    :type connector_info: ConnectorInfo
    """

    def __init__(
        self,
        connector_logger,
        connector_id: str,
        api,
        get_state: Callable[[], Optional[Dict]],
        set_state: Callable[[str], None],
        metric,
        connector_info,
    ) -> None:
        """Initialize the PingAlive daemon thread.

        :param connector_logger: Logger instance for the connector
        :type connector_logger: logging.Logger
        :param connector_id: Unique identifier of the connector
        :type connector_id: str
        :param api: OpenCTI API client instance
        :type api: OpenCTIApiClient
        :param get_state: Function to retrieve current connector state
        :type get_state: Callable[[], Optional[Dict]]
        :param set_state: Function to update connector state
        :type set_state: Callable[[str], None]
        :param metric: Metric handler for recording ping statistics
        :type metric: OpenCTIMetricHandler
        :param connector_info: ConnectorInfo instance with runtime details
        :type connector_info: ConnectorInfo
        """
        threading.Thread.__init__(self, daemon=True)
        self.connector_logger = connector_logger
        self.connector_id = connector_id
        self.in_error = False
        self.api = api
        self.get_state = get_state
        self.set_state = set_state
        self.exit_event = threading.Event()
        self.metric = metric
        self.connector_info = connector_info

    def ping(self) -> None:
        """Execute the ping loop to maintain connector heartbeat.

        Continuously pings the OpenCTI API every 40 seconds to:
        - Signal that the connector is alive
        - Send current connector state and info
        - Receive and apply any remote state updates

        If the remote state differs from local state, the local state
        is updated to match. This allows state resets from the UI.

        The loop continues until the exit_event is set.
        """
        while not self.exit_event.is_set():
            try:
                self.connector_logger.debug("PingAlive running.")
                initial_state = self.get_state()
                connector_info = self.connector_info.all_details
                self.connector_logger.debug(
                    "PingAlive ConnectorInfo", {"connector_info": connector_info}
                )
                result = self.api.connector.ping(
                    self.connector_id, initial_state, connector_info
                )
                remote_state = (
                    json.loads(result["connector_state"])
                    if result["connector_state"] is not None
                    and len(result["connector_state"]) > 0
                    else None
                )
                if initial_state != remote_state:
                    self.set_state(result["connector_state"])
                    self.connector_logger.info(
                        "Connector state has been remotely reset",
                        {"state": self.get_state()},
                    )

                if self.in_error:
                    self.in_error = False
                    self.connector_logger.info("API Ping back to normal")
                self.metric.inc("ping_api_count")
            except Exception as e:  # pylint: disable=broad-except
                self.in_error = True
                self.metric.inc("ping_api_error")
                self.connector_logger.error("Error pinging the API", {"reason": str(e)})
            self.exit_event.wait(40)

    def run(self) -> None:
        """Start the PingAlive thread execution.

        Entry point for the thread that initiates the ping loop.
        """
        self.connector_logger.info("Starting PingAlive thread")
        self.ping()

    def stop(self) -> None:
        """Stop the PingAlive thread gracefully.

        Sets the exit event to signal the ping loop to terminate.
        """
        self.connector_logger.info("Preparing PingAlive for clean shutdown")
        self.exit_event.set()


class StreamAlive(threading.Thread):
    """Watchdog thread that monitors SSE stream health via heartbeat messages.

    Monitors a queue for heartbeat signals from the stream listener.
    If no heartbeat is received within 45 seconds, the connector is
    stopped to allow for reconnection.

    :param helper: The OpenCTIConnectorHelper instance
    :type helper: OpenCTIConnectorHelper
    :param q: Queue for receiving heartbeat signals from stream listener
    :type q: Queue
    """

    def __init__(self, helper, q: Queue) -> None:
        """Initialize the StreamAlive watchdog thread.

        :param helper: The OpenCTIConnectorHelper instance
        :type helper: OpenCTIConnectorHelper
        :param q: Queue for receiving heartbeat signals
        :type q: Queue
        """
        threading.Thread.__init__(self)
        self.helper = helper
        self.q = q
        self.exit_event = threading.Event()

    def run(self) -> None:
        """Execute the stream health monitoring loop.

        Checks every 5 seconds for heartbeat signals in the queue.
        If no signal is received for 45 seconds, terminates the connector
        to trigger a reconnection.
        """
        try:
            self.helper.connector_logger.info("Starting StreamAlive thread")
            time_since_last_heartbeat = 0
            while not self.exit_event.is_set():
                time.sleep(5)
                self.helper.connector_logger.debug("StreamAlive running")
                try:
                    self.q.get(block=False)
                    time_since_last_heartbeat = 0
                except queue.Empty:
                    time_since_last_heartbeat = time_since_last_heartbeat + 5
                    if time_since_last_heartbeat > 45:
                        self.helper.connector_logger.error(
                            "Time since last heartbeat exceeded 45s, stopping the connector"
                        )
                        break
            self.helper.connector_logger.info(
                "Exit event in StreamAlive loop, stopping process."
            )
            sys.excepthook(*sys.exc_info())
        except Exception as ex:
            self.helper.connector_logger.error(
                "Error in StreamAlive loop, stopping process.", {"reason": str(ex)}
            )
            sys.excepthook(*sys.exc_info())

    def stop(self) -> None:
        """Stop the StreamAlive watchdog thread gracefully.

        Sets the exit event to signal the monitoring loop to terminate.
        """
        self.helper.connector_logger.info("Preparing StreamAlive for clean shutdown")
        self.exit_event.set()


class ListenStream(threading.Thread):
    """Thread class for consuming events from OpenCTI SSE stream.

    Connects to an OpenCTI event stream and processes events through
    a callback function. Supports recovery from a specific point in time
    and various filtering options.

    :param helper: The OpenCTIConnectorHelper instance
    :type helper: OpenCTIConnectorHelper
    :param callback: Function to call for each stream event
    :type callback: Callable
    :param url: Base URL for the stream endpoint
    :type url: str
    :param token: Authentication token for the stream
    :type token: str
    :param verify_ssl: Whether to verify SSL certificates
    :type verify_ssl: bool
    :param start_timestamp: Timestamp to start reading from (format: "timestamp-0")
    :type start_timestamp: str or None
    :param live_stream_id: ID of the specific stream to connect to
    :type live_stream_id: str or None
    :param listen_delete: Whether to receive delete events
    :type listen_delete: bool
    :param no_dependencies: Whether to exclude dependency objects
    :type no_dependencies: bool
    :param recover_iso_date: ISO date to recover events from
    :type recover_iso_date: str or None
    :param with_inferences: Whether to include inferred relationships
    :type with_inferences: bool
    """

    def __init__(
        self,
        helper,
        callback: Callable,
        url: str,
        token: str,
        verify_ssl: bool,
        start_timestamp: Optional[str],
        live_stream_id: Optional[str],
        listen_delete: bool,
        no_dependencies: bool,
        recover_iso_date: Optional[str],
        with_inferences: bool,
    ) -> None:
        """Initialize the ListenStream thread.

        :param helper: The OpenCTIConnectorHelper instance
        :type helper: OpenCTIConnectorHelper
        :param callback: Function to process stream events
        :type callback: Callable
        :param url: Base URL for the stream endpoint
        :type url: str
        :param token: Authentication token
        :type token: str
        :param verify_ssl: Whether to verify SSL certificates
        :type verify_ssl: bool
        :param start_timestamp: Starting timestamp for stream position
        :type start_timestamp: str or None
        :param live_stream_id: Specific stream ID to connect to
        :type live_stream_id: str or None
        :param listen_delete: Whether to receive delete events
        :type listen_delete: bool
        :param no_dependencies: Whether to exclude dependencies
        :type no_dependencies: bool
        :param recover_iso_date: ISO date for event recovery
        :type recover_iso_date: str or None
        :param with_inferences: Whether to include inferences
        :type with_inferences: bool
        """
        threading.Thread.__init__(self)
        self.helper = helper
        self.callback = callback
        self.url = url
        self.token = token
        self.verify_ssl = verify_ssl
        self.start_timestamp = start_timestamp
        self.live_stream_id = live_stream_id
        self.listen_delete = listen_delete
        self.no_dependencies = no_dependencies
        self.recover_iso_date = recover_iso_date
        self.with_inferences = with_inferences
        self.exit_event = threading.Event()

    def run(self) -> None:  # pylint: disable=too-many-branches
        """Execute the stream listening loop.

        Connects to the OpenCTI SSE stream and processes events:
        - Initializes or restores stream position from connector state
        - Starts a StreamAlive watchdog for health monitoring
        - Processes heartbeat, connected, and data events
        - Updates connector state with latest event ID
        - Calls the callback function for each data event

        The loop continues until stopped or an error occurs.
        """
        try:
            self.helper.connector_logger.info("Starting ListenStream thread")
            current_state = self.helper.get_state()
            start_from = self.start_timestamp
            recover_until = self.recover_iso_date
            if current_state is None:
                # First run, if no timestamp in config, put "0-0"
                if start_from is None:
                    start_from = "0-0"
                # First run, if no recover iso date in config, put today
                if recover_until is None:
                    recover_until = self.helper.date_now_z()
                self.helper.set_state(
                    {"start_from": start_from, "recover_until": recover_until}
                )
            else:
                # Get start_from from state
                # Backward compat
                if "connectorLastEventId" in current_state:
                    start_from = current_state["connectorLastEventId"]
                # Current implem
                else:
                    start_from = current_state["start_from"]
                # Get recover_until from state
                # Backward compat
                if "connectorStartTime" in current_state:
                    recover_until = current_state["connectorStartTime"]
                # Current implem
                else:
                    recover_until = current_state["recover_until"]

            # Start the stream alive watchdog
            q = Queue(maxsize=1)
            stream_alive = StreamAlive(self.helper, q)
            stream_alive.start()
            # Computing args building
            live_stream_url = self.url
            # In case no recover is explicitly set
            if recover_until is not False and recover_until not in [
                "no",
                "none",
                "No",
                "None",
                "false",
                "False",
            ]:
                live_stream_url = live_stream_url + "?recover=" + recover_until
            listen_delete = str(self.listen_delete).lower()
            no_dependencies = str(self.no_dependencies).lower()
            with_inferences = str(self.with_inferences).lower()
            self.helper.connector_logger.info(
                "Starting to listen stream events",
                {
                    "live_stream_url": live_stream_url,
                    "listen_delete": listen_delete,
                    "no_dependencies": no_dependencies,
                    "with_inferences": with_inferences,
                },
            )
            messages = SSEClient(
                live_stream_url,
                start_from,
                headers={
                    "authorization": "Bearer " + self.token,
                    "listen-delete": listen_delete,
                    "no-dependencies": no_dependencies,
                    "with-inferences": with_inferences,
                },
                verify=self.verify_ssl,
            )
            # Iter on stream messages
            for msg in messages:
                if self.exit_event.is_set():
                    stream_alive.stop()
                    break
                if msg.id is not None:
                    try:
                        q.put(msg.event, block=False)
                    except queue.Full:
                        pass
                    if msg.event == "heartbeat" or msg.event == "connected":
                        state = self.helper.get_state()
                        # state can be None if reset from the UI
                        # In this case, default parameters will be used but SSE Client needs to be restarted
                        if state is None:
                            self.exit_event.set()
                        else:
                            state["start_from"] = str(msg.id)
                            self.helper.set_state(state)
                    else:
                        self.callback(msg)
                        state = self.helper.get_state()
                        # state can be None if reset from the UI
                        # In this case, default parameters will be used but SSE Client needs to be restarted
                        if state is None:
                            self.exit_event.set()
                        else:
                            state["start_from"] = str(msg.id)
                            self.helper.set_state(state)
        except Exception as ex:
            self.helper.connector_logger.error(
                "Error in ListenStream loop, exit.", {"reason": str(ex)}
            )
            sys.excepthook(*sys.exc_info())

    def stop(self):
        """Stop the ListenStream thread.

        This method sets the exit event to signal the stream listening thread to stop.
        """
        self.helper.connector_logger.info("Preparing ListenStream for clean shutdown")
        self.exit_event.set()


class ConnectorInfo:
    """Container for connector runtime information and status.

    Stores runtime metrics and status information about the connector,
    which is sent to the OpenCTI platform during ping operations.

    :param run_and_terminate: Whether connector runs once and terminates
    :type run_and_terminate: bool
    :param buffering: Whether connector is currently buffering due to queue limits
    :type buffering: bool
    :param queue_threshold: Maximum allowed queue size in MB before buffering
    :type queue_threshold: float
    :param queue_messages_size: Current size of queued messages in MB
    :type queue_messages_size: float
    :param next_run_datetime: Scheduled datetime for next connector run
    :type next_run_datetime: datetime or None
    :param last_run_datetime: Datetime of the last connector run
    :type last_run_datetime: datetime or None

    Example:
        >>> info = ConnectorInfo(run_and_terminate=False, queue_threshold=500.0)
        >>> info.buffering = True
        >>> info.queue_messages_size = 450.0
        >>> details = info.all_details
    """

    def __init__(
        self,
        run_and_terminate: bool = False,
        buffering: bool = False,
        queue_threshold: float = 500.0,
        queue_messages_size: float = 0.0,
        next_run_datetime: datetime = None,
        last_run_datetime: datetime = None,
    ):
        """Initialize ConnectorInfo with runtime parameters.

        :param run_and_terminate: Whether connector runs once and terminates
        :type run_and_terminate: bool
        :param buffering: Whether connector is buffering
        :type buffering: bool
        :param queue_threshold: Maximum queue size in MB
        :type queue_threshold: float
        :param queue_messages_size: Current queue size in MB
        :type queue_messages_size: float
        :param next_run_datetime: Next scheduled run time
        :type next_run_datetime: datetime or None
        :param last_run_datetime: Last run time
        :type last_run_datetime: datetime or None
        """
        self._run_and_terminate = run_and_terminate
        self._buffering = buffering
        self._queue_threshold = queue_threshold
        self._queue_messages_size = queue_messages_size
        self._next_run_datetime = next_run_datetime
        self._last_run_datetime = last_run_datetime

    @property
    def all_details(self):
        """Get all connector information details as a dictionary.

        :return: Dictionary containing all connector status information
        :rtype: dict
        """
        return {
            "run_and_terminate": self._run_and_terminate,
            "buffering": self._buffering,
            "queue_threshold": self._queue_threshold,
            "queue_messages_size": self._queue_messages_size,
            "next_run_datetime": self._next_run_datetime,
            "last_run_datetime": self._last_run_datetime,
        }

    @property
    def run_and_terminate(self) -> bool:
        """Get the run_and_terminate flag.

        :return: Whether the connector runs once and terminates
        :rtype: bool
        """
        return self._run_and_terminate

    @run_and_terminate.setter
    def run_and_terminate(self, value: bool) -> None:
        """Set the run_and_terminate flag.

        :param value: Whether the connector should run once and terminate
        :type value: bool
        """
        self._run_and_terminate = value

    @property
    def buffering(self) -> bool:
        """Get the buffering status.

        :return: Whether the connector is currently buffering
        :rtype: bool
        """
        return self._buffering

    @buffering.setter
    def buffering(self, value: bool) -> None:
        """Set the buffering status.

        :param value: Whether the connector is currently buffering
        :type value: bool
        """
        self._buffering = value

    @property
    def queue_threshold(self) -> float:
        """Get the queue threshold value.

        :return: Maximum allowed queue size in MB
        :rtype: float
        """
        return self._queue_threshold

    @queue_threshold.setter
    def queue_threshold(self, value: float) -> None:
        """Set the queue threshold value.

        :param value: The queue size threshold in MB
        :type value: float
        """
        self._queue_threshold = value

    @property
    def queue_messages_size(self) -> float:
        """Get the current queue messages size.

        :return: Current size of queued messages in MB
        :rtype: float
        """
        return self._queue_messages_size

    @queue_messages_size.setter
    def queue_messages_size(self, value: float) -> None:
        """Set the current queue messages size.

        :param value: The current size of messages in the queue in MB
        :type value: float
        """
        self._queue_messages_size = value

    @property
    def next_run_datetime(self) -> datetime:
        """Get the next scheduled run datetime.

        :return: Datetime for the next scheduled run, or None if not scheduled
        :rtype: datetime or None
        """
        return self._next_run_datetime

    @next_run_datetime.setter
    def next_run_datetime(self, value: datetime) -> None:
        """Set the next scheduled run datetime.

        :param value: The datetime for the next scheduled run
        :type value: datetime
        """
        self._next_run_datetime = value

    @property
    def last_run_datetime(self) -> datetime:
        """Get the last run datetime.

        :return: Datetime of the last connector run, or None if never run
        :rtype: datetime or None
        """
        return self._last_run_datetime

    @last_run_datetime.setter
    def last_run_datetime(self, value: datetime) -> None:
        """Set the last run datetime.

        :param value: The datetime of the last run
        :type value: datetime
        """
        self._last_run_datetime = value


class OpenCTIConnectorHelper:  # pylint: disable=too-many-public-methods
    """Main helper class for developing OpenCTI connectors.

    Provides a comprehensive API for connector development, handling:
    - Connector registration and configuration
    - Message queue communication (RabbitMQ/API)
    - SSE stream consumption
    - STIX2 bundle creation and submission
    - Scheduling and lifecycle management
    - Metrics and logging

    :param config: Configuration dictionary containing OpenCTI and connector settings
    :type config: Dict
    :param playbook_compatible: Whether the connector can be used in playbooks
    :type playbook_compatible: bool

    Example:
        >>> config = {
        ...     "opencti": {"url": "http://localhost:8080", "token": "xxx"},
        ...     "connector": {"id": "xxx", "name": "My Connector", "type": "EXTERNAL_IMPORT"}
        ... }
        >>> helper = OpenCTIConnectorHelper(config)
        >>> helper.listen(my_callback_function)

    Attributes:
        api: OpenCTI API client for connector operations
        api_impersonate: API client that impersonates the request applicant
        connector_logger: Logger instance for connector messages
        connector_info: Runtime information about the connector
        metric: Prometheus metric handler
    """

    class TimeUnit(Enum):
        """Time unit enumeration for scheduling intervals (deprecated).

        Use ISO 8601 duration format with schedule_iso() instead.

        :cvar SECONDS: 1 second
        :cvar MINUTES: 60 seconds
        :cvar HOURS: 3600 seconds
        :cvar DAYS: 86400 seconds
        :cvar WEEKS: 604800 seconds
        :cvar YEARS: 31536000 seconds
        """

        SECONDS = 1
        MINUTES = 60
        HOURS = 3600
        DAYS = 86400
        WEEKS = 604800
        YEARS = 31536000

    def __init__(self, config: Dict, playbook_compatible: bool = False) -> None:
        """Initialize the OpenCTIConnectorHelper.

        :param config: Configuration dictionary with OpenCTI and connector settings
        :type config: Dict
        :param playbook_compatible: Whether the connector can be used in playbooks
        :type playbook_compatible: bool
        """
        sys.excepthook = killProgramHook

        # Cache
        self.stream_collections = {}

        # Load API config
        self.config = config
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.opencti_custom_headers = get_config_variable(
            "OPENCTI_CUSTOM_HEADERS",
            ["opencti", "custom_headers"],
            config,
            default=None,
        )
        self.opencti_ssl_verify = get_config_variable(
            "OPENCTI_SSL_VERIFY", ["opencti", "ssl_verify"], config, False, False
        )
        self.opencti_json_logging = get_config_variable(
            "OPENCTI_JSON_LOGGING", ["opencti", "json_logging"], config, False, True
        )
        # Load connector config
        self.connect_id = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], config
        )
        self.connect_auto_create_service_account = get_config_variable(
            "CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT",
            ["connector", "auto_create_service_account"],
            config,
            default=False,
        )
        self.connect_auto_create_service_account_confidence_level = get_config_variable(
            "CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT_CONFIDENCE_LEVEL",
            ["connector", "auto_create_service_account_confidence_level"],
            config,
            default=50,
            isNumber=True,
        )
        self.listen_protocol = get_config_variable(
            "CONNECTOR_LISTEN_PROTOCOL",
            ["connector", "listen_protocol"],
            config,
            default="AMQP",
        ).upper()
        self.listen_protocol_api_port = get_config_variable(
            "CONNECTOR_LISTEN_PROTOCOL_API_PORT",
            ["connector", "listen_protocol_api_port"],
            config,
            default=7070,
        )
        self.listen_protocol_api_path = get_config_variable(
            "CONNECTOR_LISTEN_PROTOCOL_API_PATH",
            ["connector", "listen_protocol_api_path"],
            config,
            default="/api/callback",
        )
        self.listen_protocol_api_ssl = get_config_variable(
            "CONNECTOR_LISTEN_PROTOCOL_API_SSL",
            ["connector", "listen_protocol_api_ssl"],
            config,
            default=False,
        )
        self.listen_protocol_api_uri = get_config_variable(
            "CONNECTOR_LISTEN_PROTOCOL_API_URI",
            ["connector", "listen_protocol_api_uri"],
            config,
            default=(
                "https://127.0.0.1:7070"
                if self.listen_protocol_api_ssl
                else "http://127.0.0.1:7070"
            ),
        )
        self.connect_type = get_config_variable(
            "CONNECTOR_TYPE", ["connector", "type"], config
        )
        self.connect_queue_threshold = get_config_variable(
            "CONNECTOR_QUEUE_THRESHOLD",
            ["connector", "queue_threshold"],
            config,
            default=500,  # Mo
        )
        self.connect_duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], config
        )
        self.connect_live_stream_id = get_config_variable(
            "CONNECTOR_LIVE_STREAM_ID",
            ["connector", "live_stream_id"],
            config,
        )
        self.connect_live_stream_listen_delete = get_config_variable(
            "CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
            ["connector", "live_stream_listen_delete"],
            config,
            default=True,
        )
        self.connect_live_stream_no_dependencies = get_config_variable(
            "CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
            ["connector", "live_stream_no_dependencies"],
            config,
            default=True,
        )
        self.connect_live_stream_with_inferences = get_config_variable(
            "CONNECTOR_LIVE_STREAM_WITH_INFERENCES",
            ["connector", "live_stream_with_inferences"],
            config,
            default=False,
        )
        self.connect_live_stream_recover_iso_date = get_config_variable(
            "CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE",
            ["connector", "live_stream_recover_iso_date"],
            config,
        )
        self.connect_live_stream_start_timestamp = get_config_variable(
            "CONNECTOR_LIVE_STREAM_START_TIMESTAMP",
            ["connector", "live_stream_start_timestamp"],
            config,
        )
        self.connect_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config
        )
        self.connect_confidence_level = None  # Deprecated since OpenCTI version >= 6.0
        self.connect_scope = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], config, default="not-applicable"
        )
        self.connect_auto = get_config_variable(
            "CONNECTOR_AUTO", ["connector", "auto"], config, default=False
        )
        self.connect_auto_update = get_config_variable(
            "CONNECTOR_AUTO_UPDATE", ["connector", "auto_update"], config, default=False
        )
        self.connect_enrichment_resolution = get_config_variable(
            "CONNECTOR_ENRICHMENT_RESOLUTION",
            ["connector", "enrichment_resolution"],
            config,
            default="none",
        )
        self.bundle_send_to_queue = get_config_variable(
            "CONNECTOR_SEND_TO_QUEUE",
            ["connector", "send_to_queue"],
            config,
            default=True,
        )
        self.bundle_send_to_directory = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY",
            ["connector", "send_to_directory"],
            config,
            default=False,
        )
        self.bundle_send_to_directory_path = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY_PATH",
            ["connector", "send_to_directory_path"],
            config,
        )
        self.bundle_send_to_directory_retention = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY_RETENTION",
            ["connector", "send_to_directory_retention"],
            config,
            isNumber=True,
            default=7,
        )
        # S3 send mode configuration
        self.bundle_send_to_s3 = get_config_variable(
            "CONNECTOR_SEND_TO_S3",
            ["connector", "send_to_s3"],
            config,
            default=False,
        )
        self.bundle_send_to_s3_bucket = get_config_variable(
            "CONNECTOR_SEND_TO_S3_BUCKET",
            ["connector", "send_to_s3_bucket"],
            config,
        )
        self.bundle_send_to_s3_folder = get_config_variable(
            "CONNECTOR_SEND_TO_S3_FOLDER",
            ["connector", "send_to_s3_folder"],
            config,
            default="connectors",
        )
        self.bundle_send_to_s3_retention = get_config_variable(
            "CONNECTOR_SEND_TO_S3_RETENTION",
            ["connector", "send_to_s3_retention"],
            config,
            isNumber=True,
            default=7,
        )
        # Cached S3 client for reuse across uploads (lazily initialized)
        self._s3_client = None
        # Override S3 connection (optional - defaults to OpenCTI's S3)
        self.s3_endpoint = get_config_variable(
            "S3_ENDPOINT", ["s3", "endpoint"], config
        )
        self.s3_port = get_config_variable(
            "S3_PORT", ["s3", "port"], config, isNumber=True
        )
        self.s3_access_key = get_config_variable(
            "S3_ACCESS_KEY", ["s3", "access_key"], config
        )
        self.s3_secret_key = get_config_variable(
            "S3_SECRET_KEY", ["s3", "secret_key"], config
        )
        self.s3_use_ssl = get_config_variable("S3_USE_SSL", ["s3", "use_ssl"], config)
        self.s3_bucket_region = get_config_variable(
            "S3_BUCKET_REGION", ["s3", "bucket_region"], config
        )
        self.connect_only_contextual = get_config_variable(
            "CONNECTOR_ONLY_CONTEXTUAL",
            ["connector", "only_contextual"],
            config,
            default=False,
        )
        self.log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="ERROR"
        ).upper()
        self.connect_run_and_terminate = get_config_variable(
            "CONNECTOR_RUN_AND_TERMINATE",
            ["connector", "run_and_terminate"],
            config,
            default=False,
        )
        self.connect_validate_before_import = get_config_variable(
            "CONNECTOR_VALIDATE_BEFORE_IMPORT",
            ["connector", "validate_before_import"],
            config,
            default=False,
        )
        self.scheduler = sched.scheduler(time.time, time.sleep)
        # Start up the server to expose the metrics.
        expose_metrics = get_config_variable(
            "CONNECTOR_EXPOSE_METRICS",
            ["connector", "expose_metrics"],
            config,
            default=False,
        )
        metrics_namespace = get_config_variable(
            "CONNECTOR_METRICS_NAMESPACE",
            ["connector", "metrics_namespace"],
            config,
            False,
            "",
        )
        metrics_subsystem = get_config_variable(
            "CONNECTOR_METRICS_SUBSYSTEM",
            ["connector", "metrics_subsystem"],
            config,
            False,
            "",
        )
        metrics_port = get_config_variable(
            "CONNECTOR_METRICS_PORT",
            ["connector", "metrics_port"],
            config,
            isNumber=True,
            default=9095,
        )
        # Initialize ConnectorInfo instance
        self.connector_info = ConnectorInfo()
        # Initialize configuration

        # If auto create service account
        if self.connect_auto_create_service_account:
            temp_api = OpenCTIApiClient(
                self.opencti_url,
                self.opencti_token,
                self.log_level,
                self.opencti_ssl_verify,
                json_logging=self.opencti_json_logging,
                custom_headers=self.opencti_custom_headers,
                bundle_send_to_queue=self.bundle_send_to_queue,
            )
            # Resolve connectors group
            groups = temp_api.group.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": ["Connectors"]}],
                    "filterGroups": [],
                }
            )
            if len(groups) > 0:
                user_email = normalize_email_prefix(
                    self.connect_name.lower() + "@connector.octi.filigran.io"
                )
                # Resolve user
                user = temp_api.user.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "user_email", "values": [user_email]}],
                        "filterGroups": [],
                    },
                    include_token=True,
                )
                if user is None:
                    user = temp_api.user.create(
                        name="[C] " + self.connect_name,
                        user_email=user_email,
                        user_confidence_level={
                            "max_confidence": self.connect_auto_create_service_account_confidence_level,
                            "overrides": [],
                        },
                        groups=[groups[0]["id"]],
                        include_token=True,
                        user_service_account=True,
                    )
                if user is not None:
                    self.opencti_token = user["api_token"]

        # - Classic API that will be directly attached to the connector rights
        self.api = OpenCTIApiClient(
            self.opencti_url,
            self.opencti_token,
            self.log_level,
            self.opencti_ssl_verify,
            json_logging=self.opencti_json_logging,
            custom_headers=self.opencti_custom_headers,
            bundle_send_to_queue=self.bundle_send_to_queue,
        )
        # - Impersonate API that will use applicant id
        # Behave like standard api if applicant not found
        self.api_impersonate = OpenCTIApiClient(
            self.opencti_url,
            self.opencti_token,
            self.log_level,
            self.opencti_ssl_verify,
            json_logging=self.opencti_json_logging,
            custom_headers=self.opencti_custom_headers,
            bundle_send_to_queue=self.bundle_send_to_queue,
        )
        self.connector_logger = self.api.logger_class(self.connect_name)
        # For retro compatibility
        self.log_debug = self.connector_logger.debug
        self.log_info = self.connector_logger.info
        self.log_warning = self.connector_logger.warning
        self.log_error = self.connector_logger.error
        # For retro compatibility

        self.metric = OpenCTIMetricHandler(
            self.connector_logger,
            expose_metrics,
            metrics_namespace,
            metrics_subsystem,
            metrics_port,
        )
        # Register the connector in OpenCTI
        self.connector = OpenCTIConnector(
            connector_id=self.connect_id,
            connector_name=self.connect_name,
            connector_type=self.connect_type,
            scope=self.connect_scope,
            auto=self.connect_auto,
            only_contextual=self.connect_only_contextual,
            playbook_compatible=playbook_compatible,
            auto_update=self.connect_auto_update,
            enrichment_resolution=self.connect_enrichment_resolution,
            listen_callback_uri=(
                self.listen_protocol_api_uri + self.listen_protocol_api_path
                if self.listen_protocol == "API"
                else None
            ),
        )
        connector_configuration = self.api.connector.register(self.connector)
        self.connector_logger.info(
            "Connector registered with ID", {"id": self.connect_id}
        )
        self.work_id = None
        self.validation_mode = "workbench"
        self.force_validation = False
        self.draft_id = None
        self.playbook = None
        self.enrichment_shared_organizations = None
        self.connector_id = connector_configuration["id"]
        self.applicant_id = connector_configuration["connector_user_id"]
        self.connector_state = connector_configuration["connector_state"]
        self.connector_config = connector_configuration["config"]

        # Configure the push information protocol
        self.queue_protocol = get_config_variable(
            env_var="CONNECTOR_QUEUE_PROTOCOL",
            yaml_path=["connector", "queue_protocol"],
            config=config,
        )
        if not self.queue_protocol:  # for backwards compatibility
            self.queue_protocol = get_config_variable(
                env_var="QUEUE_PROTOCOL",
                yaml_path=["connector", "queue_protocol"],
                config=config,
            )
            if self.queue_protocol:
                self.connector_logger.error(
                    "QUEUE_PROTOCOL is deprecated, please use CONNECTOR_QUEUE_PROTOCOL instead."
                )
        if not self.queue_protocol:
            self.queue_protocol = "amqp"

        # Overwrite connector config for RabbitMQ if given manually / in conf
        self.connector_config["connection"]["host"] = get_config_variable(
            "MQ_HOST",
            ["mq", "host"],
            config,
            default=self.connector_config["connection"]["host"],
        )
        self.connector_config["connection"]["port"] = get_config_variable(
            "MQ_PORT",
            ["mq", "port"],
            config,
            isNumber=True,
            default=self.connector_config["connection"]["port"],
        )
        self.connector_config["connection"]["vhost"] = get_config_variable(
            "MQ_VHOST",
            ["mq", "vhost"],
            config,
            default=self.connector_config["connection"]["vhost"],
        )
        self.connector_config["connection"]["use_ssl"] = get_config_variable(
            "MQ_USE_SSL",
            ["mq", "use_ssl"],
            config,
            default=self.connector_config["connection"]["use_ssl"],
        )
        self.connector_config["connection"]["user"] = get_config_variable(
            "MQ_USER",
            ["mq", "user"],
            config,
            default=self.connector_config["connection"]["user"],
        )
        self.connector_config["connection"]["pass"] = get_config_variable(
            "MQ_PASS",
            ["mq", "pass"],
            config,
            default=self.connector_config["connection"]["pass"],
        )

        # Initialize S3 config from backend, allow local overrides
        if "s3" in self.connector_config:
            self._init_s3_config(self.connector_config["s3"])

        # Start ping thread
        if not self.connect_run_and_terminate:
            is_run_and_terminate = False
            if self.connect_duration_period == 0:
                is_run_and_terminate = True

            if isinstance(self.connect_duration_period, str):
                if self.connect_duration_period == "0":
                    is_run_and_terminate = True
                else:
                    # Calculates and validate the duration period in seconds
                    timedelta_adapter = TypeAdapter(datetime.timedelta)
                    td = timedelta_adapter.validate_python(self.connect_duration_period)
                    duration_period_in_seconds = int(td.total_seconds())

                    if duration_period_in_seconds == 0:
                        is_run_and_terminate = True

            if self.connect_duration_period is None or not is_run_and_terminate:
                self.ping = PingAlive(
                    self.connector_logger,
                    self.connector.id,
                    self.api,
                    self.get_state,
                    self.set_state,
                    self.metric,
                    self.connector_info,
                )
                self.ping.start()

        # self.listen_stream = None
        self.listen_queue = None

    def _init_s3_config(self, backend_s3_config: Dict) -> None:
        """Initialize S3 config using backend values with local overrides.

        Local environment variables or config file settings take precedence
        over backend-provided values. If no local override is provided,
        the backend value is used.

        :param backend_s3_config: S3 configuration from backend registration
        :type backend_s3_config: Dict
        """
        # Use local override if set, otherwise use backend value
        # Use explicit None checks to support falsy values (0, False, empty string) as valid overrides
        self.s3_endpoint = (
            self.s3_endpoint
            if self.s3_endpoint is not None
            else backend_s3_config.get("endpoint")
        )
        self.s3_port = (
            self.s3_port if self.s3_port is not None else backend_s3_config.get("port")
        )
        self.s3_access_key = (
            self.s3_access_key
            if self.s3_access_key is not None
            else backend_s3_config.get("access_key")
        )
        self.s3_secret_key = (
            self.s3_secret_key
            if self.s3_secret_key is not None
            else backend_s3_config.get("secret_key")
        )
        self.s3_use_ssl = (
            self.s3_use_ssl
            if self.s3_use_ssl is not None
            else backend_s3_config.get("use_ssl")
        )
        self.s3_bucket_region = (
            self.s3_bucket_region
            if self.s3_bucket_region is not None
            else backend_s3_config.get("bucket_region")
        )
        # Use OpenCTI bucket by default, unless overridden
        if self.bundle_send_to_s3_bucket is None:
            self.bundle_send_to_s3_bucket = backend_s3_config.get("bucket_name")

    def _get_s3_client(self):
        """Create and return an S3 client configured with current settings.

        :return: Configured boto3 S3 client
        :rtype: boto3.client
        :raises ValueError: If required S3 configuration is missing
        """
        # Validate required S3 configuration
        missing_config = []
        if not self.s3_endpoint:
            missing_config.append("s3_endpoint")
        if not self.s3_port:
            missing_config.append("s3_port")
        if not self.s3_access_key:
            missing_config.append("s3_access_key")
        if not self.s3_secret_key:
            missing_config.append("s3_secret_key")

        if missing_config:
            raise ValueError(
                f"Missing required S3 configuration: {', '.join(missing_config)}. "
                "Ensure S3 credentials are provided via config or OpenCTI backend."
            )

        endpoint_url = (
            f"{'https' if self.s3_use_ssl else 'http'}://"
            f"{self.s3_endpoint}:{self.s3_port}"
        )
        return boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            region_name=self.s3_bucket_region,
            config=BotoConfig(signature_version="s3v4"),
        )

    def _generate_bundle_filename(self) -> str:
        """Generate a unique filename for bundle files.

        :return: Generated filename with connector name, timestamp and .json extension
        :rtype: str
        """
        return (
            self.connect_name.lower().replace(" ", "_")
            + "-"
            + time.strftime("%Y%m%d-%H%M%S-")
            + str(time.time())
            + ".json"
        )

    def _create_message_bundle(
        self, bundle_type: str, bundle: str, entities_types: list, update: bool
    ) -> dict:
        """Create a message bundle structure for directory or S3 export.

        :param bundle_type: Type of bundle (e.g., "DIRECTORY_BUNDLE", "S3_BUNDLE")
        :type bundle_type: str
        :param bundle: JSON string of the STIX bundle
        :type bundle: str
        :param entities_types: List of entity types in the bundle
        :type entities_types: list
        :param update: Whether this is an update operation
        :type update: bool
        :return: Message bundle dictionary
        :rtype: dict
        """
        return {
            "bundle_type": bundle_type,
            "applicant_id": self.applicant_id,
            "connector": {
                "id": self.connect_id,
                "name": self.connect_name,
                "type": self.connect_type,
                "scope": self.connect_scope,
                "auto": self.connect_auto,
                "validate_before_import": self.connect_validate_before_import,
            },
            "entities_types": entities_types,
            "bundle": json.loads(bundle),
            "update": update,
        }

    def _send_bundle_to_s3(self, bundle_content: str, bundle_file: str) -> None:
        """Upload bundle to S3 bucket.

        :param bundle_content: JSON string content of the bundle to upload
        :type bundle_content: str
        :param bundle_file: Filename for the bundle in S3
        :type bundle_file: str
        :raises Exception: If S3 upload fails
        """
        # Validate bucket is configured
        if not self.bundle_send_to_s3_bucket:
            raise ValueError(
                "S3 bucket not configured. Set CONNECTOR_SEND_TO_S3_BUCKET or "
                "ensure OpenCTI backend provides bucket configuration."
            )

        # Lazily create and cache the S3 client for reuse across uploads
        if self._s3_client is None:
            self._s3_client = self._get_s3_client()
        s3_client = self._s3_client

        # If folder is empty or "." (or "/" after stripping), upload to root of bucket
        # Strip trailing slashes to avoid double slashes in S3 keys
        folder = (
            self.bundle_send_to_s3_folder.rstrip("/")
            if self.bundle_send_to_s3_folder
            else None
        )
        if folder and folder != ".":
            key = f"{folder}/{bundle_file}"
        else:
            key = bundle_file

        try:
            s3_client.put_object(
                Bucket=self.bundle_send_to_s3_bucket,
                Key=key,
                Body=bundle_content.encode("utf-8"),
                ContentType="application/json",
            )

            self.connector_logger.info(
                "Bundle uploaded to S3",
                {"bucket": self.bundle_send_to_s3_bucket, "key": key},
            )

            # Handle retention - delete old files
            if self.bundle_send_to_s3_retention > 0:
                self._cleanup_old_s3_bundles(s3_client)
        except Exception as e:
            self.connector_logger.error(
                "Failed to upload bundle to S3",
                {"bucket": self.bundle_send_to_s3_bucket, "key": key, "error": str(e)},
            )
            raise

    def _cleanup_old_s3_bundles(self, s3_client) -> None:
        """Remove expired bundles from S3 based on retention policy.

        Only deletes bundles created by this connector (matching connector name prefix)
        to avoid deleting bundles from other connectors sharing the same folder.

        :param s3_client: Configured boto3 S3 client
        :type s3_client: boto3.client
        """
        # Build prefix: folder + connector name prefix
        # Strip trailing slashes to avoid double slashes in S3 keys
        folder = (
            self.bundle_send_to_s3_folder.rstrip("/")
            if self.bundle_send_to_s3_folder
            else None
        )
        connector_prefix = self.connect_name.lower().replace(" ", "_") + "-"
        if folder and folder != ".":
            prefix = f"{folder}/{connector_prefix}"
        else:
            prefix = connector_prefix

        cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=self.bundle_send_to_s3_retention
        )

        try:
            paginator = s3_client.get_paginator("list_objects_v2")
            paginate_args = {"Bucket": self.bundle_send_to_s3_bucket, "Prefix": prefix}
            for page in paginator.paginate(**paginate_args):
                for obj in page.get("Contents", []):
                    if obj["LastModified"] < cutoff_time:
                        s3_client.delete_object(
                            Bucket=self.bundle_send_to_s3_bucket, Key=obj["Key"]
                        )
                        self.connector_logger.debug(
                            "Deleted expired S3 bundle",
                            {"key": obj["Key"], "modified": str(obj["LastModified"])},
                        )
        except Exception as e:
            self.connector_logger.warning(
                "Failed to cleanup old S3 bundles", {"error": str(e)}
            )

    def stop(self) -> None:
        """Stop the connector and clean up resources.

        This method stops all running threads (listen queue, ping thread) and
        unregisters the connector from OpenCTI.
        """
        self.connector_logger.info("Preparing connector for clean shutdown")
        if self.listen_queue:
            self.listen_queue.stop()
        # if self.listen_stream:
        #     self.listen_stream.stop()
        self.ping.stop()
        self.api.connector.unregister(self.connector_id)

    def get_name(self) -> Optional[Union[bool, int, str]]:
        """Get the connector name.

        :return: The name of the connector
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.connect_name

    def get_stream_collection(self):
        """Get the stream collection configuration.

        :return: Stream collection configuration dictionary
        :rtype: dict
        :raises ValueError: If no stream is connected
        """
        if self.connect_live_stream_id is not None:
            if self.connect_live_stream_id in ["live", "raw"]:
                return {
                    "id": self.connect_live_stream_id,
                    "name": self.connect_live_stream_id,
                    "description": self.connect_live_stream_id,
                    "stream_live": True,
                    "stream_public": False,
                }
            # Get from cache
            elif self.connect_live_stream_id in self.stream_collections:
                return self.stream_collections[self.connect_live_stream_id]
            else:
                query = """
                    query StreamCollection($id: String!) {
                        streamCollection(id: $id)  {
                            id
                            name
                            description
                            stream_live
                            stream_public
                        }
                    }
                """
                result = self.api.query(query, {"id": self.connect_live_stream_id})
                # Put in cache
                self.stream_collections[self.connect_live_stream_id] = result["data"][
                    "streamCollection"
                ]
                return result["data"]["streamCollection"]
        else:
            raise ValueError("This connector is not connected to any stream")

    def get_only_contextual(self) -> Optional[Union[bool, int, str]]:
        """Get the only_contextual configuration value.

        :return: Whether the connector processes only contextual data
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.connect_only_contextual

    def get_run_and_terminate(self) -> Optional[Union[bool, int, str]]:
        """Get the run_and_terminate configuration value.

        :return: Whether the connector should run once and terminate
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.connect_run_and_terminate

    def get_validate_before_import(self) -> Optional[Union[bool, int, str]]:
        """Get the validate_before_import configuration value.

        :return: Whether to validate data before importing
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.connect_validate_before_import

    def set_state(self, state) -> None:
        """Set the connector state.

        Stores the connector state as a JSON string for persistence across runs.
        The state can be retrieved later using get_state().

        :param state: State object to store, or None to clear the state
        :type state: Dict or None
        """
        if isinstance(state, Dict):
            self.connector_state = json.dumps(state)
        else:
            self.connector_state = None

    def get_state(self) -> Optional[Dict]:
        """Get the connector state.

        Retrieves the current connector state that was previously stored.
        The state is used to track progress and resume operations across runs.

        :return: The current state of the connector, or None if no state exists
        :rtype: Optional[Dict]
        """
        try:
            if self.connector_state:
                state = json.loads(self.connector_state)
                if isinstance(state, Dict) and state:
                    return state
        except:  # pylint: disable=bare-except  # noqa: E722
            pass
        return None

    def force_ping(self):
        """Force a ping to the OpenCTI API to update connector state.

        This method manually triggers a ping to synchronize the connector state
        with the OpenCTI platform.
        """
        try:
            initial_state = self.get_state()
            connector_info = self.connector_info.all_details
            self.connector_logger.debug(
                "ForcePing ConnectorInfo", {"connector_info": connector_info}
            )
            result = self.api.connector.ping(
                self.connector_id, initial_state, connector_info
            )
            remote_state = (
                json.loads(result["connector_state"])
                if result["connector_state"] is not None
                and len(result["connector_state"]) > 0
                else None
            )
            if initial_state != remote_state:
                self.api.connector.ping(
                    self.connector_id, initial_state, connector_info
                )
        except Exception as e:  # pylint: disable=broad-except
            self.metric.inc("error_count")
            self.connector_logger.error("Error pinging the API", {"reason": str(e)})

    def next_run_datetime(self, duration_period_in_seconds: Union[int, float]) -> None:
        """Calculate and set the next scheduled run datetime in ISO format.

        :param duration_period_in_seconds: Duration in seconds until next run
        :type duration_period_in_seconds: Union[int, float]
        """
        try:
            duration_timedelta = datetime.timedelta(seconds=duration_period_in_seconds)
            next_datetime = datetime.datetime.utcnow() + duration_timedelta
            # Set next_run_datetime
            self.connector_info.next_run_datetime = next_datetime.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.connector_logger.info(
                "Schedule next run of connector",
                {"next_run_datetime": self.connector_info.next_run_datetime},
            )
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An error occurred while calculating the next run in datetime",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def last_run_datetime(self) -> None:
        """Set the last run datetime to the current UTC time in ISO format."""
        try:
            current_datetime = datetime.datetime.utcnow()
            # Set last_run_datetime
            self.connector_info.last_run_datetime = current_datetime.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An error occurred while converting the last run in datetime",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def check_connector_buffering(self) -> bool:
        """Check if the RabbitMQ queue has exceeded the allowed threshold.

        :return: True if queue size exceeds threshold, False otherwise
        :rtype: bool
        """
        try:
            connector_details = self.api.connector.read(connector_id=self.connector_id)

            if connector_details and connector_details.get("id") is not None:
                connector_queue_id = connector_details["id"]
                connector_queue_details = connector_details["connector_queue_details"]

                queue_messages_size_byte = connector_queue_details["messages_size"]
                queue_threshold = float(self.connect_queue_threshold)

                # Convert queue_messages_size to MB (decimal)
                queue_messages_size_mo = queue_messages_size_byte / 1000000

                self.connector_logger.debug(
                    "Connector queue details",
                    {
                        "connector_queue_id": connector_queue_id,
                        "queue_threshold": queue_threshold,
                        "messages_number": connector_queue_details["messages_number"],
                        "queue_messages_size": queue_messages_size_mo,
                    },
                )

                # Set the connector info
                self.connector_info.queue_messages_size = queue_messages_size_mo
                self.connector_info.queue_threshold = queue_threshold

                if queue_messages_size_mo < queue_threshold:
                    # Set buffering
                    self.connector_info.buffering = False
                    return False
                else:
                    self.connector_logger.info(
                        "Connector will not run until the queue messages size is reduced under queue threshold"
                    )
                    # Set buffering
                    self.connector_info.buffering = True
                    return True

            else:
                self.metric.inc("error_count")
                self.connector_logger.error(
                    "An error occurred while retrieving connector details"
                )
                sys.excepthook(*sys.exc_info())
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An error occurred while checking the queue size",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def schedule_unit(
        self,
        message_callback: Callable[[], None],
        duration_period: Union[int, float, str],
        time_unit: TimeUnit,
    ) -> None:
        """Schedule connector execution with a time unit (deprecated).

        This method manages backward compatibility of intervals on connectors.
        Use schedule_iso method instead.

        :param message_callback: The connector process callback function
        :type message_callback: Callable[[], None]
        :param duration_period: The connector interval value
        :type duration_period: Union[int, float, str]
        :param time_unit: The unit of time (YEARS, WEEKS, DAYS, HOURS, MINUTES, SECONDS)
        :type time_unit: TimeUnit
        """
        try:
            # Calculates the duration period in seconds
            time_unit_in_seconds = time_unit.value
            duration_period_in_seconds = float(duration_period) * time_unit_in_seconds

            # Start schedule_process
            self.schedule_process(message_callback, duration_period_in_seconds)

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An unexpected error occurred during schedule_unit",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def schedule_iso(
        self, message_callback: Callable[[], None], duration_period: str
    ) -> None:
        """Schedule connector execution using ISO 8601 duration format.

        :param message_callback: The connector process callback function
        :type message_callback: Callable[[], None]
        :param duration_period: Duration in ISO 8601 format (e.g., "P18Y9W4DT11H9M8S")
        :type duration_period: str
        """
        try:
            if duration_period == "0":
                duration_period_in_seconds = 0
            else:
                # Calculates and validate the duration period in seconds
                timedelta_adapter = TypeAdapter(datetime.timedelta)
                td = timedelta_adapter.validate_python(duration_period)
                duration_period_in_seconds = int(td.total_seconds())

            # Start schedule_process
            self.schedule_process(message_callback, duration_period_in_seconds)

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An unexpected error occurred during schedule_iso",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def _schedule_process(
        self,
        scheduler: sched.scheduler,
        message_callback: Callable[[], None],
        duration_period: Union[int, float],
    ) -> None:
        """Execute scheduled connector process if queue is not buffering.

        The connector process starts only if the queue messages size is less than
        or equal to the queue_threshold variable.

        :param scheduler: Scheduler containing tasks to be started
        :type scheduler: sched.scheduler
        :param message_callback: The connector process callback function
        :type message_callback: Callable[[], None]
        :param duration_period: The connector's interval in seconds
        :type duration_period: Union[int, float]
        """
        try:
            self.connector_logger.info("Starting schedule")
            check_connector_buffering = self.check_connector_buffering()

            if not check_connector_buffering:
                # Start running the connector
                message_callback()
                # Lets you know what is the last run of the connector datetime
                self.last_run_datetime()

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An error occurred while checking the queue size",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

        finally:
            # Lets you know what the next run of the scheduler will be
            self.next_run_datetime(duration_period)
            # Then schedule the next execution
            scheduler.enter(
                duration_period,
                1,
                self._schedule_process,
                (scheduler, message_callback, duration_period),
            )

    def schedule_process(
        self, message_callback: Callable[[], None], duration_period: Union[int, float]
    ) -> None:
        """Schedule the execution of a connector process.

        If duration_period is zero or connect_run_and_terminate is True,
        the process will run once and terminate. Otherwise, it schedules
        the next run based on the interval.

        :param message_callback: The connector process callback function
        :type message_callback: Callable[[], None]
        :param duration_period: The connector's interval in seconds
        :type duration_period: Union[int, float]
        """
        try:
            # In the case where the duration_period_converted is zero, we consider it to be a run and terminate
            if self.connect_run_and_terminate or duration_period == 0:
                self.connector_logger.info("Starting run and terminate")
                # Set run_and_terminate
                self.connector_info.run_and_terminate = True
                check_connector_buffering = self.check_connector_buffering()

                if not check_connector_buffering:
                    # Start running the connector
                    message_callback()

                # Lets you know what is the last run of the connector datetime
                self.last_run_datetime()
                self.connector_logger.info("Closing run and terminate")
                self.force_ping()
                sys.exit(0)
            else:
                # Start running the connector
                message_callback()
                # Set queue_threshold and queue_messages_size for the first run
                self.check_connector_buffering()
                # Lets you know what is the last run of the connector datetime
                self.last_run_datetime()
                # Lets you know what the next run of the scheduler will be
                self.next_run_datetime(duration_period)

                # Then schedule the next execution
                self.scheduler.enter(
                    duration_period,
                    1,
                    self._schedule_process,
                    (self.scheduler, message_callback, duration_period),
                )
                self.scheduler.run()

        except SystemExit:
            self.connector_logger.info("SystemExit caught, stopping the scheduler")
            if self.connect_run_and_terminate:
                self.connector_logger.info("Closing run and terminate")
                self.force_ping()
                sys.exit(0)

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "An unexpected error occurred during schedule",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def listen(
        self,
        message_callback: Callable[[Dict], str],
    ) -> None:
        """Listen for messages from the queue and process them via callback.

        Starts a listener thread that consumes messages from RabbitMQ or HTTP API
        (depending on configured listen protocol) and processes each message
        through the provided callback function. This method blocks until the
        listener is stopped.

        :param message_callback: Function to process incoming messages. Receives
            event data dict and should return a status message string.
        :type message_callback: Callable[[Dict], str]
        """
        self.listen_queue = ListenQueue(
            self,
            self.opencti_token,
            self.config,
            self.connector_config,
            self.applicant_id,
            self.listen_protocol,
            self.listen_protocol_api_ssl,
            self.listen_protocol_api_path,
            self.listen_protocol_api_port,
            message_callback,
        )
        self.listen_queue.start()
        self.listen_queue.join()

    def listen_stream(
        self,
        message_callback: Callable,
        url: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        start_timestamp: Optional[str] = None,
        live_stream_id: Optional[str] = None,
        listen_delete: Optional[bool] = None,
        no_dependencies: Optional[bool] = None,
        recover_iso_date: Optional[str] = None,
        with_inferences: Optional[bool] = None,
    ) -> ListenStream:
        """Start listening to an OpenCTI event stream.

        Connects to an SSE stream and processes events through the callback.
        Parameters default to connector configuration values if not specified.

        :param message_callback: Function to call for each stream event
        :type message_callback: Callable
        :param url: Base URL for stream (defaults to opencti_url)
        :type url: str or None
        :param token: Authentication token (defaults to opencti_token)
        :type token: str or None
        :param verify_ssl: Whether to verify SSL certificates
        :type verify_ssl: bool or None
        :param start_timestamp: Stream position to start from
        :type start_timestamp: str or None
        :param live_stream_id: Specific stream ID to connect to
        :type live_stream_id: str or None
        :param listen_delete: Whether to receive delete events
        :type listen_delete: bool or None
        :param no_dependencies: Whether to exclude dependencies
        :type no_dependencies: bool or None
        :param recover_iso_date: ISO date to recover events from
        :type recover_iso_date: str or None
        :param with_inferences: Whether to include inferred data
        :type with_inferences: bool or None

        :return: The started ListenStream thread
        :rtype: ListenStream
        """
        # URL
        if url is None:
            url = self.opencti_url
        # Token
        if token is None:
            token = self.opencti_token
        # Verify SSL
        if verify_ssl is None:
            verify_ssl = self.opencti_ssl_verify
        # Live Stream ID
        if live_stream_id is None and self.connect_live_stream_id is not None:
            live_stream_id = self.connect_live_stream_id
        # Listen delete
        if listen_delete is None and self.connect_live_stream_listen_delete is not None:
            listen_delete = self.connect_live_stream_listen_delete
        elif listen_delete is None:
            listen_delete = False
        # No deps
        if (
            no_dependencies is None
            and self.connect_live_stream_no_dependencies is not None
        ):
            no_dependencies = self.connect_live_stream_no_dependencies
        elif no_dependencies is None:
            no_dependencies = False
        # With inferences
        if (
            with_inferences is None
            and self.connect_live_stream_with_inferences is not None
        ):
            with_inferences = self.connect_live_stream_with_inferences
        elif with_inferences is None:
            with_inferences = False
        # Start timestamp
        if (
            start_timestamp is None
            and self.connect_live_stream_start_timestamp is not None
        ):
            start_timestamp = str(self.connect_live_stream_start_timestamp) + "-0"
        elif start_timestamp is not None:
            start_timestamp = str(start_timestamp) + "-0"
        # Recover ISO date
        if (
            recover_iso_date is None
            and self.connect_live_stream_recover_iso_date is not None
        ):
            recover_iso_date = self.connect_live_stream_recover_iso_date
        # Generate the stream URL
        url = url + "/stream"
        if live_stream_id is not None:
            url = url + "/" + live_stream_id
        self.listen_stream = ListenStream(
            self,
            message_callback,
            url,
            token,
            verify_ssl,
            start_timestamp,
            live_stream_id,
            listen_delete,
            no_dependencies,
            recover_iso_date,
            with_inferences,
        )
        self.listen_stream.start()
        return self.listen_stream

    def get_opencti_url(self) -> Optional[Union[bool, int, str]]:
        """Get the OpenCTI URL.

        :return: The URL of the OpenCTI platform
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.opencti_url

    def get_opencti_token(self) -> Optional[Union[bool, int, str]]:
        """Get the OpenCTI API token.

        :return: The API token for OpenCTI authentication
        :rtype: Optional[Union[bool, int, str]]
        """
        return self.opencti_token

    def get_connector(self) -> OpenCTIConnector:
        """Get the OpenCTIConnector instance.

        :return: The OpenCTIConnector instance
        :rtype: OpenCTIConnector
        """
        return self.connector

    def date_now(self) -> str:
        """Get the current UTC datetime in ISO 8601 format.

        Returns the current time with timezone offset notation (+00:00).

        :return: Current UTC datetime as ISO 8601 string (e.g., "2024-01-15T10:30:00+00:00")
        :rtype: str

        Example:
            >>> helper.date_now()
            '2024-01-15T10:30:00+00:00'
        """
        return (
            datetime.datetime.utcnow()
            .replace(microsecond=0, tzinfo=datetime.timezone.utc)
            .isoformat()
        )

    def date_now_z(self) -> str:
        """Get the current UTC datetime in ISO 8601 format with Z suffix.

        Returns the current time with 'Z' suffix instead of '+00:00'.
        This format is commonly used in STIX objects.

        :return: Current UTC datetime as ISO 8601 string (e.g., "2024-01-15T10:30:00Z")
        :rtype: str

        Example:
            >>> helper.date_now_z()
            '2024-01-15T10:30:00Z'
        """
        return (
            datetime.datetime.utcnow()
            .replace(microsecond=0, tzinfo=datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    # Push Stix2 helper
    def send_stix2_bundle(self, bundle: str, **kwargs) -> list:
        """Send a STIX2 bundle to the OpenCTI platform.

        Processes and sends a STIX2 bundle to OpenCTI via the message queue or API.
        The bundle is split into smaller chunks and sent with proper sequencing.
        Supports validation workflows, draft mode, and directory export.

        :param bundle: Valid STIX2 bundle as a JSON string
        :type bundle: str
        :param work_id: Work ID for tracking the import job (default: self.work_id)
        :type work_id: str, optional
        :param validation_mode: Validation mode - "workbench" or "draft" (default: self.validation_mode)
        :type validation_mode: str, optional
        :param draft_id: Draft context ID to send the bundle to (default: self.draft_id)
        :type draft_id: str, optional
        :param entities_types: List of entity types to filter (default: None)
        :type entities_types: list, optional
        :param update: Whether to update existing data in the database (default: False)
        :type update: bool, optional
        :param event_version: Event version for the bundle (default: None)
        :type event_version: str, optional
        :param bypass_validation: Skip validation workflow (default: False)
        :type bypass_validation: bool, optional
        :param force_validation: Force validation even if not configured (default: self.force_validation)
        :type force_validation: bool, optional
        :param entity_id: Entity ID for context (default: None)
        :type entity_id: str, optional
        :param file_markings: File markings to apply (default: None)
        :type file_markings: list, optional
        :param file_name: File name for workbench upload (default: None)
        :type file_name: str, optional
        :param send_to_queue: Whether to send to message queue (default: self.bundle_send_to_queue)
        :type send_to_queue: bool, optional
        :param cleanup_inconsistent_bundle: Clean up inconsistent bundle data (default: False)
        :type cleanup_inconsistent_bundle: bool, optional
        :param send_to_directory: Whether to write bundle to directory (default: self.bundle_send_to_directory)
        :type send_to_directory: bool, optional
        :param send_to_directory_path: Directory path for bundle export (default: self.bundle_send_to_directory_path)
        :type send_to_directory_path: str, optional
        :param send_to_directory_retention: Days to retain exported files (default: self.bundle_send_to_directory_retention)
        :type send_to_directory_retention: int, optional
        :param send_to_s3: Whether to upload bundle to S3 (default: self.bundle_send_to_s3)
        :type send_to_s3: bool, optional

        :return: List of processed bundle chunks
        :rtype: list

        :raises ValueError: If the bundle is empty or contains no valid objects
        """
        work_id = kwargs.get("work_id", self.work_id)
        validation_mode = kwargs.get("validation_mode", self.validation_mode)
        draft_id = kwargs.get("draft_id", self.draft_id)
        entities_types = kwargs.get("entities_types", None)
        update = kwargs.get("update", False)
        event_version = kwargs.get("event_version", None)
        bypass_validation = kwargs.get("bypass_validation", False)
        force_validation = kwargs.get("force_validation", self.force_validation)
        entity_id = kwargs.get("entity_id", None)
        file_markings = kwargs.get("file_markings", None)
        file_name = kwargs.get("file_name", None)
        bundle_send_to_queue = kwargs.get("send_to_queue", self.bundle_send_to_queue)
        cleanup_inconsistent_bundle = kwargs.get("cleanup_inconsistent_bundle", False)
        bundle_send_to_directory = kwargs.get(
            "send_to_directory", self.bundle_send_to_directory
        )
        bundle_send_to_directory_path = kwargs.get(
            "send_to_directory_path", self.bundle_send_to_directory_path
        )
        bundle_send_to_directory_retention = kwargs.get(
            "send_to_directory_retention", self.bundle_send_to_directory_retention
        )
        bundle_send_to_s3 = kwargs.get("send_to_s3", self.bundle_send_to_s3)

        # In case of enrichment ingestion, ensure the sharing if needed
        if self.enrichment_shared_organizations is not None:
            # Every element of the bundle must be enriched with the same organizations
            bundle_data = json.loads(bundle)
            for item in bundle_data["objects"]:
                if (
                    "extensions" in item
                    and "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
                    in item["extensions"]
                ):
                    octi_extensions = item["extensions"][
                        "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
                    ]
                    if octi_extensions.get("granted_refs") is not None:
                        octi_extensions["granted_refs"] = list(
                            set(
                                octi_extensions["granted_refs"]
                                + self.enrichment_shared_organizations
                            )
                        )
                    else:
                        octi_extensions["granted_refs"] = (
                            self.enrichment_shared_organizations
                        )
                else:
                    if item.get("x_opencti_granted_refs") is not None:
                        item["x_opencti_granted_refs"] = list(
                            set(
                                item["x_opencti_granted_refs"]
                                + self.enrichment_shared_organizations
                            )
                        )
                    else:
                        item["x_opencti_granted_refs"] = (
                            self.enrichment_shared_organizations
                        )
            bundle = json.dumps(bundle_data)

        # If execution in playbook, callback the api
        if self.playbook is not None:
            self.api.playbook.playbook_step_execution(self.playbook, bundle)
            return [bundle]

        # Upload workbench in case of pending validation
        if not file_name and work_id:
            file_name = f"{work_id}.json"

        if (
            (self.connect_validate_before_import or force_validation)
            and not bypass_validation
            and file_name
        ):
            if validation_mode == "workbench":
                self.api.upload_pending_file(
                    file_name=file_name,
                    data=bundle,
                    mime_type="application/json",
                    entity_id=entity_id,
                    file_markings=file_markings,
                )
                return []
            elif validation_mode == "draft" and not draft_id:
                draft_id = self.api.create_draft(
                    draft_name=file_name, entity_id=entity_id
                )
                if not draft_id:
                    self.connector_logger.error("Draft couldn't be created")
                    return []
                if work_id:
                    self.api.work.add_draft_context(work_id, draft_id)

        # If directory setup, write the bundle to the target directory
        if bundle_send_to_directory and bundle_send_to_directory_path is not None:
            self.connector_logger.info(
                "The connector sending bundle to directory",
                {
                    "connector": self.connect_name,
                    "directory": bundle_send_to_directory_path,
                    "also_queuing": bundle_send_to_queue,
                },
            )
            bundle_file = self._generate_bundle_filename()
            write_file = os.path.join(
                bundle_send_to_directory_path, bundle_file + ".tmp"
            )
            message_bundle = self._create_message_bundle(
                "DIRECTORY_BUNDLE", bundle, entities_types, update
            )
            # Maintains the list of files under control
            if bundle_send_to_directory_retention > 0:  # If 0, disable the auto remove
                current_time = time.time()
                for f in os.listdir(bundle_send_to_directory_path):
                    if f.endswith(".json"):
                        file_location = os.path.join(bundle_send_to_directory_path, f)
                        file_time = os.stat(file_location).st_mtime
                        is_expired_file = (
                            file_time
                            < current_time - 86400 * bundle_send_to_directory_retention
                        )  # 86400 = 1 day
                        if is_expired_file:
                            os.remove(file_location)
            # Write the bundle to target directory
            with open(write_file, "w") as f:
                str_bundle = json.dumps(message_bundle)
                f.write(str_bundle)
            # Rename the file after full write
            final_write_file = os.path.join(bundle_send_to_directory_path, bundle_file)
            os.rename(write_file, final_write_file)

        # If S3 setup, upload the bundle to the target S3 bucket
        if bundle_send_to_s3 and self.bundle_send_to_s3_bucket is not None:
            self.connector_logger.info(
                "The connector sending bundle to S3",
                {
                    "connector": self.connect_name,
                    "bucket": self.bundle_send_to_s3_bucket,
                    "folder": self.bundle_send_to_s3_folder,
                    "also_queuing": bundle_send_to_queue,
                },
            )
            bundle_file = self._generate_bundle_filename()
            message_bundle = self._create_message_bundle(
                "S3_BUNDLE", bundle, entities_types, update
            )
            self._send_bundle_to_s3(json.dumps(message_bundle), bundle_file)

        stix2_splitter = OpenCTIStix2Splitter()
        (expectations_number, _, bundles) = (
            stix2_splitter.split_bundle_with_expectations(
                bundle=bundle,
                use_json=True,
                event_version=event_version,
                cleanup_inconsistent_bundle=cleanup_inconsistent_bundle,
            )
        )

        if len(bundles) == 0:
            self.metric.inc("error_count")
            raise ValueError("Nothing to import")

        if bundle_send_to_queue:
            if entities_types is None:
                entities_types = []
            if self.queue_protocol == "amqp":
                if work_id:
                    self.api.work.add_expectations(work_id, expectations_number)
                pika_credentials = pika.PlainCredentials(
                    self.connector_config["connection"]["user"],
                    self.connector_config["connection"]["pass"],
                )
                pika_parameters = pika.ConnectionParameters(
                    heartbeat=10,
                    host=self.connector_config["connection"]["host"],
                    port=self.connector_config["connection"]["port"],
                    virtual_host=self.connector_config["connection"]["vhost"],
                    credentials=pika_credentials,
                    ssl_options=(
                        pika.SSLOptions(
                            create_mq_ssl_context(self.config),
                            self.connector_config["connection"]["host"],
                        )
                        if self.connector_config["connection"]["use_ssl"]
                        else None
                    ),
                )
                pika_connection = pika.BlockingConnection(pika_parameters)
                channel = pika_connection.channel()
                try:
                    channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    self.connector_logger.warning(str(err))
                self.connector_logger.info(
                    self.connect_name + " sending bundle to queue"
                )
                for sequence, bundle in enumerate(bundles, start=1):
                    self._send_bundle(
                        channel,
                        bundle,
                        work_id=work_id,
                        entities_types=entities_types,
                        sequence=sequence,
                        update=update,
                        draft_id=draft_id,
                    )
                channel.close()
                pika_connection.close()
            elif self.queue_protocol == "api":
                self.api.send_bundle_to_api(
                    connector_id=self.connector_id, bundle=bundle, work_id=work_id
                )
                self.metric.inc("bundle_send")
            else:
                raise ValueError(
                    f"{self.queue_protocol}: this queue protocol is not supported"
                )

        return bundles

    def _send_bundle(self, channel, bundle, **kwargs) -> None:
        """Send a STIX2 bundle to RabbitMQ to be consumed by workers.

        Publishes a bundle message to the configured RabbitMQ exchange with
        persistent delivery mode. Retries automatically on delivery failure.

        :param channel: RabbitMQ channel for publishing
        :type channel: pika.channel.Channel
        :param bundle: Valid STIX2 bundle as a JSON string
        :type bundle: str
        :param work_id: Work ID for tracking (default: None)
        :type work_id: str, optional
        :param sequence: Sequence number for bundle ordering (default: 0)
        :type sequence: int, optional
        :param entities_types: List of entity types to filter (default: None)
        :type entities_types: list, optional
        :param update: Whether to update existing data in the database (default: False)
        :type update: bool, optional
        :param draft_id: Draft context ID for the bundle (default: None)
        :type draft_id: str, optional
        """
        work_id = kwargs.get("work_id", None)
        sequence = kwargs.get("sequence", 0)
        update = kwargs.get("update", False)
        entities_types = kwargs.get("entities_types", None)
        draft_id = kwargs.get("draft_id", None)

        if entities_types is None:
            entities_types = []

        # Validate the STIX 2 bundle
        # validation = validate_string(bundle)
        # if not validation.is_valid:
        # raise ValueError('The bundle is not a valid STIX2 JSON')

        # Prepare the message
        # if self.current_work_id is None:
        #    raise ValueError('The job id must be specified')
        message = {
            "bundle_type": "QUEUE_BUNDLE",
            "applicant_id": self.applicant_id,
            "action_sequence": sequence,
            "entities_types": entities_types,
            "content": base64.b64encode(bundle.encode("utf-8", "escape")).decode(
                "utf-8"
            ),
            "update": update,
            "draft_id": draft_id,
        }
        if work_id is not None:
            message["work_id"] = work_id

        # Send the message
        try:
            channel.basic_publish(
                exchange=self.connector_config["push_exchange"],
                routing_key=self.connector_config["push_routing"],
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2, content_encoding="utf-8"  # make message persistent
                ),
            )
            self.connector_logger.debug("Bundle has been sent")
            self.metric.inc("bundle_send")
        except (UnroutableError, NackError):
            self.connector_logger.error("Unable to send bundle, retry...")
            self.metric.inc("error_count")
            time.sleep(10)
            self._send_bundle(channel, bundle, **kwargs)

    @staticmethod
    def stix2_deduplicate_objects(items) -> list:
        """Deduplicate STIX2 objects by their ID.

        Removes duplicate STIX2 objects from a list, keeping only the first
        occurrence of each unique ID.

        :param items: List of STIX2 objects to deduplicate
        :type items: list
        :return: Deduplicated list of STIX2 objects
        :rtype: list
        """

        ids = []
        final_items = []
        for item in items:
            if item["id"] not in ids:
                final_items.append(item)
                ids.append(item["id"])
        return final_items

    @staticmethod
    def stix2_create_bundle(items) -> Optional[str]:
        """Create a STIX2 bundle from a list of objects.

        Wraps STIX2 objects in a valid bundle structure with a generated UUID.
        Automatically serializes objects if they are STIX2 library instances.

        :param items: List of STIX2 objects (dicts or STIX2 library objects)
        :type items: list
        :return: JSON string of the STIX2 bundle, or None if items is empty
        :rtype: Optional[str]
        """

        # Check if item are native STIX 2 lib
        for i in range(len(items)):
            if hasattr(items[i], "serialize"):
                items[i] = json.loads(items[i].serialize())

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": items,
        }
        return json.dumps(bundle)

    @staticmethod
    def check_max_tlp(tlp: str, max_tlp: str) -> bool:
        """Check if a TLP level is within the allowed maximum TLP level.

        Validates that the given TLP marking is at or below the maximum
        allowed TLP level. Useful for filtering data based on sharing
        restrictions.

        :param tlp: The TLP level to check (e.g., "TLP:GREEN", "TLP:AMBER")
        :type tlp: str
        :param max_tlp: The highest allowed TLP level for comparison
        :type max_tlp: str
        :return: True if the TLP level is within the allowed range, False otherwise
        :rtype: bool

        Example:
            >>> OpenCTIConnectorHelper.check_max_tlp("TLP:GREEN", "TLP:AMBER")
            True
            >>> OpenCTIConnectorHelper.check_max_tlp("TLP:RED", "TLP:GREEN")
            False
        """
        if tlp is None or max_tlp is None:
            return True

        allowed_tlps: Dict[str, List[str]] = {
            "TLP:RED": [
                "TLP:WHITE",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:RED",
            ],
            "TLP:AMBER+STRICT": [
                "TLP:WHITE",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
            ],
            "TLP:AMBER": ["TLP:WHITE", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"],
            "TLP:GREEN": ["TLP:WHITE", "TLP:CLEAR", "TLP:GREEN"],
            "TLP:WHITE": ["TLP:WHITE", "TLP:CLEAR"],
            "TLP:CLEAR": ["TLP:WHITE", "TLP:CLEAR"],
        }

        return tlp.upper() in allowed_tlps[max_tlp.upper()]

    @staticmethod
    def get_attribute_in_extension(key: str, stix_object: Dict) -> any:
        """Get an attribute from OpenCTI STIX extensions.

        Retrieves a value from OpenCTI's custom STIX extension definitions.
        Checks both the primary OpenCTI extension and the SDO extension,
        falling back to the object's root attributes if not found in extensions.

        :param key: The attribute key to retrieve
        :type key: str
        :param stix_object: A STIX object dictionary
        :type stix_object: Dict

        :return: The attribute value, or None if not found
        :rtype: any

        Example:
            >>> obj = {"extensions": {"extension-definition--ea279b3e-...": {"score": 85}}}
            >>> OpenCTIConnectorHelper.get_attribute_in_extension("score", obj)
            85
        """
        if (
            "extensions" in stix_object
            and "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            in stix_object["extensions"]
            and key
            in stix_object["extensions"][
                "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            ]
        ):
            return stix_object["extensions"][
                "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            ][key]
        elif (
            "extensions" in stix_object
            and "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            in stix_object["extensions"]
            and key
            in stix_object["extensions"][
                "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            ]
        ):
            return stix_object["extensions"][
                "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            ][key]
        elif key in stix_object and key not in ["type"]:
            return stix_object[key]
        return None

    @staticmethod
    def get_attribute_in_mitre_extension(key: str, stix_object: Dict) -> any:
        """Get an attribute from MITRE ATT&CK STIX extension.

        Retrieves a value from the MITRE ATT&CK custom STIX extension
        definition used for attack patterns and techniques.

        :param key: The attribute key to retrieve
        :type key: str
        :param stix_object: A STIX object dictionary
        :type stix_object: Dict

        :return: The attribute value, or None if not found
        :rtype: any

        Example:
            >>> obj = {"extensions": {"extension-definition--322b8f77-...": {"x_mitre_version": "1.0"}}}
            >>> OpenCTIConnectorHelper.get_attribute_in_mitre_extension("x_mitre_version", obj)
            '1.0'
        """
        if (
            "extensions" in stix_object
            and "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            in stix_object["extensions"]
            and key
            in stix_object["extensions"][
                "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            ]
        ):
            return stix_object["extensions"][
                "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            ][key]
        return None

    def get_data_from_enrichment(self, data, standard_id, opencti_entity):
        """Extract STIX entity and objects from enrichment data.

        :param data: The enrichment data containing a bundle
        :type data: dict
        :param standard_id: The STIX standard ID of the entity
        :type standard_id: str
        :param opencti_entity: The OpenCTI entity object
        :type opencti_entity: dict
        :return: Dictionary containing stix_entity and stix_objects
        :rtype: dict
        """
        bundle = data.get("bundle", None)
        # Extract main entity from bundle in case of playbook
        if bundle is None:
            # Generate bundle
            stix_objects = self.api.stix2.prepare_export(
                entity=self.api.stix2.generate_export(copy.copy(opencti_entity))
            )
        else:
            stix_objects = bundle["objects"]
        stix_entity = [e for e in stix_objects if e["id"] == standard_id][0]
        return {
            "stix_entity": stix_entity,
            "stix_objects": stix_objects,
        }
