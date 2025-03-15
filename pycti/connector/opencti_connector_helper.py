import asyncio
import base64
import copy
import datetime
import json
import os
import queue
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

import pika
import uvicorn
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
FALSY: List[str] = ["no", "false", "False"]

app = FastAPI()


def killProgramHook(etype, value, tb):
    os.kill(os.getpid(), signal.SIGTERM)


def start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


def get_config_variable(
    env_var: str,
    yaml_path: List,
    config: Dict = {},
    isNumber: Optional[bool] = False,
    default=None,
    required=False,
) -> Union[bool, int, None, str]:
    """[summary]

    :param env_var: environment variable name
    :param yaml_path: path to yaml config
    :param config: client config dict, defaults to {}
    :param isNumber: specify if the variable is a number, defaults to False
    :param default: default value
    """

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


def is_memory_certificate(certificate):
    return certificate.startswith("-----BEGIN")


def ssl_verify_locations(ssl_context, certdata):
    if certdata is None:
        return

    if is_memory_certificate(certdata):
        ssl_context.load_verify_locations(cadata=certdata)
    else:
        ssl_context.load_verify_locations(cafile=certdata)


# As cert must be written in files to be loaded in ssl context
# Creates a temporary file in the most secure manner possible
def data_to_temp_file(data):
    # The file is readable and writable only by the creating user ID.
    # If the operating system uses permission bits to indicate whether a
    # file is executable, the file is executable by no one. The file
    # descriptor is not inherited by children of this process.
    file_descriptor, file_path = tempfile.mkstemp()
    with os.fdopen(file_descriptor, "w") as open_file:
        open_file.write(data)
        open_file.close()
    return file_path


def ssl_cert_chain(ssl_context, cert_data, key_data, passphrase):
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


def create_callback_ssl_context(config) -> ssl.SSLContext:
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


def create_mq_ssl_context(config) -> ssl.SSLContext:
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
    """Main class for the ListenQueue used in OpenCTIConnectorHelper

    :param helper: instance of a `OpenCTIConnectorHelper` class
    :type helper: OpenCTIConnectorHelper
    :param config: dict containing client config
    :type config: Dict
    :param callback: callback function to process queue
    :type callback: callable
    """

    def __init__(
        self,
        helper,
        opencti_token,
        config: Dict,
        connector_config: Dict,
        applicant_id,
        listen_protocol,
        listen_protocol_api_ssl,
        listen_protocol_api_path,
        listen_protocol_api_port,
        callback,
    ) -> None:
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
        """process a message from the rabbit queue

        :param channel: channel instance
        :type channel: callable
        :param method: message methods
        :type method: callable
        :param properties: unused
        :type properties: str
        :param body: message body (data)
        :type body: str or bytes or bytearray
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

    def _data_handler(self, json_data) -> None:
        # Execute the callback
        try:
            event_data = json_data["event"]
            entity_id = event_data.get("entity_id")
            entity_type = event_data.get("entity_type")
            validation_mode = event_data.get("validation_mode", "workbench")
            # Set the API headers
            internal_data = json_data["internal"]
            work_id = internal_data["work_id"]
            draft_id = internal_data.get("draft_id", "")
            self.helper.work_id = work_id

            self.helper.validation_mode = validation_mode
            self.helper.draft_id = draft_id
            self.helper.api.set_draft_id(draft_id)
            self.helper.api_impersonate.set_draft_id(draft_id)

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
                        "Unable to read/access to the entity, please check that the connector permission"
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
                    stix_objects = self.helper.api.stix2.prepare_export(
                        entity=self.helper.api.stix2.generate_export(
                            copy.copy(opencti_entity)
                        )
                    )
                    stix_entity = [
                        e
                        for e in stix_objects
                        if e["id"] == opencti_entity["standard_id"]
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

            # Handle applicant_id for in-personalization
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

        except Exception as e:  # pylint: disable=broad-except
            self.helper.metric.inc("error_count")
            self.helper.connector_logger.error(
                "Error in message processing, reporting error to API"
            )
            if work_id:
                try:
                    self.helper.api.work.to_processed(work_id, str(e), True)
                except:  # pylint: disable=bare-except
                    self.helper.metric.inc("error_count")
                    self.helper.connector_logger.error(
                        "Failing reporting the processing"
                    )

    async def _http_process_callback(self, request: Request):
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
        if self.listen_protocol == "AMQP":
            self.helper.connector_logger.info("Starting ListenQueue thread")
            while not self.exit_event.is_set():
                try:
                    self.helper.connector_logger.info(
                        "ListenQueue connecting to rabbitMq."
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
                        # confirm_delivery is only for cluster mode rabbitMQ
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
        self.helper.connector_logger.info("Preparing ListenQueue for clean shutdown")
        self.exit_event.set()
        self.pika_connection.close()
        if self.thread:
            self.thread.join()


class PingAlive(threading.Thread):
    def __init__(
        self,
        connector_logger,
        connector_id,
        api,
        get_state,
        set_state,
        metric,
        connector_info,
    ) -> None:
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
        self.connector_logger.info("Starting PingAlive thread")
        self.ping()

    def stop(self) -> None:
        self.connector_logger.info("Preparing PingAlive for clean shutdown")
        self.exit_event.set()


class StreamAlive(threading.Thread):
    def __init__(self, helper, q) -> None:
        threading.Thread.__init__(self)
        self.helper = helper
        self.q = q
        self.exit_event = threading.Event()

    def run(self) -> None:
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
        self.helper.connector_logger.info("Preparing StreamAlive for clean shutdown")
        self.exit_event.set()


class ListenStream(threading.Thread):
    def __init__(
        self,
        helper,
        callback,
        url,
        token,
        verify_ssl,
        start_timestamp,
        live_stream_id,
        listen_delete,
        no_dependencies,
        recover_iso_date,
        with_inferences,
    ) -> None:
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
            # In case no recover is explicitely set
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
                            self.exit = True
                        state["start_from"] = str(msg.id)
                        self.helper.set_state(state)
        except Exception as ex:
            self.helper.connector_logger.error(
                "Error in ListenStream loop, exit.", {"reason": str(ex)}
            )
            sys.excepthook(*sys.exc_info())

    def stop(self):
        self.helper.connector_logger.info("Preparing ListenStream for clean shutdown")
        self.exit_event.set()


class ConnectorInfo:
    def __init__(
        self,
        run_and_terminate: bool = False,
        buffering: bool = False,
        queue_threshold: float = 500.0,
        queue_messages_size: float = 0.0,
        next_run_datetime: datetime = None,
        last_run_datetime: datetime = None,
    ):
        self._run_and_terminate = run_and_terminate
        self._buffering = buffering
        self._queue_threshold = queue_threshold
        self._queue_messages_size = queue_messages_size
        self._next_run_datetime = next_run_datetime
        self._last_run_datetime = last_run_datetime

    @property
    def all_details(self):
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
        return self._run_and_terminate

    @run_and_terminate.setter
    def run_and_terminate(self, value):
        self._run_and_terminate = value

    @property
    def buffering(self) -> bool:
        return self._buffering

    @buffering.setter
    def buffering(self, value):
        self._buffering = value

    @property
    def queue_threshold(self) -> float:
        return self._queue_threshold

    @queue_threshold.setter
    def queue_threshold(self, value):
        self._queue_threshold = value

    @property
    def queue_messages_size(self) -> float:
        return self._queue_messages_size

    @queue_messages_size.setter
    def queue_messages_size(self, value):
        self._queue_messages_size = value

    @property
    def next_run_datetime(self) -> datetime:
        return self._next_run_datetime

    @next_run_datetime.setter
    def next_run_datetime(self, value):
        self._next_run_datetime = value

    @property
    def last_run_datetime(self) -> datetime:
        return self._last_run_datetime

    @last_run_datetime.setter
    def last_run_datetime(self, value):
        self._last_run_datetime = value


class OpenCTIConnectorHelper:  # pylint: disable=too-many-public-methods
    """Python API for OpenCTI connector

    :param config: dict standard config
    :type config: Dict
    """

    class TimeUnit(Enum):
        SECONDS = 1
        MINUTES = 60
        HOURS = 3600
        DAYS = 86400
        WEEKS = 604800
        YEARS = 31536000

    def __init__(self, config: Dict, playbook_compatible=False) -> None:
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
            False,
            None,
        )
        self.connect_live_stream_listen_delete = get_config_variable(
            "CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
            ["connector", "live_stream_listen_delete"],
            config,
            False,
            True,
        )
        self.connect_live_stream_no_dependencies = get_config_variable(
            "CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
            ["connector", "live_stream_no_dependencies"],
            config,
            False,
            False,
        )
        self.connect_live_stream_with_inferences = get_config_variable(
            "CONNECTOR_LIVE_STREAM_WITH_INFERENCES",
            ["connector", "live_stream_with_inferences"],
            config,
            False,
            False,
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
            "CONNECTOR_SCOPE", ["connector", "scope"], config
        )
        self.connect_auto = get_config_variable(
            "CONNECTOR_AUTO", ["connector", "auto"], config, False, False
        )
        self.bundle_send_to_queue = get_config_variable(
            "CONNECTOR_SEND_TO_QUEUE",
            ["connector", "send_to_queue"],
            config,
            False,
            True,
        )
        self.bundle_send_to_directory = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY",
            ["connector", "send_to_directory"],
            config,
            False,
            False,
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
            True,
            7,
        )
        self.connect_only_contextual = get_config_variable(
            "CONNECTOR_ONLY_CONTEXTUAL",
            ["connector", "only_contextual"],
            config,
            False,
            False,
        )
        self.log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="INFO"
        ).upper()
        self.connect_run_and_terminate = get_config_variable(
            "CONNECTOR_RUN_AND_TERMINATE",
            ["connector", "run_and_terminate"],
            config,
            False,
            False,
        )
        self.connect_validate_before_import = get_config_variable(
            "CONNECTOR_VALIDATE_BEFORE_IMPORT",
            ["connector", "validate_before_import"],
            config,
            False,
            False,
        )
        self.scheduler = sched.scheduler(time.time, time.sleep)
        # Start up the server to expose the metrics.
        expose_metrics = get_config_variable(
            "CONNECTOR_EXPOSE_METRICS",
            ["connector", "expose_metrics"],
            config,
            False,
            False,
        )
        metrics_port = get_config_variable(
            "CONNECTOR_METRICS_PORT", ["connector", "metrics_port"], config, True, 9095
        )
        # Initialize ConnectorInfo instance
        self.connector_info = ConnectorInfo()
        # Initialize configuration
        # - Classic API that will be directly attached to the connector rights
        self.api = OpenCTIApiClient(
            self.opencti_url,
            self.opencti_token,
            self.log_level,
            self.opencti_ssl_verify,
            json_logging=self.opencti_json_logging,
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
            self.connector_logger, expose_metrics, metrics_port
        )
        # Register the connector in OpenCTI
        self.connector = OpenCTIConnector(
            self.connect_id,
            self.connect_name,
            self.connect_type,
            self.connect_scope,
            self.connect_auto,
            self.connect_only_contextual,
            playbook_compatible,
            self.listen_protocol_api_uri + self.listen_protocol_api_path,
        )
        connector_configuration = self.api.connector.register(self.connector)
        self.connector_logger.info(
            "Connector registered with ID", {"id": self.connect_id}
        )
        self.work_id = None
        self.validation_mode = "workbench"
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

    def stop(self) -> None:
        self.connector_logger.info("Preparing connector for clean shutdown")
        if self.listen_queue:
            self.listen_queue.stop()
        # if self.listen_stream:
        #     self.listen_stream.stop()
        self.ping.stop()
        self.api.connector.unregister(self.connector_id)

    def get_name(self) -> Optional[Union[bool, int, str]]:
        return self.connect_name

    def get_stream_collection(self):
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
        return self.connect_only_contextual

    def get_run_and_terminate(self) -> Optional[Union[bool, int, str]]:
        return self.connect_run_and_terminate

    def get_validate_before_import(self) -> Optional[Union[bool, int, str]]:
        return self.connect_validate_before_import

    def set_state(self, state) -> None:
        """sets the connector state

        :param state: state object
        :type state: Dict or None
        """
        if isinstance(state, Dict):
            self.connector_state = json.dumps(state)
        else:
            self.connector_state = None

    def get_state(self) -> Optional[Dict]:
        """get the connector state

        :return: returns the current state of the connector if there is any
        :rtype:
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
        """
        Lets you know what the next run of the scheduler will be in iso datetime format

        :param duration_period_in_seconds: Duration in seconds
        :return: None
        """
        try:
            duration_timedelta = datetime.timedelta(seconds=duration_period_in_seconds)
            next_datetime = datetime.datetime.utcnow() + duration_timedelta
            # Set next_run_datetime
            self.connector_info.next_run_datetime = next_datetime.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.connector_logger.info(
                "[INFO] Schedule next run of connector: ",
                {"next_run_datetime": self.connector_info.next_run_datetime},
            )
            return
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "[ERROR] An error occurred while calculating the next run in datetime",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def last_run_datetime(self) -> None:
        """
        Lets you know what the last run of the connector the scheduler processed, will be in iso datetime format

        :return: None
        """
        try:
            current_datetime = datetime.datetime.utcnow()
            # Set last_run_datetime
            self.connector_info.last_run_datetime = current_datetime.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            return
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "[ERROR] An error occurred while converting the last run in datetime",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def check_connector_buffering(self) -> bool:
        """
        Lets you know if the RabbitMQ queue has exceeded the allowed threshold defined by the connector or not
        :return: boolean
        """
        try:
            connector_details = self.api.connector.read(connector_id=self.connector_id)

            if connector_details and connector_details.get("id") is not None:
                connector_queue_id = connector_details["id"]
                connector_queue_details = connector_details["connector_queue_details"]

                queue_messages_size_byte = connector_queue_details["messages_size"]
                queue_threshold = float(self.connect_queue_threshold)

                # Convert queue_messages_size to Mo (decimal)
                queue_messages_size_mo = queue_messages_size_byte / 1000000

                self.connector_logger.debug(
                    "[DEBUG] Connector queue details ...",
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
                        "[INFO] Connector will not run until the queue messages size is reduced under queue threshold"
                    )
                    # Set buffering
                    self.connector_info.buffering = True
                    return True

            else:
                self.metric.inc("error_count")
                self.connector_logger.error(
                    "[ERROR] An error occurred while retrieving connector details"
                )
                sys.excepthook(*sys.exc_info())
        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "[ERROR] An error occurred while checking the queue size",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def schedule_unit(
        self,
        message_callback: Callable[[], None],
        duration_period: Union[int, float, str],
        time_unit: TimeUnit,
    ) -> None:
        """
        This (deprecated) method is there to manage backward compatibility of intervals on connectors,
        allows you to calculate the duration period of connectors in seconds with time_unit and will be
        replaced by the "schedule_iso" method. It uses a TimeUnit enum.

        :param message_callback: Corresponds to the connector process
        :param duration_period: Corresponds to the connector interval, it can vary depending on the connector
        configuration.
        :param time_unit: The unit of time for the duration_period.
        Enum TimeUnit Valid (YEARS, WEEKS, DAYS, HOURS, MINUTES, SECONDS)
        :return: None
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
                "[ERROR] An unexpected error occurred during schedule_unit",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def schedule_iso(
        self, message_callback: Callable[[], None], duration_period: str
    ) -> None:
        """
        This method allows you to calculate the duration period of connectors in seconds from ISO 8601 format
        and start the scheduler process.

        :param message_callback: Corresponds to the connector process
        :param duration_period: Corresponds to a string in ISO 8601 format "P18Y9W4DT11H9M8S"
        :return: None
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
                "[ERROR] An unexpected error occurred during schedule_iso",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def _schedule_process(
        self,
        scheduler: sched.scheduler,
        message_callback: Callable[[], None],
        duration_period: Union[int, float],
    ) -> None:
        """
        When scheduling, the function retrieves the details of the connector queue,
        and the connector process starts only if the size of the queue messages is less than or
        equal to the queue_threshold variable.

        :param scheduler: Scheduler contains a list of all tasks to be started
        :param message_callback: Corresponds to the connector process
        :param duration_period: Corresponds to the connector's interval
        :return: None
        """
        try:
            self.connector_logger.info("[INFO] Starting schedule")
            check_connector_buffering = self.check_connector_buffering()

            if not check_connector_buffering:
                # Start running the connector
                message_callback()
                # Lets you know what is the last run of the connector datetime
                self.last_run_datetime()

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "[ERROR] An error occurred while checking the queue size",
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
        """
        This method schedules the execution of a connector process.
        If `duration_period' is zero or `self.connect_run_and_terminate' is True, the process will run and terminate.
        Otherwise, it schedules the next run based on the interval.

        :param message_callback: Corresponds to the connector process
        :param duration_period: Corresponds to the connector's interval in seconds
        :return: None
        """
        try:
            # In the case where the duration_period_converted is zero, we consider it to be a run and terminate
            if self.connect_run_and_terminate or duration_period == 0:
                self.connector_logger.info("[INFO] Starting run and terminate")
                # Set run_and_terminate
                self.connector_info.run_and_terminate = True
                check_connector_buffering = self.check_connector_buffering()

                if not check_connector_buffering:
                    # Start running the connector
                    message_callback()

                # Lets you know what is the last run of the connector datetime
                self.last_run_datetime()
                self.connector_logger.info("[INFO] Closing run and terminate")
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
                self.connector_logger.info("[INFO] Closing run and terminate")
                self.force_ping()
                sys.exit(0)

        except Exception as err:
            self.metric.inc("error_count")
            self.connector_logger.error(
                "[ERROR] An unexpected error occurred during schedule",
                {"reason": str(err)},
            )
            sys.excepthook(*sys.exc_info())

    def listen(
        self,
        message_callback: Callable[[Dict], str],
    ) -> None:
        """listen for messages and register callback function

        :param message_callback: callback function to process messages
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
        message_callback,
        url=None,
        token=None,
        verify_ssl=None,
        start_timestamp=None,
        live_stream_id=None,
        listen_delete=None,
        no_dependencies=None,
        recover_iso_date=None,
        with_inferences=None,
    ) -> ListenStream:
        """listen for messages and register callback function

        :param message_callback: callback function to process messages
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
        return self.opencti_url

    def get_opencti_token(self) -> Optional[Union[bool, int, str]]:
        return self.opencti_token

    def get_connector(self) -> OpenCTIConnector:
        return self.connector

    def date_now(self) -> str:
        """get the current date (UTC)
        :return: current datetime for utc
        :rtype: str
        """
        return (
            datetime.datetime.utcnow()
            .replace(microsecond=0, tzinfo=datetime.timezone.utc)
            .isoformat()
        )

    def date_now_z(self) -> str:
        """get the current date (UTC)
        :return: current datetime for utc
        :rtype: str
        """
        return (
            datetime.datetime.utcnow()
            .replace(microsecond=0, tzinfo=datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    # Push Stix2 helper
    def send_stix2_bundle(self, bundle: str, **kwargs) -> list:
        """send a stix2 bundle to the API

        :param work_id: a valid work id
        :param draft_id: a draft context to send the bundle to
        :param bundle: valid stix2 bundle
        :type bundle:
        :param entities_types: list of entities, defaults to None
        :type entities_types: list, optional
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :param bypass_split: use to prevent splitting of the bundle. This option has been removed since 6.3 and is no longer used.
        :type bypass_split: bool, optional
        :raises ValueError: if the bundle is empty
        :return: list of bundles
        :rtype: list
        """
        work_id = kwargs.get("work_id", self.work_id)
        validation_mode = kwargs.get("validation_mode", self.validation_mode)
        draft_id = kwargs.get("draft_id", self.draft_id)
        entities_types = kwargs.get("entities_types", None)
        update = kwargs.get("update", False)
        event_version = kwargs.get("event_version", None)
        bypass_validation = kwargs.get("bypass_validation", False)
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

        if self.connect_validate_before_import and not bypass_validation and file_name:
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
            bundle_file = (
                self.connect_name.lower().replace(" ", "_")
                + "-"
                + time.strftime("%Y%m%d-%H%M%S-")
                + str(time.time())
                + ".json"
            )
            write_file = os.path.join(
                bundle_send_to_directory_path, bundle_file + ".tmp"
            )
            message_bundle = {
                "bundle_type": "DIRECTORY_BUNDLE",
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

        stix2_splitter = OpenCTIStix2Splitter()
        (
            expectations_number,
            bundles,
        ) = stix2_splitter.split_bundle_with_expectations(
            bundle=bundle,
            use_json=True,
            event_version=event_version,
            cleanup_inconsistent_bundle=cleanup_inconsistent_bundle,
        )

        if len(bundles) == 0:
            self.metric.inc("error_count")
            raise ValueError("Nothing to import")

        if bundle_send_to_queue:
            if work_id and draft_id:
                self.api.work.add_draft_context(work_id, draft_id)
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
            else:
                raise ValueError(
                    f"{self.queue_protocol}: this queue protocol is not supported"
                )

        return bundles

    def _send_bundle(self, channel, bundle, **kwargs) -> None:
        """send a STIX2 bundle to RabbitMQ to be consumed by workers

        :param channel: RabbitMQ channel
        :type channel: callable
        :param bundle: valid stix2 bundle
        :type bundle:
        :param entities_types: list of entity types, defaults to None
        :type entities_types: list, optional
        :param update: whether to update data in the database, defaults to False
        :type update: bool, optional
        :param draft_id: if draft_id is set, bundle must be set in draft context
        :type draft_id:
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

    def stix2_get_embedded_objects(self, item) -> Dict:
        """gets created and marking refs for a stix2 item

        :param item: valid stix2 item
        :type item:
        :return: returns a dict of created_by of object_marking_refs
        :rtype: Dict
        """
        # Marking definitions
        object_marking_refs = []
        if "object_marking_refs" in item:
            for object_marking_ref in item["object_marking_refs"]:
                if object_marking_ref in self.cache_index:
                    object_marking_refs.append(self.cache_index[object_marking_ref])
        # Created by ref
        created_by_ref = None
        if "created_by_ref" in item and item["created_by_ref"] in self.cache_index:
            created_by_ref = self.cache_index[item["created_by_ref"]]

        return {
            "object_marking_refs": object_marking_refs,
            "created_by_ref": created_by_ref,
        }

    def stix2_get_entity_objects(self, entity) -> list:
        """process a stix2 entity

        :param entity: valid stix2 entity
        :type entity:
        :return: entity objects as list
        :rtype: list
        """

        items = [entity]
        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(entity)
        # Add created by ref
        if embedded_objects["created_by_ref"] is not None:
            items.append(embedded_objects["created_by_ref"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items

    def stix2_get_relationship_objects(self, relationship) -> list:
        """get a list of relations for a stix2 relationship object

        :param relationship: valid stix2 relationship
        :type relationship:
        :return: list of relations objects
        :rtype: list
        """

        items = [relationship]
        # Get source ref
        if relationship["source_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["source_ref"]])

        # Get target ref
        if relationship["target_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["target_ref"]])

        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(relationship)
        # Add created by ref
        if embedded_objects["created_by"] is not None:
            items.append(embedded_objects["created_by"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items

    def stix2_get_report_objects(self, report) -> list:
        """get a list of items for a stix2 report object

        :param report: valid stix2 report object
        :type report:
        :return: list of items for a stix2 report object
        :rtype: list
        """

        items = [report]
        # Add all object refs
        for object_ref in report["object_refs"]:
            items.append(self.cache_index[object_ref])
        for item in items:
            if item["type"] == "relationship":
                items = items + self.stix2_get_relationship_objects(item)
            else:
                items = items + self.stix2_get_entity_objects(item)
        return items

    @staticmethod
    def stix2_deduplicate_objects(items) -> list:
        """deduplicate stix2 items

        :param items: valid stix2 items
        :type items:
        :return: de-duplicated list of items
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
        """create a stix2 bundle with items

        :param items: valid stix2 items
        :type items:
        :return: JSON of the stix2 bundle
        :rtype:
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
        """check the allowed TLP levels for a TLP string

        :param tlp: string for TLP level to check
        :type tlp: str
        :param max_tlp: the highest allowed TLP level
        :type max_tlp: str
        :return: TLP level in allowed TLPs
        :rtype: bool
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
    def get_attribute_in_extension(key, object) -> any:
        if (
            "extensions" in object
            and "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            in object["extensions"]
            and key
            in object["extensions"][
                "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            ]
        ):
            return object["extensions"][
                "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
            ][key]
        elif (
            "extensions" in object
            and "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            in object["extensions"]
            and key
            in object["extensions"][
                "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            ]
        ):
            return object["extensions"][
                "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
            ][key]
        elif key in object and key not in ["type"]:
            return object[key]
        return None

    @staticmethod
    def get_attribute_in_mitre_extension(key, object) -> any:
        if (
            "extensions" in object
            and "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            in object["extensions"]
            and key
            in object["extensions"][
                "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            ]
        ):
            return object["extensions"][
                "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
            ][key]
        return None

    def get_data_from_enrichment(self, data, standard_id, opencti_entity):
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
