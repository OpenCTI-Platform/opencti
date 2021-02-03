import datetime
import threading
import queue
import uuid
import requests

import pika
import logging
import json
import time
import base64
import os

from typing import Callable, Dict, Optional, Union
from sseclient import SSEClient
from pika.exceptions import UnroutableError, NackError
from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector import OpenCTIConnector
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

EVENTS_QUEUE = queue.Queue()


def get_config_variable(
    env_var: str,
    yaml_path: list,
    config: Dict = {},
    isNumber: Optional[bool] = False,
    default=None,
) -> Union[bool, int, None, str]:
    """[summary]

    :param env_var: environnement variable name
    :param yaml_path: path to yaml config
    :param config: client config dict, defaults to {}
    :param isNumber: specify if the variable is a number, defaults to False
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

    if result == "yes" or result == "true" or result == "True":
        return True
    elif result == "no" or result == "false" or result == "False":
        return False
    elif isNumber:
        return int(result)
    else:
        return result


class ListenQueue(threading.Thread):
    """Main class for the ListenQueue used in OpenCTIConnectorHelper

    :param helper: instance of a `OpenCTIConnectorHelper` class
    :type helper: OpenCTIConnectorHelper
    :param config: dict containing client config
    :type config: dict
    :param callback: callback function to process queue
    :type callback: callable
    """

    def __init__(self, helper, config: dict, callback):
        threading.Thread.__init__(self)
        self.pika_credentials = None
        self.pika_parameters = None
        self.pika_connection = None
        self.channel = None
        self.helper = helper
        self.callback = callback
        self.host = config["connection"]["host"]
        self.port = config["connection"]["port"]
        self.user = config["connection"]["user"]
        self.password = config["connection"]["pass"]
        self.queue_name = config["listen"]

    # noinspection PyUnusedLocal
    def _process_message(self, channel, method, properties, body):
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
        thread = threading.Thread(target=self._data_handler, args=[json_data])
        thread.start()
        while thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(1.0)
        logging.info(
            "Message (delivery_tag="
            + str(method.delivery_tag)
            + ") processed, thread terminated"
        )
        channel.basic_ack(delivery_tag=method.delivery_tag)

    def _data_handler(self, json_data):
        # Set the API headers
        work_id = json_data["internal"]["work_id"]
        applicant_id = json_data["internal"]["applicant_id"]
        self.helper.work_id = work_id
        if applicant_id is not None:
            self.helper.applicant_id = applicant_id
            self.helper.api.set_applicant_id_header(applicant_id)
        # Execute the callback
        try:
            self.helper.api.work.to_received(
                work_id, "Connector ready to process the operation"
            )
            message = self.callback(json_data["event"])
            self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            logging.exception("Error in message processing, reporting error to API")
            try:
                self.helper.api.work.to_processed(work_id, str(e), True)
            except:
                logging.error("Failing reporting the processing")

    def run(self):
        while True:
            try:
                # Connect the broker
                self.pika_credentials = pika.PlainCredentials(self.user, self.password)
                self.pika_parameters = pika.ConnectionParameters(
                    self.host, self.port, "/", self.pika_credentials
                )
                self.pika_connection = pika.BlockingConnection(self.pika_parameters)
                self.channel = self.pika_connection.channel()
                self.channel.basic_consume(
                    queue=self.queue_name, on_message_callback=self._process_message
                )
                self.channel.start_consuming()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(10)


class PingAlive(threading.Thread):
    def __init__(self, connector_id, api, get_state, set_state):
        threading.Thread.__init__(self)
        self.connector_id = connector_id
        self.in_error = False
        self.api = api
        self.get_state = get_state
        self.set_state = set_state

    def ping(self):
        while True:
            try:
                initial_state = self.get_state()
                result = self.api.connector.ping(self.connector_id, initial_state)
                remote_state = (
                    json.loads(result["connector_state"])
                    if len(result["connector_state"]) > 0
                    else None
                )
                if initial_state != remote_state:
                    self.set_state(result["connector_state"])
                    logging.info(
                        'Connector state has been remotely reset to: "'
                        + self.get_state()
                        + '"'
                    )
                if self.in_error:
                    self.in_error = False
                    logging.error("API Ping back to normal")
            except Exception:
                self.in_error = True
                logging.error("Error pinging the API")
            time.sleep(40)

    def run(self):
        logging.info("Starting ping alive thread")
        self.ping()


class StreamCatcher(threading.Thread):
    def __init__(
        self,
        opencti_url,
        opencti_token,
        connector_last_event_id,
        last_event_id,
        stream_connection_id,
    ):
        threading.Thread.__init__(self)
        self.opencti_url = opencti_url
        self.opencti_token = opencti_token
        self.connector_last_event_id = connector_last_event_id
        self.last_event_id = last_event_id
        self.stream_connection_id = stream_connection_id

    def get_range(self, from_id):
        payload = {
            "from": from_id,
            "size": 2000,
            "connectionId": self.stream_connection_id,
        }
        headers = {"Authorization": "Bearer " + self.opencti_token}
        r = requests.post(
            self.opencti_url + "/stream/history", json=payload, headers=headers
        )
        result = r.json()
        if result and "lastEventId" in result:
            return result["lastEventId"]

    def run(self):
        if self.connector_last_event_id:
            from_event_id = self.connector_last_event_id
            from_event_timestamp = 0
            last_event_timestamp = int(self.last_event_id.split("-")[0])
            while (
                from_event_timestamp <= last_event_timestamp
                and from_event_id != self.last_event_id
            ):
                from_event_id = self.get_range(from_event_id)
                from_event_timestamp = int(from_event_id.split("-")[0])
        logging.info("Events catchup requests done.")


class StreamProcessor(threading.Thread):
    def __init__(self, message_callback, get_state, set_state):
        threading.Thread.__init__(self)
        self.message_callback = message_callback
        self.get_state = get_state
        self.set_state = set_state

    def run(self):
        logging.info("All old events processed, consuming is now LIVE!")
        while True:
            msg = EVENTS_QUEUE.get(block=True, timeout=None)
            self.message_callback(msg)
            state = self.get_state()
            if state is not None:
                state["connectorLastEventId"] = msg.id
                self.set_state(state)
            else:
                self.set_state({"connectorLastEventId": msg.id})


class OpenCTIConnectorHelper:
    """Python API for OpenCTI connector

    :param config: Dict standard config
    :type config: dict
    """

    def __init__(self, config: dict):
        # Load API config
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.opencti_ssl_verify = get_config_variable(
            "OPENCTI_SSL_VERIFY", ["opencti", "ssl_verify"], config, False, True
        )
        # Load connector config
        self.connect_id = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], config
        )
        self.connect_type = get_config_variable(
            "CONNECTOR_TYPE", ["connector", "type"], config
        )
        self.connect_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config
        )
        self.connect_confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            True,
        )
        self.connect_scope = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], config
        )
        self.connect_auto = get_config_variable(
            "CONNECTOR_AUTO", ["connector", "auto"], config, False, False
        )
        self.log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config
        )

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError("Invalid log level: " + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize configuration
        self.api = OpenCTIApiClient(
            self.opencti_url, self.opencti_token, self.log_level
        )
        # Register the connector in OpenCTI
        self.connector = OpenCTIConnector(
            self.connect_id,
            self.connect_name,
            self.connect_type,
            self.connect_scope,
            self.connect_auto,
        )
        connector_configuration = self.api.connector.register(self.connector)
        logging.info("Connector registered with ID:" + self.connect_id)
        self.connector_id = connector_configuration["id"]
        self.work_id = None
        self.applicant_id = connector_configuration["connector_user"]["id"]
        self.connector_state = connector_configuration["connector_state"]
        self.config = connector_configuration["config"]

        # Start ping thread
        self.ping = PingAlive(
            self.connector.id, self.api, self.get_state, self.set_state
        )
        self.ping.start()

    def get_name(self):
        return self.connect_name

    def set_state(self, state) -> None:
        """sets the connector state

        :param state: state object
        :type state: dict
        """

        self.connector_state = json.dumps(state)

    def get_state(self):
        """get the connector state

        :return: returns the current state of the connector if there is any
        :rtype:
        """

        try:
            if self.connector_state:
                state = json.loads(self.connector_state)
                if isinstance(state, dict) and state:
                    return state
        except:
            pass
        return None

    def listen(self, message_callback: Callable[[str, Dict], str]) -> None:
        """listen for messages and register callback function

        :param message_callback: callback function to process messages
        :type message_callback: Callable[[Dict], List[str]]
        """

        listen_queue = ListenQueue(self, self.config, message_callback)
        listen_queue.start()

    def listen_stream(
        self, message_callback, url=None, token=None, verify=None
    ) -> None:
        """listen for messages and register callback function

        :param message_callback: callback function to process messages
        """
        current_state = self.get_state()
        if current_state is None:
            current_state = {"connectorLastEventId": "-"}

        # Get the last event ID with the "connected" event msg
        if url is not None and token is not None:
            opencti_ssl_verify = verify if verify is not None else True
            logging.info(
                "Starting listening stream events with SSL verify to: "
                + str(opencti_ssl_verify)
            )
            messages = SSEClient(
                url + "/stream",
                headers={"Authorization": "Bearer " + token},
                verify=opencti_ssl_verify,
            )
        else:
            logging.info(
                "Starting listening stream events with SSL verify to: "
                + str(self.opencti_ssl_verify)
            )
            messages = SSEClient(
                self.opencti_url + "/stream",
                headers={"Authorization": "Bearer " + self.opencti_token},
                verify=self.opencti_ssl_verify,
            )

        # Create processor thread
        processor_thread = StreamProcessor(
            message_callback, self.get_state, self.set_state
        )

        last_event_id = None
        for msg in messages:
            try:
                data = json.loads(msg.data)
            except:
                logging.error("Failed to load JSON: " + msg.data)
                continue
            if msg.event == "heartbeat":
                logging.info("HEARTBEAT:" + str(msg))
                continue
            elif msg.event == "connected":
                last_event_id = data["lastEventId"]
                stream_connection_id = data["connectionId"]
                # Launch processor if up to date
                if current_state["connectorLastEventId"] == last_event_id:
                    processor_thread.start()
                # Launch catcher if not up to date
                if last_event_id != current_state["connectorLastEventId"]:
                    logging.info(
                        "Some events have not been processed, catching them..."
                    )
                    if url is not None and token is not None:
                        catcher_thread = StreamCatcher(
                            url,
                            token,
                            current_state["connectorLastEventId"],
                            last_event_id,
                            stream_connection_id,
                        )
                    else:
                        catcher_thread = StreamCatcher(
                            self.opencti_url,
                            self.opencti_token,
                            current_state["connectorLastEventId"],
                            last_event_id,
                            stream_connection_id,
                        )
                    catcher_thread.start()
            else:
                # If receiving the last message, launch processor
                if msg.id == last_event_id:
                    message_callback(msg)
                    processor_thread.start()
                elif "catchup" not in data:
                    EVENTS_QUEUE.put(msg)
                else:
                    message_callback(msg)
                    state = self.get_state()
                    if state is not None:
                        state["connectorLastEventId"] = msg.id
                        self.set_state(state)
                    else:
                        self.set_state({"connectorLastEventId": msg.id})

    def get_opencti_url(self):
        return self.opencti_url

    def get_opencti_token(self):
        return self.opencti_token

    def get_connector(self):
        return self.connector

    def log_error(self, msg):
        logging.error(msg)

    def log_info(self, msg):
        logging.info(msg)

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

    # Push Stix2 helper
    def send_stix2_bundle(self, bundle, **kwargs) -> list:
        """send a stix2 bundle to the API

        :param work_id: a valid work id
        :param bundle: valid stix2 bundle
        :type bundle:
        :param entities_types: list of entities, defaults to None
        :type entities_types: list, optional
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :raises ValueError: if the bundle is empty
        :return: list of bundles
        :rtype: list
        """
        work_id = kwargs.get("work_id", self.work_id)
        entities_types = kwargs.get("entities_types", None)
        update = kwargs.get("update", False)

        if entities_types is None:
            entities_types = []
        stix2_splitter = OpenCTIStix2Splitter()
        bundles = stix2_splitter.split_bundle(bundle)
        if len(bundles) == 0:
            raise ValueError("Nothing to import")
        if work_id is not None:
            self.api.work.add_expectations(work_id, len(bundles))
        pika_credentials = pika.PlainCredentials(
            self.config["connection"]["user"], self.config["connection"]["pass"]
        )
        pika_parameters = pika.ConnectionParameters(
            self.config["connection"]["host"],
            self.config["connection"]["port"],
            "/",
            pika_credentials,
        )
        pika_connection = pika.BlockingConnection(pika_parameters)
        channel = pika_connection.channel()
        for sequence, bundle in enumerate(bundles, start=1):
            self._send_bundle(
                channel,
                bundle,
                work_id=work_id,
                entities_types=entities_types,
                sequence=sequence,
                update=update,
            )
        channel.close()
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
        """
        work_id = kwargs.get("work_id", None)
        sequence = kwargs.get("sequence", 0)
        update = kwargs.get("update", False)
        entities_types = kwargs.get("entities_types", None)

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
            "applicant_id": self.applicant_id,
            "action_sequence": sequence,
            "entities_types": entities_types,
            "content": base64.b64encode(bundle.encode("utf-8")).decode("utf-8"),
            "update": update,
        }
        if work_id is not None:
            message["work_id"] = work_id

        # Send the message
        try:
            routing_key = "push_routing_" + self.connector_id
            channel.basic_publish(
                exchange=self.config["push_exchange"],
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                ),
            )
            logging.info("Bundle has been sent")
        except (UnroutableError, NackError) as e:
            logging.error("Unable to send bundle, retry...", e)
            self._send_bundle(channel, bundle, **kwargs)

    def split_stix2_bundle(self, bundle) -> list:
        """splits a valid stix2 bundle into a list of bundles

        :param bundle: valid stix2 bundle
        :type bundle:
        :raises Exception: if data is not valid JSON
        :return: returns a list of bundles
        :rtype: list
        """

        self.cache_index = {}
        self.cache_added = []
        try:
            bundle_data = json.loads(bundle)
        except:
            raise Exception("File data is not a valid JSON")

        # validation = validate_parsed_json(bundle_data)
        # if not validation.is_valid:
        #     raise ValueError('The bundle is not a valid STIX2 JSON:' + bundle)

        # Index all objects by id
        for item in bundle_data["objects"]:
            self.cache_index[item["id"]] = item

        bundles = []
        # Reports must be handled because of object_refs
        for item in bundle_data["objects"]:
            if item["type"] == "report":
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_report_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Relationships not added in previous reports
        for item in bundle_data["objects"]:
            if item["type"] == "relationship" and item["id"] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_relationship_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Entities not added in previous reports and relationships
        for item in bundle_data["objects"]:
            if item["type"] != "relationship" and item["id"] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_entity_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        return bundles

    def stix2_get_embedded_objects(self, item) -> dict:
        """gets created and marking refs for a stix2 item

        :param item: valid stix2 item
        :type item:
        :return: returns a dict of created_by of object_marking_refs
        :rtype: dict
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
    def stix2_create_bundle(items):
        """create a stix2 bundle with items

        :param items: valid stix2 items
        :type items:
        :return: JSON of the stix2 bundle
        :rtype:
        """

        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.0",
            "objects": items,
        }
        return json.dumps(bundle)

    @staticmethod
    def check_max_tlp(tlp, max_tlp) -> bool:
        """check the allowed TLP levels for a TLP string

        :param tlp: string for TLP level to check
        :type tlp: str
        :param max_tlp: the highest allowed TLP level
        :type max_tlp: str
        :return: list of allowed TLP levels
        :rtype: bool
        """

        allowed_tlps = ["TLP:WHITE"]
        if max_tlp == "TLP:RED":
            allowed_tlps = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]
        elif max_tlp == "TLP:AMBER":
            allowed_tlps = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"]
        elif max_tlp == "TLP:GREEN":
            allowed_tlps = ["TLP:WHITE", "TLP:GREEN"]

        return tlp in allowed_tlps
