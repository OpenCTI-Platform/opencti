# coding: utf-8
import base64
import datetime
import io
import json
import logging
from typing import Union

import magic
import requests
import urllib3
from pythonjsonlogger import jsonlogger

from pycti.api import LOGGER
from pycti.api.opencti_api_connector import OpenCTIApiConnector
from pycti.api.opencti_api_work import OpenCTIApiWork
from pycti.entities.opencti_attack_pattern import AttackPattern
from pycti.entities.opencti_campaign import Campaign
from pycti.entities.opencti_case import Case
from pycti.entities.opencti_channel import Channel
from pycti.entities.opencti_course_of_action import CourseOfAction
from pycti.entities.opencti_data_component import DataComponent
from pycti.entities.opencti_data_source import DataSource
from pycti.entities.opencti_event import Event
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_grouping import Grouping
from pycti.entities.opencti_identity import Identity
from pycti.entities.opencti_incident import Incident
from pycti.entities.opencti_indicator import Indicator
from pycti.entities.opencti_infrastructure import Infrastructure
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_kill_chain_phase import KillChainPhase
from pycti.entities.opencti_label import Label
from pycti.entities.opencti_language import Language
from pycti.entities.opencti_location import Location
from pycti.entities.opencti_malware import Malware
from pycti.entities.opencti_marking_definition import MarkingDefinition
from pycti.entities.opencti_narrative import Narrative
from pycti.entities.opencti_note import Note
from pycti.entities.opencti_observed_data import ObservedData
from pycti.entities.opencti_opinion import Opinion
from pycti.entities.opencti_report import Report
from pycti.entities.opencti_stix import Stix
from pycti.entities.opencti_stix_core_object import StixCoreObject
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_cyber_observable_relationship import (
    StixCyberObservableRelationship,
)
from pycti.entities.opencti_stix_domain_object import StixDomainObject
from pycti.entities.opencti_stix_object_or_stix_relationship import (
    StixObjectOrStixRelationship,
)
from pycti.entities.opencti_stix_sighting_relationship import StixSightingRelationship
from pycti.entities.opencti_threat_actor import ThreatActor
from pycti.entities.opencti_tool import Tool
from pycti.entities.opencti_vocabulary import Vocabulary
from pycti.entities.opencti_vulnerability import Vulnerability
from pycti.utils.opencti_stix2 import OpenCTIStix2
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get("timestamp"):
            # This doesn't use record.created, so it is slightly off
            now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            log_record["timestamp"] = now
        if log_record.get("level"):
            log_record["level"] = log_record["level"].upper()
        else:
            log_record["level"] = record.levelname


class File:
    def __init__(self, name, data, mime="text/plain"):
        self.name = name
        self.data = data
        self.mime = mime


class OpenCTIApiClient:
    """Main API client for OpenCTI

    :param url: OpenCTI API url
    :type url: str
    :param token: OpenCTI API token
    :type token: str
    :param log_level: log level for the client
    :type log_level: str, optional
    :param ssl_verify:
    :type ssl_verify: bool, optional
    :param proxies:
    :type proxies: dict, optional, The proxy configuration, would have `http` and `https` attributes. Defaults to {}
        ```
        proxies: {
            "http: "http://my_proxy:8080"
            "https: "http://my_proxy:8080"
        }
        ```
    :param json_logging: format the logs as json if set to True
    :type json_logging: bool, optional
    """

    def __init__(
        self,
        url,
        token,
        log_level="info",
        ssl_verify=False,
        proxies=None,
        json_logging=False,
    ):
        """Constructor method"""

        # Check configuration
        self.ssl_verify = ssl_verify
        self.proxies = proxies
        if url is None or len(url) == 0:
            raise ValueError("An URL must be set")
        if token is None or len(token) == 0 or token == "ChangeMe":
            raise ValueError("A TOKEN must be set")

        # Configure logger
        log_level = log_level.upper()
        LOGGER.setLevel(log_level)

        if json_logging:
            log_handler = logging.StreamHandler()
            log_handler.setLevel(log_level)
            formatter = CustomJsonFormatter(
                "%(timestamp)s %(level)s %(name)s %(message)s"
            )
            log_handler.setFormatter(formatter)
            logging.basicConfig(handlers=[log_handler], level=log_level, force=True)
        else:
            logging.basicConfig(level=log_level)

        # Define API
        self.api_token = token
        self.api_url = url + "/graphql"
        self.request_headers = {"Authorization": "Bearer " + token}
        self.session = requests.session()

        # Define the dependencies
        self.work = OpenCTIApiWork(self)
        self.connector = OpenCTIApiConnector(self)
        self.stix2 = OpenCTIStix2(self)

        # Define the entities
        self.vocabulary = Vocabulary(self)
        self.label = Label(self)
        self.marking_definition = MarkingDefinition(self)
        self.external_reference = ExternalReference(self, File)
        self.kill_chain_phase = KillChainPhase(self)
        self.opencti_stix_object_or_stix_relationship = StixObjectOrStixRelationship(
            self
        )
        self.stix = Stix(self)
        self.stix_domain_object = StixDomainObject(self, File)
        self.stix_core_object = StixCoreObject(self, File)
        self.stix_cyber_observable = StixCyberObservable(self, File)
        self.stix_core_relationship = StixCoreRelationship(self)
        self.stix_sighting_relationship = StixSightingRelationship(self)
        self.stix_cyber_observable_relationship = StixCyberObservableRelationship(self)
        self.identity = Identity(self)
        self.event = Event(self)
        self.location = Location(self)
        self.threat_actor = ThreatActor(self)
        self.intrusion_set = IntrusionSet(self)
        self.infrastructure = Infrastructure(self)
        self.campaign = Campaign(self)
        self.case = Case(self)
        self.incident = Incident(self)
        self.malware = Malware(self)
        self.tool = Tool(self)
        self.channel = Channel(self)
        self.narrative = Narrative(self)
        self.language = Language(self)
        self.vulnerability = Vulnerability(self)
        self.attack_pattern = AttackPattern(self)
        self.course_of_action = CourseOfAction(self)
        self.data_component = DataComponent(self)
        self.data_source = DataSource(self)
        self.report = Report(self)
        self.note = Note(self)
        self.observed_data = ObservedData(self)
        self.opinion = Opinion(self)
        self.grouping = Grouping(self)
        self.indicator = Indicator(self)

        # Check if openCTI is available
        if not self.health_check():
            raise ValueError(
                "OpenCTI API is not reachable. Waiting for OpenCTI API to start or check your configuration..."
            )

    def set_applicant_id_header(self, applicant_id):
        self.request_headers["opencti-applicant-id"] = applicant_id

    def set_retry_number(self, retry_number):
        self.request_headers["opencti-retry-number"] = (
            "" if retry_number is None else str(retry_number)
        )

    def query(self, query, variables={}):
        """submit a query to the OpenCTI GraphQL API

        :param query: GraphQL query string
        :type query: str
        :param variables: GraphQL query variables, defaults to {}
        :type variables: dict, optional
        :return: returns the response json content
        :rtype: Any
        """

        query_var = {}
        files_vars = []
        # Implementation of spec https://github.com/jaydenseric/graphql-multipart-request-spec
        # Support for single or multiple upload
        # Batching or mixed upload or not supported
        var_keys = variables.keys()
        for key in var_keys:
            val = variables[key]
            is_file = type(val) is File
            is_files = (
                isinstance(val, list)
                and len(val) > 0
                and all(map(lambda x: isinstance(x, File), val))
            )
            if is_file or is_files:
                files_vars.append({"key": key, "file": val, "multiple": is_files})
                query_var[key] = None if is_file else [None] * len(val)
            else:
                query_var[key] = val

        # If yes, transform variable (file to null) and create multipart query
        if len(files_vars) > 0:
            multipart_data = {
                "operations": json.dumps({"query": query, "variables": query_var})
            }
            # Build the multipart map
            map_index = 0
            file_vars = {}
            for file_var_item in files_vars:
                is_multiple_files = file_var_item["multiple"]
                var_name = "variables." + file_var_item["key"]
                if is_multiple_files:
                    # [(var_name + "." + i)] if is_multiple_files else
                    for _ in file_var_item["file"]:
                        file_vars[str(map_index)] = [(var_name + "." + str(map_index))]
                        map_index += 1
                else:
                    file_vars[str(map_index)] = [var_name]
                    map_index += 1
            multipart_data["map"] = json.dumps(file_vars)
            # Add the files
            file_index = 0
            multipart_files = []
            for file_var_item in files_vars:
                files = file_var_item["file"]
                is_multiple_files = file_var_item["multiple"]
                if is_multiple_files:
                    for file in files:
                        if isinstance(file.data, str):
                            file_multi = (
                                str(file_index),
                                (
                                    file.name,
                                    io.BytesIO(file.data.encode("utf-8", "replace")),
                                    file.mime,
                                ),
                            )
                        else:
                            file_multi = (
                                str(file_index),
                                (file.name, file.data, file.mime),
                            )
                        multipart_files.append(file_multi)
                        file_index += 1
                else:
                    if isinstance(files.data, str):
                        file_multi = (
                            str(file_index),
                            (
                                files.name,
                                io.BytesIO(files.data.encode("utf-8", "replace")),
                                files.mime,
                            ),
                        )
                    else:
                        file_multi = (
                            str(file_index),
                            (files.name, files.data, files.mime),
                        )
                    multipart_files.append(file_multi)
                    file_index += 1
            # Send the multipart request
            r = self.session.post(
                self.api_url,
                data=multipart_data,
                files=multipart_files,
                headers=self.request_headers,
                verify=self.ssl_verify,
                proxies=self.proxies,
            )
        # If no
        else:
            r = self.session.post(
                self.api_url,
                json={"query": query, "variables": variables},
                headers=self.request_headers,
                verify=self.ssl_verify,
                proxies=self.proxies,
            )
        # Build response
        if r.status_code == 200:
            result = r.json()
            if "errors" in result:
                main_error = result["errors"][0]
                error_name = (
                    main_error["name"]
                    if "name" in main_error
                    else main_error["message"]
                )
                if "data" in main_error and "reason" in main_error["data"]:
                    LOGGER.error(main_error["data"]["reason"])
                    raise ValueError(
                        {"name": error_name, "message": main_error["data"]["reason"]}
                    )
                else:
                    LOGGER.error(main_error["message"])
                    raise ValueError(
                        {"name": error_name, "message": main_error["message"]}
                    )
            else:
                return result
        else:
            LOGGER.info(r.text)
            raise ValueError(r.text)

    def fetch_opencti_file(self, fetch_uri, binary=False, serialize=False):
        """get file from the OpenCTI API

        :param fetch_uri: download URI to use
        :type fetch_uri: str
        :param binary: [description], defaults to False
        :type binary: bool, optional
        :return: returns either the file content as text or bytes based on `binary`
        :rtype: str or bytes
        """

        r = self.session.get(fetch_uri, headers=self.request_headers)
        if binary:
            if serialize:
                return base64.b64encode(r.content).decode("utf-8")
            return r.content
        if serialize:
            return base64.b64encode(r.text).decode("utf-8")
        return r.text

    def log(self, level, message):
        """log a message with defined log level
        :param level: must be a valid logging log level (debug, info, warning, error)
        :type level: str
        :param message: the message to log
        :type message: str
        """

        if level == "debug":
            LOGGER.debug(message)
        elif level == "info":
            LOGGER.info(message)
        elif level == "warning":
            LOGGER.warning(message)
        elif level == "error":
            LOGGER.error(message)

    def health_check(self):
        """submit an example request to the OpenCTI API.

        :return: returns `True` if the health check has been successful
        :rtype: bool
        """
        try:
            test = self.threat_actor.list(first=1)
            if test is not None:
                return True
        except:
            return False
        return False

    def get_logs_worker_config(self):
        """get the logsWorkerConfig

        return: the logsWorkerConfig
        rtype: dict
        """

        LOGGER.info("Getting logs worker config...")
        query = """
            query LogsWorkerConfig {
                logsWorkerConfig {
                    elasticsearch_url
                    elasticsearch_proxy
                    elasticsearch_index
                    elasticsearch_username
                    elasticsearch_password
                    elasticsearch_api_key
                    elasticsearch_ssl_reject_unauthorized
                }
            }
        """
        result = self.query(query)
        return result["data"]["logsWorkerConfig"]

    def not_empty(self, value):
        """check if a value is empty for str, list and int

        :param value: value to check
        :type value: str or list or int or float or bool or datetime.date
        :return: returns `True` if the value is one of the supported types and not empty
        :rtype: bool
        """

        if value is not None:
            if isinstance(value, bool):
                return True
            if isinstance(value, datetime.date):
                return True
            if isinstance(value, str):
                if len(value) > 0:
                    return True
                else:
                    return False
            if isinstance(value, dict):
                return bool(value)
            if isinstance(value, list):
                is_not_empty = False
                for v in value:
                    if len(v) > 0:
                        is_not_empty = True
                return is_not_empty
            if isinstance(value, float):
                return True
            if isinstance(value, int):
                return True
            else:
                return False
        else:
            return False

    def process_multiple(self, data: dict, with_pagination=False) -> Union[dict, list]:
        """processes data returned by the OpenCTI API with multiple entities

        :param data: data to process
        :param with_pagination: whether to use pagination with the API
        :returns: returns either a dict or list with the processes entities
        """

        if with_pagination:
            result = {"entities": [], "pagination": {}}
        else:
            result = []
        if data is None:
            return result
        for edge in (
            data["edges"] if "edges" in data and data["edges"] is not None else []
        ):
            row = edge["node"]
            if with_pagination:
                result["entities"].append(self.process_multiple_fields(row))
            else:
                result.append(self.process_multiple_fields(row))
        if with_pagination and "pageInfo" in data:
            result["pagination"] = data["pageInfo"]
        return result

    def process_multiple_ids(self, data) -> list:
        """processes data returned by the OpenCTI API with multiple ids

        :param data: data to process
        :return: returns a list of ids
        """

        result = []
        if data is None:
            return result
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict) and "id" in d:
                    result.append(d["id"])
        return result

    def process_multiple_fields(self, data):
        """processes data returned by the OpenCTI API with multiple fields

        :param data: data to process
        :type data: dict
        :return: returns the data dict with all fields processed
        :rtype: dict
        """

        # Handle process_multiple_fields specific case
        attribute = OpenCTIStix2Utils.retrieveClassForMethod(
            self, data, "entity_type", "process_multiple_fields"
        )
        if attribute is not None:
            data = attribute.process_multiple_fields(data)

        if data is None:
            return data
        if "createdBy" in data and data["createdBy"] is not None:
            data["createdById"] = data["createdBy"]["id"]
            if "objectMarking" in data["createdBy"]:
                data["createdBy"]["objectMarking"] = self.process_multiple(
                    data["createdBy"]["objectMarking"]
                )
                data["createdBy"]["objectMarkingIds"] = self.process_multiple_ids(
                    data["createdBy"]["objectMarking"]
                )
            if "objectLabel" in data["createdBy"]:
                data["createdBy"]["objectLabel"] = self.process_multiple(
                    data["createdBy"]["objectLabel"]
                )
                data["createdBy"]["objectLabelIds"] = self.process_multiple_ids(
                    data["createdBy"]["objectLabel"]
                )
        else:
            data["createdById"] = None
        if "objectMarking" in data:
            data["objectMarking"] = self.process_multiple(data["objectMarking"])
            data["objectMarkingIds"] = self.process_multiple_ids(data["objectMarking"])
        if "objectLabel" in data:
            data["objectLabel"] = self.process_multiple(data["objectLabel"])
            data["objectLabelIds"] = self.process_multiple_ids(data["objectLabel"])
        if "reports" in data:
            data["reports"] = self.process_multiple(data["reports"])
            data["reportsIds"] = self.process_multiple_ids(data["reports"])
        if "notes" in data:
            data["notes"] = self.process_multiple(data["notes"])
            data["notesIds"] = self.process_multiple_ids(data["notes"])
        if "opinions" in data:
            data["opinions"] = self.process_multiple(data["opinions"])
            data["opinionsIds"] = self.process_multiple_ids(data["opinions"])
        if "observedData" in data:
            data["observedData"] = self.process_multiple(data["observedData"])
            data["observedDataIds"] = self.process_multiple_ids(data["observedData"])
        if "killChainPhases" in data:
            data["killChainPhases"] = self.process_multiple(data["killChainPhases"])
            data["killChainPhasesIds"] = self.process_multiple_ids(
                data["killChainPhases"]
            )
        if "externalReferences" in data:
            data["externalReferences"] = self.process_multiple(
                data["externalReferences"]
            )
            data["externalReferencesIds"] = self.process_multiple_ids(
                data["externalReferences"]
            )
        if "objects" in data:
            data["objects"] = self.process_multiple(data["objects"])
            data["objectsIds"] = self.process_multiple_ids(data["objects"])
        if "observables" in data:
            data["observables"] = self.process_multiple(data["observables"])
            data["observablesIds"] = self.process_multiple_ids(data["observables"])
        if "stixCoreRelationships" in data:
            data["stixCoreRelationships"] = self.process_multiple(
                data["stixCoreRelationships"]
            )
            data["stixCoreRelationshipsIds"] = self.process_multiple_ids(
                data["stixCoreRelationships"]
            )
        if "indicators" in data:
            data["indicators"] = self.process_multiple(data["indicators"])
            data["indicatorsIds"] = self.process_multiple_ids(data["indicators"])
        if "importFiles" in data:
            data["importFiles"] = self.process_multiple(data["importFiles"])
            data["importFilesIds"] = self.process_multiple_ids(data["importFiles"])
        # See aliases of GraphQL query in stix_core_object method
        if "name_alt" in data:
            data["name"] = data["name_alt"]
            del data["name_alt"]
        if "content_alt" in data:
            data["content"] = data["content_alt"]
            del data["content_alt"]
        return data

    def upload_file(self, **kwargs):
        """upload a file to OpenCTI API

        :param `**kwargs`: arguments for file upload (required: `file_name` and `data`)
        :return: returns the query respons for the file upload
        :rtype: dict
        """

        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        if file_name is not None:
            LOGGER.info("Uploading a file.")
            query = """
                mutation UploadImport($file: Upload!) {
                    uploadImport(file: $file) {
                        id
                        name
                    }
                }
             """
            if data is None:
                data = open(file_name, "rb")
                if file_name.endswith(".json"):
                    mime_type = "application/json"
                else:
                    mime_type = magic.from_file(file_name, mime=True)

            return self.query(query, {"file": (File(file_name, data, mime_type))})
        else:
            LOGGER.error("[upload] Missing parameter: file_name")
            return None

    def upload_pending_file(self, **kwargs):
        """upload a file to OpenCTI API

        :param `**kwargs`: arguments for file upload (required: `file_name` and `data`)
        :return: returns the query response for the file upload
        :rtype: dict
        """

        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        entity_id = kwargs.get("entity_id", None)

        if file_name is not None:
            LOGGER.info("Uploading a file.")
            query = """
                    mutation UploadPending($file: Upload!, $entityId: String) {
                        uploadPending(file: $file, entityId: $entityId) {
                            id
                            name
                        }
                    }
                 """
            if data is None:
                data = open(file_name, "rb")
                if file_name.endswith(".json"):
                    mime_type = "application/json"
                else:
                    mime_type = magic.from_file(file_name, mime=True)
            return self.query(
                query,
                {"file": (File(file_name, data, mime_type)), "entityId": entity_id},
            )
        else:
            LOGGER.error("[upload] Missing parameter: file_name")
            return None

    def get_stix_content(self, id):
        """get the STIX content of any entity

        return: the STIX content in JSON
        rtype: dict
        """

        LOGGER.info("Entity in JSON %s", id)
        query = """
            query StixQuery($id: String!) {
                stix(id: $id)
            }
        """
        result = self.query(query, {"id": id})
        return json.loads(result["data"]["stix"])

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
