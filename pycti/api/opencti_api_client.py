# coding: utf-8
import base64
import datetime
import io
import json
from typing import Dict, Tuple, Union

import magic
import requests

from pycti import __version__
from pycti.api.opencti_api_connector import OpenCTIApiConnector
from pycti.api.opencti_api_playbook import OpenCTIApiPlaybook
from pycti.api.opencti_api_work import OpenCTIApiWork
from pycti.entities.opencti_attack_pattern import AttackPattern
from pycti.entities.opencti_campaign import Campaign
from pycti.entities.opencti_capability import Capability
from pycti.entities.opencti_case_incident import CaseIncident
from pycti.entities.opencti_case_rfi import CaseRfi
from pycti.entities.opencti_case_rft import CaseRft
from pycti.entities.opencti_channel import Channel
from pycti.entities.opencti_course_of_action import CourseOfAction
from pycti.entities.opencti_data_component import DataComponent
from pycti.entities.opencti_data_source import DataSource
from pycti.entities.opencti_event import Event
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_feedback import Feedback
from pycti.entities.opencti_group import Group
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
from pycti.entities.opencti_malware_analysis import MalwareAnalysis
from pycti.entities.opencti_marking_definition import MarkingDefinition
from pycti.entities.opencti_narrative import Narrative
from pycti.entities.opencti_note import Note
from pycti.entities.opencti_observed_data import ObservedData
from pycti.entities.opencti_opinion import Opinion
from pycti.entities.opencti_report import Report
from pycti.entities.opencti_role import Role
from pycti.entities.opencti_settings import Settings
from pycti.entities.opencti_stix import Stix
from pycti.entities.opencti_stix_core_object import StixCoreObject
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_domain_object import StixDomainObject
from pycti.entities.opencti_stix_nested_ref_relationship import (
    StixNestedRefRelationship,
)
from pycti.entities.opencti_stix_object_or_stix_relationship import (
    StixObjectOrStixRelationship,
)
from pycti.entities.opencti_stix_sighting_relationship import StixSightingRelationship
from pycti.entities.opencti_task import Task
from pycti.entities.opencti_threat_actor import ThreatActor
from pycti.entities.opencti_threat_actor_group import ThreatActorGroup
from pycti.entities.opencti_threat_actor_individual import ThreatActorIndividual
from pycti.entities.opencti_tool import Tool
from pycti.entities.opencti_user import User
from pycti.entities.opencti_vocabulary import Vocabulary
from pycti.entities.opencti_vulnerability import Vulnerability
from pycti.utils.opencti_logger import logger
from pycti.utils.opencti_stix2 import OpenCTIStix2
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


def build_request_headers(token: str, custom_headers: str, app_logger):
    headers_dict = {
        "User-Agent": "pycti/" + __version__,
        "Authorization": "Bearer " + token,
    }
    # Build and add custom headers
    if custom_headers is not None:
        for header_pair in custom_headers.strip().split(";"):
            if header_pair:  # Skip empty header pairs
                try:
                    key, value = header_pair.split(":", 1)
                    headers_dict[key.strip()] = value.strip()
                except ValueError:
                    app_logger.warning(
                        "Ignored invalid header pair", {"header_pair": header_pair}
                    )
    return headers_dict


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
    :param ssl_verify: Requiring the requests to verify the TLS certificate at the server.
    :type ssl_verify: bool, str, optional
    :param proxies:
    :type proxies: dict, optional, The proxy configuration, would have `http` and `https` attributes. Defaults to {}
        ```
        proxies: {
            "http": "http://my_proxy:8080"
            "https": "http://my_proxy:8080"
        }
        ```
    :param json_logging: format the logs as json if set to True
    :type json_logging: bool, optional
    :param bundle_send_to_queue: if bundle will be sent to queue
    :type bundle_send_to_queue: bool, optional
    :param cert: If String, file path to pem file. If Tuple, a ('path_to_cert.crt', 'path_to_key.key') pair representing the certificate and the key.
    :type cert: str, tuple, optional
    :param custom_headers: Add custom headers to use with the graphql queries
    :type custom_headers: str, optional must in the format header01:value;header02:value
    :param perform_health_check: if client init must check the api access
    :type perform_health_check: bool, optional
    """

    def __init__(
        self,
        url: str,
        token: str,
        log_level: str = "info",
        ssl_verify: Union[bool, str] = False,
        proxies: Union[Dict[str, str], None] = None,
        json_logging: bool = False,
        bundle_send_to_queue: bool = True,
        cert: Union[str, Tuple[str, str], None] = None,
        custom_headers: str = None,
        perform_health_check: bool = True,
    ):
        """Constructor method"""

        # Check configuration
        self.bundle_send_to_queue = bundle_send_to_queue
        self.ssl_verify = ssl_verify
        self.cert = cert
        self.proxies = proxies
        if url is None or len(url) == 0:
            raise ValueError("An URL must be set")
        if token is None or len(token) == 0 or token == "ChangeMe":
            raise ValueError("A TOKEN must be set")

        # Configure logger
        self.logger_class = logger(log_level.upper(), json_logging)
        self.app_logger = self.logger_class("api")
        self.admin_logger = self.logger_class("admin")

        # Define API
        self.api_token = token
        self.api_url = url + "/graphql"
        self.request_headers = build_request_headers(
            token, custom_headers, self.app_logger
        )
        self.session = requests.session()
        # Define the dependencies
        self.work = OpenCTIApiWork(self)
        self.playbook = OpenCTIApiPlaybook(self)
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
        self.stix_nested_ref_relationship = StixNestedRefRelationship(self)
        self.identity = Identity(self)
        self.event = Event(self)
        self.location = Location(self)
        self.threat_actor = ThreatActor(self)
        self.threat_actor_group = ThreatActorGroup(self)
        self.threat_actor_individual = ThreatActorIndividual(self)
        self.intrusion_set = IntrusionSet(self)
        self.infrastructure = Infrastructure(self)
        self.campaign = Campaign(self)
        self.case_incident = CaseIncident(self)
        self.feedback = Feedback(self)
        self.case_rfi = CaseRfi(self)
        self.case_rft = CaseRft(self)
        self.task = Task(self)
        self.incident = Incident(self)
        self.malware = Malware(self)
        self.malware_analysis = MalwareAnalysis(self)
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

        # Admin functionality
        self.capability = Capability(self)
        self.role = Role(self)
        self.group = Group(self)
        self.user = User(self)
        self.settings = Settings(self)

        # Check if openCTI is available
        if perform_health_check and not self.health_check():
            raise ValueError(
                "OpenCTI API is not reachable. Waiting for OpenCTI API to start or check your configuration..."
            )

    def set_applicant_id_header(self, applicant_id):
        self.request_headers["opencti-applicant-id"] = applicant_id

    def set_playbook_id_header(self, playbook_id):
        self.request_headers["opencti-playbook-id"] = playbook_id

    def set_event_id(self, event_id):
        self.request_headers["opencti-event-id"] = event_id

    def set_draft_id(self, draft_id):
        self.request_headers["opencti-draft-id"] = draft_id

    def set_synchronized_upsert_header(self, synchronized):
        self.request_headers["synchronized-upsert"] = (
            "true" if synchronized is True else "false"
        )

    def set_previous_standard_header(self, previous_standard):
        self.request_headers["previous-standard"] = previous_standard

    def get_request_headers(self, hide_token=True):
        request_headers_copy = self.request_headers.copy()
        if hide_token and "Authorization" in request_headers_copy:
            request_headers_copy["Authorization"] = "*****"
        return request_headers_copy

    def set_retry_number(self, retry_number):
        self.request_headers["opencti-retry-number"] = (
            "" if retry_number is None else str(retry_number)
        )

    def query(self, query, variables=None):
        """submit a query to the OpenCTI GraphQL API

        :param query: GraphQL query string
        :type query: str
        :param variables: GraphQL query variables, defaults to {}
        :type variables: dict, optional
        :return: returns the response json content
        :rtype: Any
        """
        variables = variables or {}
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
                        file_vars[str(map_index)] = [var_name + "." + str(map_index)]
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
                cert=self.cert,
                proxies=self.proxies,
                timeout=300,
            )
        # If no
        else:
            r = self.session.post(
                self.api_url,
                json={"query": query, "variables": variables},
                headers=self.request_headers,
                verify=self.ssl_verify,
                cert=self.cert,
                proxies=self.proxies,
                timeout=300,
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
                error_detail = {
                    "name": error_name,
                    "error_message": main_error["message"],
                }
                meta_data = main_error["data"] if "data" in main_error else {}
                # Prevent logging of input as bundle is logged differently
                if meta_data.get("input") is not None:
                    del meta_data["input"]
                value_error = {**error_detail, **meta_data}
                raise ValueError(value_error)
            else:
                return result
        else:
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

        r = self.session.get(
            fetch_uri,
            headers=self.request_headers,
            verify=self.ssl_verify,
            cert=self.cert,
            proxies=self.proxies,
            timeout=300,
        )
        if binary:
            if serialize:
                return base64.b64encode(r.content).decode("utf-8")
            return r.content
        if serialize:
            return base64.b64encode(r.text).decode("utf-8")
        return r.text

    def health_check(self):
        """submit an example request to the OpenCTI API.

        :return: returns `True` if the health check has been successful
        :rtype: bool
        """
        try:
            self.app_logger.info("Health check (platform version)...")
            test = self.query(
                """
                  query healthCheck {
                    about {
                      version
                    }
                  }
                """
            )
            if test is not None:
                return True
        except Exception as err:  # pylint: disable=broad-except
            self.app_logger.error(str(err))
            return False
        return False

    def get_logs_worker_config(self):
        """get the logsWorkerConfig

        return: the logsWorkerConfig
        rtype: dict
        """

        self.app_logger.info("Getting logs worker config...")
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

        # Data can be multiple in edges or directly.
        # -- When data is directly a listing
        if isinstance(data, list):
            for row in data:
                if with_pagination:
                    result["entities"].append(self.process_multiple_fields(row))
                else:
                    result.append(self.process_multiple_fields(row))
            return result

        # -- When data is wrapper in edges
        for edge in (
            data["edges"] if "edges" in data and data["edges"] is not None else []
        ):
            row = edge["node"]
            if with_pagination:
                result["entities"].append(self.process_multiple_fields(row))
            else:
                result.append(self.process_multiple_fields(row))

        # -- Add page info if required
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
        :return: returns the query response for the file upload
        :rtype: dict
        """

        file_name = kwargs.get("file_name", None)
        file_markings = kwargs.get("file_markings", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        if file_name is not None:
            self.app_logger.info("Uploading a file.")
            query = """
                mutation UploadImport($file: Upload!, $fileMarkings: [String]) {
                    uploadImport(file: $file, fileMarkings: $fileMarkings) {
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
            query_vars = {"file": (File(file_name, data, mime_type))}
            # optional file markings
            if file_markings is not None:
                query_vars["fileMarkings"] = file_markings
            return self.query(query, query_vars)
        else:
            self.app_logger.error("[upload] Missing parameter: file_name")
            return None

    def create_draft(self, **kwargs):
        """create a draft in OpenCTI API
        :param `**kwargs`: arguments for file name creating draft (required: `draft_name`)
        :return: returns the query response for the draft creation
        :rtype: id
        """

        draft_name = kwargs.get("draft_name", None)
        entity_id = kwargs.get("entity_id", None)

        if draft_name is not None:
            self.app_logger.info("Creating a draft.")
            query = """
                    mutation draftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
                        draftWorkspaceAdd(input: $input) {
                            id
                        }
                    }
                 """
            queryResult = self.query(
                query,
                {"input": {"name": draft_name, "entity_id": entity_id}},
            )
            return queryResult["data"]["draftWorkspaceAdd"]["id"]
        else:
            self.app_logger.error("[create_draft] Missing parameter: draft_name")
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
        file_markings = kwargs.get("file_markings", [])

        if file_name is not None:
            self.app_logger.info("Uploading a file.")
            query = """
                    mutation UploadPending($file: Upload!, $entityId: String, $file_markings: [String!]) {
                        uploadPending(file: $file, entityId: $entityId, file_markings: $file_markings) {
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
                {
                    "file": (File(file_name, data, mime_type)),
                    "entityId": entity_id,
                    "file_markings": file_markings,
                },
            )
        else:
            self.app_logger.error("[upload] Missing parameter: file_name")
            return None

    def send_bundle_to_api(self, **kwargs):
        """Push a bundle to a queue through OpenCTI API

        :param `**kwargs`: arguments for bundle push (required: `connectorId` and `bundle`)
        :return: returns the query response for the bundle push
        :rtype: dict
        """

        connector_id = kwargs.get("connector_id", None)
        work_id = kwargs.get("work_id", None)
        bundle = kwargs.get("bundle", None)

        if connector_id is not None and bundle is not None:
            self.app_logger.info(
                "Pushing a bundle to queue through API", {connector_id}
            )
            mutation = """
                    mutation StixBundlePush($connectorId: String!, $bundle: String!, $work_id: String) {
                        stixBundlePush(connectorId: $connectorId, bundle: $bundle, work_id: $work_id)
                    }
                 """
            return self.query(
                mutation,
                {"connectorId": connector_id, "bundle": bundle, "work_id": work_id},
            )
        else:
            self.app_logger.error(
                "[bundle push] Missing parameter: connector_id or bundle"
            )
            return None

    def get_stix_content(self, id):
        """get the STIX content of any entity

        return: the STIX content in JSON
        rtype: dict
        """

        self.app_logger.info("Entity in JSON", {"id": id})
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
