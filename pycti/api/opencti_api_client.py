# coding: utf-8

import io
import magic
import requests
import urllib3
import json
import logging

from typing import Union

from pycti.api.opencti_api_connector import OpenCTIApiConnector
from pycti.api.opencti_api_job import OpenCTIApiJob
from pycti.utils.constants import ObservableTypes
from pycti.utils.opencti_stix2 import OpenCTIStix2

from pycti.entities.opencti_tag import Tag
from pycti.entities.opencti_marking_definition import MarkingDefinition
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_kill_chain_phase import KillChainPhase
from pycti.entities.opencti_stix_entity import StixEntity
from pycti.entities.opencti_stix_domain_entity import StixDomainEntity
from pycti.entities.opencti_stix_observable import StixObservable
from pycti.entities.opencti_stix_relation import StixRelation
from pycti.entities.opencti_stix_sighting import StixSighting
from pycti.entities.opencti_stix_observable_relation import StixObservableRelation
from pycti.entities.opencti_identity import Identity
from pycti.entities.opencti_threat_actor import ThreatActor
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_campaign import Campaign
from pycti.entities.opencti_incident import Incident
from pycti.entities.opencti_malware import Malware
from pycti.entities.opencti_tool import Tool
from pycti.entities.opencti_vulnerability import Vulnerability
from pycti.entities.opencti_attack_pattern import AttackPattern
from pycti.entities.opencti_course_of_action import CourseOfAction
from pycti.entities.opencti_report import Report
from pycti.entities.opencti_note import Note
from pycti.entities.opencti_opinion import Opinion
from pycti.entities.opencti_indicator import Indicator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    """

    def __init__(self, url, token, log_level="info", ssl_verify=False):
        """Constructor method
        """

        # Check configuration
        self.ssl_verify = ssl_verify
        if url is None or len(token) == 0:
            raise ValueError("Url configuration must be configured")
        if token is None or len(token) == 0 or token == "ChangeMe":
            raise ValueError(
                "Token configuration must be the same as APP__ADMIN__TOKEN"
            )

        # Configure logger
        self.log_level = log_level
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError("Invalid log level: " + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Define API
        self.api_token = token
        self.api_url = url + "/graphql"
        self.request_headers = {"Authorization": "Bearer " + token}

        # Define the dependencies
        self.job = OpenCTIApiJob(self)
        self.connector = OpenCTIApiConnector(self)
        self.stix2 = OpenCTIStix2(self)

        # Define the entities
        self.tag = Tag(self)
        self.marking_definition = MarkingDefinition(self)
        self.external_reference = ExternalReference(self)
        self.kill_chain_phase = KillChainPhase(self)
        self.stix_entity = StixEntity(self)
        self.stix_domain_entity = StixDomainEntity(self, File)
        self.stix_observable = StixObservable(self)
        self.stix_relation = StixRelation(self)
        self.stix_sighting = StixSighting(self)
        self.stix_observable_relation = StixObservableRelation(self)
        self.identity = Identity(self)
        self.threat_actor = ThreatActor(self)
        self.intrusion_set = IntrusionSet(self)
        self.campaign = Campaign(self)
        self.incident = Incident(self)
        self.malware = Malware(self)
        self.tool = Tool(self)
        self.vulnerability = Vulnerability(self)
        self.attack_pattern = AttackPattern(self)
        self.course_of_action = CourseOfAction(self)
        self.report = Report(self)
        self.note = Note(self)
        self.opinion = Opinion(self)
        self.indicator = Indicator(self)

        # Check if openCTI is available
        if not self.health_check():
            raise ValueError(
                "OpenCTI API is not reachable. Waiting for OpenCTI API to start or check your configuration..."
            )

    def get_token(self):
        """Get the API token

        :return: returns the configured API token
        :rtype: str
        """

        return self.api_token

    def set_token(self, token):
        """set the request header with the specified token

        :param token: OpenCTI API token
        :type token: str
        """

        self.request_headers = {"Authorization": "Bearer " + token}

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
                                (file.name, io.BytesIO(file.data.encode()), file.mime,),
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
                            (files.name, io.BytesIO(files.data.encode()), files.mime),
                        )
                    else:
                        file_multi = (
                            str(file_index),
                            (files.name, files.data, files.mime),
                        )
                    multipart_files.append(file_multi)
                    file_index += 1
            # Send the multipart request
            r = requests.post(
                self.api_url,
                data=multipart_data,
                files=multipart_files,
                headers=self.request_headers,
                verify=self.ssl_verify,
            )
        # If no
        else:
            r = requests.post(
                self.api_url,
                json={"query": query, "variables": variables},
                headers=self.request_headers,
                verify=self.ssl_verify,
            )
        # Build response
        if r.status_code == 200:
            result = r.json()
            if "errors" in result:
                logging.error(result["errors"][0]["message"])
            else:
                return result
        else:
            logging.info(r.text)

    def fetch_opencti_file(self, fetch_uri, binary=False):
        """get file from the OpenCTI API

        :param fetch_uri: download URI to use
        :type fetch_uri: str
        :param binary: [description], defaults to False
        :type binary: bool, optional
        :return: returns either the file content as text or bytes based on `binary`
        :rtype: str or bytes
        """

        r = requests.get(fetch_uri, headers=self.request_headers)
        if binary:
            return r.content
        return r.text

    def log(self, level, message):
        """log a message with defined log level

        :param level: must be a valid logging log level (debug, info, warning, error)
        :type level: str
        :param message: the message to log
        :type message: str
        """

        if level == "debug":
            logging.debug(message)
        elif level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warn(message)
        elif level == "error":
            logging.error(message)

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

        logging.info("Getting logs worker config...")
        query = """
            query LogsWorkerConfig {
                logsWorkerConfig {
                    elasticsearch_url
                    elasticsearch_index
                    rabbitmq_url
                }
            }
        """
        result = self.query(query)
        return result["data"]["logsWorkerConfig"]

    def not_empty(self, value):
        """check if a value is empty for str, list and int

        :param value: value to check
        :type value: str or list or int
        :return: returns `True` if the value is one of the supported types and not empty
        :rtype: bool
        """

        if value is not None:
            if isinstance(value, str):
                if len(value) > 0:
                    return True
                else:
                    return False
            if isinstance(value, list):
                is_not_empty = False
                for v in value:
                    if len(v) > 0:
                        is_not_empty = True
                return is_not_empty
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
            # Handle remote relation ID
            if (
                "relation" in edge
                and edge["relation"] is not None
                and "id" in edge["relation"]
            ):
                row["remote_relation_id"] = edge["relation"]["id"]
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

        if data is None:
            return data
        if (
            "createdByRef" in data
            and data["createdByRef"] is not None
            and "node" in data["createdByRef"]
        ):
            row = data["createdByRef"]["node"]
            # Handle remote relation ID
            if "relation" in data["createdByRef"]:
                row["remote_relation_id"] = data["createdByRef"]["relation"]["id"]
            data["createdByRef"] = row
            data["createdByRefId"] = row["id"]
        else:
            data["createdByRef"] = None
            data["createdByRefId"] = None
        if "markingDefinitions" in data:
            data["markingDefinitions"] = self.process_multiple(
                data["markingDefinitions"]
            )
            data["markingDefinitionsIds"] = self.process_multiple_ids(
                data["markingDefinitions"]
            )
        if "tags" in data:
            data["tags"] = self.process_multiple(data["tags"])
            data["tagsIds"] = self.process_multiple_ids(data["tags"])
        if "reports" in data:
            data["reports"] = self.process_multiple(data["reports"])
            data["reportsIds"] = self.process_multiple_ids(data["reports"])
        if "notes" in data:
            data["notes"] = self.process_multiple(data["notes"])
            data["notesIds"] = self.process_multiple_ids(data["notes"])
        if "opinions" in data:
            data["opinions"] = self.process_multiple(data["opinions"])
            data["opinionsIds"] = self.process_multiple_ids(data["opinions"])
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
        if "objectRefs" in data:
            data["objectRefs"] = self.process_multiple(data["objectRefs"])
            data["objectRefsIds"] = self.process_multiple_ids(data["objectRefs"])
        if "observableRefs" in data:
            data["observableRefs"] = self.process_multiple(data["observableRefs"])
            data["observableRefsIds"] = self.process_multiple_ids(
                data["observableRefs"]
            )
        if "relationRefs" in data:
            data["relationRefs"] = self.process_multiple(data["relationRefs"])
            data["relationRefsIds"] = self.process_multiple_ids(data["relationRefs"])
        if "stixRelations" in data:
            data["stixRelations"] = self.process_multiple(data["stixRelations"])
            data["stixRelationsIds"] = self.process_multiple_ids(data["stixRelations"])
        if "indicators" in data:
            data["indicators"] = self.process_multiple(data["indicators"])
            data["indicatorsIds"] = self.process_multiple_ids(data["indicators"])
        if "importFiles" in data:
            data["importFiles"] = self.process_multiple(data["importFiles"])
            data["importFilesIds"] = self.process_multiple_ids(data["importFiles"])
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
            self.log("info", "Uploading a file.")
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
                mime_type = magic.from_file(file_name, mime=True)

            return self.query(query, {"file": (File(file_name, data, mime_type))})
        else:
            self.log(
                "error", "[upload] Missing parameters: file_name or data",
            )
            return None

    # TODO Move to StixObservable
    def update_stix_observable_field(self, id, key, value):
        logging.info("Updating field " + key + " of " + id + "...")
        query = """
            mutation StixObservableEdit($id: ID!, $input: EditInput!) {
                stixObservableEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        observable_value
                        entity_type
                    }
                }
            }
        """
        self.query(query, {"id": id, "input": {"key": key, "value": value}})

    # TODO Move to ExternalReference
    def delete_external_reference(self, id):
        logging.info("Deleting + " + id + "...")
        query = """
             mutation ExternalReferenceEdit($id: ID!) {
                 externalReferenceEdit(id: $id) {
                     delete
                 }
             }
         """
        self.query(query, {"id": id})

    # TODO Move to Vulnerability
    def create_vulnerability_if_not_exists(
        self,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.vulnerability.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    def resolve_role(self, relation_type, from_type, to_type):
        """resolves the role for a specified entity

        :param relation_type: input relation type
        :type relation_type: str
        :param from_type: entity type
        :type from_type: str
        :param to_type: entity type
        :type to_type: str
        :return: returns the role mapping
        :rtype: dict
        """

        if from_type == "stix-relation":
            from_type = "stix_relation"
        if to_type == "stix-relation":
            to_type = "stix_relation"
        if relation_type == "related-to":
            return {"from_role": "relate_from", "to_role": "relate_to"}

        relation_type = relation_type.lower()
        from_type = from_type.lower()
        from_type = (
            "observable"
            if (
                (
                    ObservableTypes.has_value(from_type)
                    and (
                        relation_type == "localization" or relation_type == "gathering"
                    )
                )
                or from_type == "stix-observable"
            )
            else from_type
        )
        to_type = to_type.lower()
        mapping = {
            "uses": {
                "threat-actor": {
                    "malware": {"from_role": "user", "to_role": "usage"},
                    "tool": {"from_role": "user", "to_role": "usage"},
                    "attack-pattern": {"from_role": "user", "to_role": "usage"},
                },
                "intrusion-set": {
                    "malware": {"from_role": "user", "to_role": "usage"},
                    "tool": {"from_role": "user", "to_role": "usage"},
                    "attack-pattern": {"from_role": "user", "to_role": "usage"},
                },
                "campaign": {
                    "malware": {"from_role": "user", "to_role": "usage"},
                    "tool": {"from_role": "user", "to_role": "usage"},
                    "attack-pattern": {"from_role": "user", "to_role": "usage"},
                },
                "incident": {
                    "malware": {"from_role": "user", "to_role": "usage"},
                    "tool": {"from_role": "user", "to_role": "usage"},
                    "attack-pattern": {"from_role": "user", "to_role": "usage"},
                },
                "malware": {
                    "tool": {"from_role": "user", "to_role": "usage"},
                    "attack-pattern": {"from_role": "user", "to_role": "usage"},
                },
                "tool": {"attack-pattern": {"from_role": "user", "to_role": "usage"}},
            },
            "variant-of": {
                "malware": {
                    "malware": {"from_role": "original", "to_role": "variation"},
                },
                "tool": {"tool": {"from_role": "original", "to_role": "variation"},},
            },
            "targets": {
                "threat-actor": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "user": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "intrusion-set": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "user": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "campaign": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "user": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "incident": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "user": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "malware": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "user": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "attack-pattern": {
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
            },
            "attributed-to": {
                "threat-actor": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "organization": {"from_role": "attribution", "to_role": "origin"},
                    "user": {"from_role": "attribution", "to_role": "origin"},
                },
                "intrusion-set": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "threat-actor": {"from_role": "attribution", "to_role": "origin"},
                },
                "campaign": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "threat-actor": {"from_role": "attribution", "to_role": "origin"},
                    "intrusion-set": {"from_role": "attribution", "to_role": "origin"},
                },
                "incident": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "threat-actor": {"from_role": "attribution", "to_role": "origin"},
                    "intrusion-set": {"from_role": "attribution", "to_role": "origin"},
                    "campaign": {"from_role": "attribution", "to_role": "origin"},
                },
                "malware": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "threat-actor": {"from_role": "attribution", "to_role": "origin"},
                },
            },
            "mitigates": {
                "course-of-action": {
                    "attack-pattern": {"from_role": "mitigation", "to_role": "problem"}
                }
            },
            "localization": {
                "threat-actor": {
                    "region": {"from_role": "localized", "to_role": "location"},
                    "country": {"from_role": "localized", "to_role": "location"},
                    "city": {"from_role": "localized", "to_role": "location"},
                },
                "observable": {
                    "region": {"from_role": "localized", "to_role": "location"},
                    "country": {"from_role": "localized", "to_role": "location"},
                    "city": {"from_role": "localized", "to_role": "location"},
                },
                "stix_relation": {
                    "region": {"from_role": "localized", "to_role": "location"},
                    "country": {"from_role": "localized", "to_role": "location"},
                    "city": {"from_role": "localized", "to_role": "location"},
                },
                "region": {"region": {"from_role": "localized", "to_role": "location"}},
                "country": {
                    "region": {"from_role": "localized", "to_role": "location"}
                },
                "city": {"country": {"from_role": "localized", "to_role": "location"}},
                "organization": {
                    "region": {"from_role": "localized", "to_role": "location"},
                    "country": {"from_role": "localized", "to_role": "location"},
                    "city": {"from_role": "localized", "to_role": "location"},
                },
            },
            "indicates": {
                "indicator": {
                    "threat-actor": {
                        "from_role": "indicator",
                        "to_role": "characterize",
                    },
                    "intrusion-set": {
                        "from_role": "indicator",
                        "to_role": "characterize",
                    },
                    "campaign": {"from_role": "indicator", "to_role": "characterize"},
                    "malware": {"from_role": "indicator", "to_role": "characterize"},
                    "tool": {"from_role": "indicator", "to_role": "characterize"},
                    "stix_relation": {
                        "from_role": "indicator",
                        "to_role": "characterize",
                    },
                }
            },
            "gathering": {
                "threat-actor": {
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "sector": {
                    "sector": {"from_role": "part_of", "to_role": "gather"},
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "organization": {
                    "sector": {"from_role": "part_of", "to_role": "gather"},
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "user": {
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "observable": {
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                    "user": {"from_role": "part_of", "to_role": "gather"},
                },
            },
            "drops": {
                "malware": {
                    "malware": {"from_role": "dropping", "to_role": "dropped"},
                    "tool": {"from_role": "dropping", "to_role": "dropped"},
                },
                "tool": {
                    "malware": {"from_role": "dropping", "to_role": "dropped"},
                    "tool": {"from_role": "dropping", "to_role": "dropped"},
                },
            },
            "belongs": {
                "ipv4-addr": {
                    "autonomous-system": {
                        "from_role": "belonging_to",
                        "to_role": "belonged_to",
                    }
                },
                "ipv6-addr": {
                    "autonomous-system": {
                        "from_role": "belonging_to",
                        "to_role": "belonged_to",
                    }
                },
            },
            "resolves": {
                "ipv4-addr": {
                    "domain": {"from_role": "resolving", "to_role": "resolved",}
                },
                "ipv6-addr": {
                    "domain": {"from_role": "resolving", "to_role": "resolved",}
                },
            },
            "corresponds": {
                "file-name": {
                    "file-md5": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha1": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha256": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                },
                "file-md5": {
                    "file-name": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha1": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha256": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                },
                "file-sha1": {
                    "file-name": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-md5": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha256": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                },
                "file-sha256": {
                    "file-name": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-md5": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                    "file-sha1": {
                        "from_role": "correspond_from",
                        "to_role": "correspond_to",
                    },
                },
            },
        }
        if (
            relation_type in mapping
            and from_type in mapping[relation_type]
            and to_type in mapping[relation_type][from_type]
        ):
            return mapping[relation_type][from_type][to_type]
        else:
            return None
