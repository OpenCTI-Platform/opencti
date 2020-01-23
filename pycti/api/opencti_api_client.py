# coding: utf-8

import io
import magic
from typing import List
from deprecated import deprecated

import requests
import urllib3
import datetime
import dateutil.parser
import json
import logging

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
from pycti.entities.opencti_indicator import Indicator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class File:
    def __init__(self, name, data, mime="text/plain"):
        self.name = name
        self.data = data
        self.mime = mime


class OpenCTIApiClient:
    """
        Python API for OpenCTI
        :param url: OpenCTI URL
        :param token: The API key
    """

    def __init__(self, url, token, log_level="info", ssl_verify=False):
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
        self.indicator = Indicator(self)

        # Check if openCTI is available
        if not self.health_check():
            raise ValueError("OpenCTI API seems down")

    def query(self, query, variables={}):
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
        if r.status_code == requests.codes.ok:
            result = r.json()
            if "errors" in result:
                logging.error(result["errors"][0]["message"])
            else:
                return result
        else:
            logging.info(r.text)

    def fetch_opencti_file(self, fetch_uri):
        r = requests.get(fetch_uri, headers=self.request_headers)
        return r.text

    def log(self, level, message):
        if level == "debug":
            logging.debug(message)
        elif level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warn(message)
        elif level == "error":
            logging.error(message)

    def health_check(self):
        try:
            test = self.threat_actor.list(first=1)
            if test is not None:
                return True
        except:
            return False
        return False

    def not_empty(self, value):
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
                        is_not_empty = False
                return is_not_empty
            if isinstance(value, int):
                return True
            else:
                return False
        else:
            return False

    def process_multiple(self, data):
        result = []
        if data is None:
            return result
        for edge in (
            data["edges"] if "edges" in data and data["edges"] is not None else []
        ):
            row = edge["node"]
            # Handle remote relation ID
            if "relation" in edge:
                row["remote_relation_id"] = edge["relation"]["id"]
            result.append(self.process_multiple_fields(row))
        return result

    def process_multiple_ids(self, data):
        result = []
        if data is None:
            return result
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict) and "id" in d:
                    result.append(d["id"])
        return result

    def process_multiple_fields(self, data):
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
        else:
            data["createdByRef"] = None
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

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def check_existing_stix_domain_entity(self, stix_id_key=None, name=None, type=None):
        return self.stix_domain_entity.get_by_stix_id_or_name(
            types=[type], stix_id_key=stix_id_key, name=name
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def get_stix_domain_entity(self, id):
        return self.stix_domain_entity.read(id=id)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def get_stix_domain_entity_by_external_reference(self, id, type):
        return self.stix_domain_entity.read(
            types=[type], filters=[{"key": "hasExternalReference", "values": [id]}]
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def get_stix_domain_entity_by_name(self, name, type="Stix-Domain-Entity"):
        return self.stix_domain_entity.get_by_stix_id_or_name(types=[type], name=name)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def get_stix_entity_by_stix_id_key(self, stix_id_key):
        return self.stix_entity.read(id=stix_id_key)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def search_stix_domain_entities(self, keyword, type="Stix-Domain-Entity"):
        return self.stix_domain_entity.list(types=[type], search=keyword)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def search_stix_domain_entity_by_name(
        self, name_or_alias, type="Stix-Domain-Entity"
    ):
        return self.stix_domain_entity.get_by_stix_id_or_name(
            types=[type], name=name_or_alias
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def update_stix_domain_entity_field(self, id, key, value):
        return self.stix_domain_entity.update_field(id=id, key=key, value=value)

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

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def update_stix_relation_field(self, id, key, value):
        return self.stix_relation.update_field(id=id, key=key, value=value)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def push_stix_domain_entity_export(self, entity_id, file_name, data):
        return self.stix_domain_entity.push_entity_export(entity_id, file_name, data)

    @deprecated(
        version="2.1.0", reason="Replaced by the StixDomainEntity class in pycti"
    )
    def delete_stix_domain_entity(self, id):
        return self.stix_domain_entity.delete(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def get_stix_relation_by_stix_id_key(self, stix_id_key):
        return self.stix_relation.read(stix_id_key=stix_id_key)

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def get_stix_relation_by_id(self, id):
        return self.stix_relation.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def get_stix_relations(
        self,
        from_id=None,
        to_id=None,
        type="stix_relation",
        first_seen=None,
        last_seen=None,
        inferred=False,
    ):
        if first_seen is not None and last_seen is not None:
            first_seen = dateutil.parser.parse(first_seen)
            first_seen_start = (first_seen + datetime.timedelta(days=-1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            first_seen_stop = (first_seen + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            last_seen = dateutil.parser.parse(last_seen)
            last_seen_start = (last_seen + datetime.timedelta(days=-1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            last_seen_stop = (last_seen + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
        else:
            first_seen_start = None
            first_seen_stop = None
            last_seen_start = None
            last_seen_stop = None
        return self.stix_relation.list(
            fromId=from_id,
            toId=to_id,
            relationType=type,
            firstSeenStart=first_seen_start,
            firstSeenStop=first_seen_stop,
            lastSeenStart=last_seen_start,
            lastSeenStop=last_seen_stop,
            inferred=inferred,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def get_stix_relation(
        self, from_id, to_id, type="stix_relation", first_seen=None, last_seen=None
    ):
        if first_seen is not None and last_seen is not None:
            first_seen = dateutil.parser.parse(first_seen)
            first_seen_start = (first_seen + datetime.timedelta(days=-1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            first_seen_stop = (first_seen + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            last_seen = dateutil.parser.parse(last_seen)
            last_seen_start = (last_seen + datetime.timedelta(days=-1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            last_seen_stop = (last_seen + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
        else:
            first_seen_start = None
            first_seen_stop = None
            last_seen_start = None
            last_seen_stop = None
        return self.stix_relation.read(
            fromId=from_id,
            toId=to_id,
            relationType=type,
            firstSeenStart=first_seen_start,
            firstSeenStop=first_seen_stop,
            lastSeenStart=last_seen_start,
            lastSeenStop=last_seen_stop,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def create_relation(
        self,
        from_id,
        from_role,
        to_id,
        to_role,
        type,
        description,
        first_seen,
        last_seen,
        weight=None,
        role_played=None,
        score=None,
        expiration=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.stix_relation.create_raw(
            fromId=from_id,
            fromRole=from_role,
            toId=to_id,
            toRole=to_role,
            relationship_type=type,
            description=description,
            first_seen=first_seen,
            last_seen=last_seen,
            weight=weight,
            role_played=role_played,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def create_relation_if_not_exists(
        self,
        from_id,
        from_type,
        to_id,
        to_type,
        type,
        description,
        first_seen,
        last_seen,
        weight,
        role_played=None,
        score=None,
        expiration=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.stix_relation.create(
            fromId=from_id,
            fromType=from_type,
            toId=to_id,
            toType=to_type,
            relationship_type=type,
            description=description,
            first_seen=first_seen,
            last_seen=last_seen,
            weight=weight,
            role_played=role_played,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixRelation class in pycti")
    def delete_relation(self, id):
        return self.stix_relation.delete(id=id)

    @deprecated(
        version="2.1.0", reason="Replaced by the MarkingDefinition class in pycti"
    )
    def get_marking_definition_by_id(self, id):
        return self.marking_definition.read(id=id)

    @deprecated(
        version="2.1.0", reason="Replaced by the MarkingDefinition class in pycti"
    )
    def get_marking_definition_by_stix_id_key(self, stix_id_key):
        return self.marking_definition.read(id=stix_id_key)

    @deprecated(
        version="2.1.0", reason="Replaced by the MarkingDefinition class in pycti"
    )
    def get_marking_definition_by_definition(self, definition_type, definition):
        return self.marking_definition.read(
            filters=[
                {"key": "definition_type", "values": [definition_type]},
                {"key": "definition", "values": [definition]},
            ]
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the MarkingDefinition class in pycti"
    )
    def create_marking_definition(
        self,
        definition_type,
        definition,
        level=0,
        color=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.marking_definition.create(
            definition_type=definition_type,
            definition=definition,
            level=level,
            color=color,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the MarkingDefinition class in pycti"
    )
    def create_marking_definition_if_not_exists(
        self,
        definition_type,
        definition,
        level=0,
        color=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.marking_definition.create(
            definition_type=definition_type,
            definition=definition,
            level=level,
            color=color,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the ExternalReference class in pycti"
    )
    def get_external_reference_by_url(self, url):
        return self.external_reference.read(filters=[{"key": "url", "values": [url]}])

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

    @deprecated(
        version="2.1.0", reason="Replaced by the ExternalReference class in pycti"
    )
    def create_external_reference(
        self,
        source_name,
        url,
        external_id="",
        description="",
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.external_reference.create(
            source_name=source_name,
            url=url,
            external_id=external_id,
            description=description,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(
        version="2.1.0", reason="Replaced by the ExternalReference class in pycti"
    )
    def create_external_reference_if_not_exists(
        self,
        source_name,
        url,
        external_id="",
        description="",
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.external_reference.create(
            source_name=source_name,
            url=url,
            external_id=external_id,
            description=description,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the KillChainPhase class in pycti")
    def get_kill_chain_phase(self, phase_name):
        return self.kill_chain_phase.read(
            filters=[{"key": "phase_name", "values": [phase_name]}]
        )

    @deprecated(version="2.1.0", reason="Replaced by the KillChainPhase class in pycti")
    def create_kill_chain_phase(
        self,
        kill_chain_name,
        phase_name,
        phase_order=0,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.kill_chain_phase.create(
            kill_chain_name=kill_chain_name,
            phase_name=phase_name,
            phase_order=phase_order,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the KillChainPhase class in pycti")
    def create_kill_chain_phase_if_not_exists(
        self,
        kill_chain_name,
        phase_name,
        phase_order=0,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.kill_chain_phase.create(
            kill_chain_name=kill_chain_name,
            phase_name=phase_name,
            phase_order=phase_order,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Identity class in pycti")
    def get_identity(self, id):
        return self.identity.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Identity class in pycti")
    def get_identities(self, limit=10000):
        return self.identity.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Identity class in pycti")
    def create_identity(
        self,
        type,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.identity.create_raw(
            type=type,
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Identity class in pycti")
    def create_identity_if_not_exists(
        self,
        type,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.identity.create(
            type=type,
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the ThreatActor class in pycti")
    def get_threat_actor(self, id):
        return self.threat_actor.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the ThreatActor class in pycti")
    def get_threat_actors(self, limit=10000):
        return self.threat_actor.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Threat-Actor class in pycti")
    def create_threat_actor(
        self,
        name,
        description,
        alias=None,
        goal=None,
        sophistication=None,
        resource_level=None,
        primary_motivation=None,
        secondary_motivation=None,
        personal_motivation=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.threat_actor.create(
            name=name,
            description=description,
            alias=alias,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivation=secondary_motivation,
            personal_motivation=personal_motivation,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Threat-Actor class in pycti")
    def create_threat_actor_if_not_exists(
        self,
        name,
        description,
        alias=None,
        goal=None,
        sophistication=None,
        resource_level=None,
        primary_motivation=None,
        secondary_motivation=None,
        personal_motivation=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.threat_actor.create(
            name=name,
            description=description,
            alias=alias,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivation=secondary_motivation,
            personal_motivation=personal_motivation,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the IntrusionSet class in pycti")
    def get_intrusion_set(self, id):
        return self.intrusion_set.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the IntrusionSet class in pycti")
    def get_intrusion_sets(self, limit=10000):
        return self.intrusion_set.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the IntrusionSet class in pycti")
    def create_intrusion_set(
        self,
        name,
        description,
        alias=None,
        first_seen=None,
        last_seen=None,
        goal=None,
        sophistication=None,
        resource_level=None,
        primary_motivation=None,
        secondary_motivation=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.intrusion_set.create(
            name=name,
            description=description,
            alias=alias,
            first_seen=first_seen,
            last_seen=last_seen,
            goal=goal,
            sophistication=sophistication,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivation=secondary_motivation,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the IntrusionSet class in pycti")
    def create_intrusion_set_if_not_exists(
        self,
        name,
        description,
        alias=None,
        first_seen=None,
        last_seen=None,
        goal=None,
        sophistication=None,
        resource_level=None,
        primary_motivation=None,
        secondary_motivation=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.intrusion_set.create(
            name=name,
            description=description,
            alias=alias,
            first_seen=first_seen,
            last_seen=last_seen,
            goal=goal,
            sophistication=sophistication,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivation=secondary_motivation,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Campaign class in pycti")
    def get_campaign(self, id):
        return self.campaign.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Campaign class in pycti")
    def get_campaigns(self, limit=10000):
        return self.campaign.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Campaign class in pycti")
    def create_campaign(
        self,
        name,
        description,
        alias=None,
        objective=None,
        first_seen=None,
        last_seen=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.campaign.create(
            name=name,
            description=description,
            alias=alias,
            objective=objective,
            first_seen=first_seen,
            last_seen=last_seen,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Campaign class in pycti")
    def create_campaign_if_not_exists(
        self,
        name,
        description,
        alias=None,
        objective=None,
        first_seen=None,
        last_seen=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.campaign.create(
            name=name,
            description=description,
            alias=alias,
            objective=objective,
            first_seen=first_seen,
            last_seen=last_seen,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Incident class in pycti")
    def get_incident(self, id):
        return self.incident.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Incident class in pycti")
    def get_incidents(self, limit=10000):
        return self.incident.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Incident class in pycti")
    def create_incident(
        self,
        name,
        description,
        alias=None,
        objective=None,
        first_seen=None,
        last_seen=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.incident.create_raw(
            name=name,
            description=description,
            alias=alias,
            objective=objective,
            first_seen=first_seen,
            last_seen=last_seen,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Incident class in pycti")
    def create_incident_if_not_exists(
        self,
        name,
        description,
        alias=None,
        objective=None,
        first_seen=None,
        last_seen=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.incident.create(
            name=name,
            description=description,
            alias=alias,
            objective=objective,
            first_seen=first_seen,
            last_seen=last_seen,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Malware class in pycti")
    def get_malware(self, id):
        return self.malware.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Malware class in pycti")
    def get_malwares(self, limit=10000):
        return self.malware.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Malware class in pycti")
    def create_malware(
        self,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.malware.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Malware class in pycti")
    def create_malware_if_not_exists(
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
        return self.malware.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Tool class in pycti")
    def get_tool(self, id):
        return self.tool.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Tool class in pycti")
    def get_tools(self, limit=10000):
        return self.tool.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Tool class in pycti")
    def create_tool(
        self,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.tool.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Tool class in pycti")
    def create_tool_if_not_exists(
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
        return self.tool.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Vulnerability class in pycti")
    def get_vulnerability(self, id):
        return self.vulnerability.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Vulnerability class in pycti")
    def get_vulnerabilities(self, limit=10000):
        return self.vulnerability.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Vulnerability class in pycti")
    def create_vulnerability(
        self,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.vulnerability.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

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

    @deprecated(version="2.1.0", reason="Replaced by the AttackPattern class in pycti")
    def get_attack_pattern(self, id):
        return self.attack_pattern.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the AttackPattern class in pycti")
    def get_attack_patterns(self, limit=10000):
        return self.attack_pattern.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the AttackPattern class in pycti")
    def create_attack_pattern(
        self,
        name,
        description,
        alias=None,
        platform=None,
        required_permission=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.attack_pattern.create_raw(
            name=name,
            description=description,
            alias=alias,
            platform=platform,
            required_permission=required_permission,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the AttackPattern class in pycti")
    def create_attack_pattern_if_not_exists(
        self,
        name,
        description,
        alias=None,
        platform=None,
        required_permission=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.attack_pattern.create(
            name=name,
            description=description,
            alias=alias,
            platform=platform,
            required_permission=required_permission,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the CourseOfAction class in pycti")
    def get_course_of_action(self, id):
        return self.course_of_action.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the CourseOfAction class in pycti")
    def get_course_of_actions(self, limit=10000):
        return self.course_of_action.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the CourseOfAction class in pycti")
    def create_course_of_action(
        self,
        name,
        description,
        alias=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.course_of_action.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the CourseOfAction class in pycti")
    def create_course_of_action_if_not_exists(
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
        return self.course_of_action.create(
            name=name,
            description=description,
            alias=alias,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def check_existing_report(self, stix_id_key=None, name=None, published=None):
        return self.report.get_by_stix_id_or_name(
            stix_id_key=stix_id_key, name=name, published=published
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def search_reports_by_name_and_date(self, name, published):
        return self.report.list(
            filters=[
                {"key": "name", "values": [name]},
                {"key": "published", "values": [published]},
            ]
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def search_report_by_name_and_date(self, name, published):
        return self.report.read(
            filters=[
                {"key": "name", "values": [name]},
                {"key": "published", "values": [published]},
            ]
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def get_report(self, id):
        return self.report.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def get_reports(self, limit=10000):
        return self.report.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def get_reports_by_stix_entity_stix_id(self, stix_entity_stix_id, limit=10000):
        stix_entity_result = self.stix_entity.read(id=stix_entity_stix_id)
        if stix_entity_result is not None:
            return self.report.list(
                filters=[
                    {"key": "knowledgeContains", "values": [stix_entity_result["id"]]},
                ],
                first=limit,
            )
        else:
            return []

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def create_report(
        self,
        name,
        description,
        published,
        report_class,
        object_status=None,
        source_confidence_level=None,
        graph_data=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.report.create_raw(
            name=name,
            description=description,
            published=published,
            report_class=report_class,
            object_status=object_status,
            source_confidence_level=source_confidence_level,
            graph_data=graph_data,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def create_report_if_not_exists(
        self,
        name,
        description,
        published,
        report_class,
        object_status=None,
        source_confidence_level=None,
        graph_data=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.report.create(
            name=name,
            description=description,
            published=published,
            report_class=report_class,
            object_status=object_status,
            source_confidence_level=source_confidence_level,
            graph_data=graph_data,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def create_report_if_not_exists_from_external_reference(
        self,
        external_reference_id,
        name,
        description,
        published,
        report_class,
        object_status=None,
        source_confidence_level=None,
        graph_data=None,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.report.create(
            name=name,
            external_reference_id=external_reference_id,
            description=description,
            published=published,
            report_class=report_class,
            object_status=object_status,
            source_confidence_level=source_confidence_level,
            graph_data=graph_data,
            id=id,
            stix_id_key=stix_id_key,
            created=created,
            modified=modified,
            update=True,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixObservable class in pycti")
    def get_stix_observable_by_id(self, id):
        return self.stix_observable.read(id=id)

    @deprecated(version="2.1.0", reason="Replaced by the StixObservable class in pycti")
    def get_stix_observable_by_value(self, observable_value):
        return self.stix_observable.read(
            filters=[{"key": "observable_value", "values": [observable_value]}]
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixObservable class in pycti")
    def get_stix_observables(self, limit=10000):
        return self.stix_observable.list(first=limit)

    @deprecated(version="2.1.0", reason="Replaced by the StixObservable class in pycti")
    def create_stix_observable(
        self,
        type,
        observable_value,
        description,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
    ):
        return self.stix_observable.create_raw(
            type=type,
            observable_value=observable_value,
            description=description,
            id=id,
            stix_id_key=stix_id_key,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixObservable class in pycti")
    def create_stix_observable_if_not_exists(
        self,
        type,
        observable_value,
        description,
        id=None,
        stix_id_key=None,
        created=None,
        modified=None,
        update=False,
    ):
        return self.stix_observable.create(
            type=type,
            observable_value=observable_value,
            description=description,
            id=id,
            stix_id_key=stix_id_key,
            update=update,
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixEntity class in pycti")
    def update_stix_domain_entity_created_by_ref(self, object_id, identity_id):
        self.stix_entity.update_created_by_ref(id=object_id, identity_id=identity_id)

    @deprecated(version="2.1.0", reason="Replaced by the StixEntity class in pycti")
    def update_stix_observable_created_by_ref(self, object_id, identity_id):
        self.stix_entity.update_created_by_ref(id=object_id, identity_id=identity_id)

    @deprecated(version="2.1.0", reason="Replaced by the StixEntity class in pycti")
    def add_marking_definition_if_not_exists(self, object_id, marking_definition_id):
        return self.stix_entity.add_marking_definition(
            id=object_id, marking_definition_id=marking_definition_id
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixEntity class in pycti")
    def add_kill_chain_phase_if_not_exists(self, object_id, kill_chain_phase_id):
        return self.stix_entity.add_kill_chain_phase(
            id=object_id, kill_chain_phase_id=kill_chain_phase_id
        )

    @deprecated(version="2.1.0", reason="Replaced by the StixEntity class in pycti")
    def add_external_reference_if_not_exists(self, object_id, external_reference_id):
        return self.stix_entity.add_external_reference(
            id=object_id, external_reference_id=external_reference_id
        )

    @deprecated(version="2.1.0", reason="Replaced by the Report class in pycti")
    def add_object_ref_to_report_if_not_exists(self, report_id, object_id):
        return self.report.add_stix_entity(id=report_id, entity_id=object_id)

    def resolve_role(self, relation_type, from_type, to_type):
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
            "variants-of": {
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
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "intrusion-set": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "campaign": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "incident": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
                "malware": {
                    "identity": {"from_role": "source", "to_role": "target"},
                    "sector": {"from_role": "source", "to_role": "target"},
                    "region": {"from_role": "source", "to_role": "target"},
                    "country": {"from_role": "source", "to_role": "target"},
                    "city": {"from_role": "source", "to_role": "target"},
                    "organization": {"from_role": "source", "to_role": "target"},
                    "vulnerability": {"from_role": "source", "to_role": "target"},
                },
            },
            "attributed-to": {
                "threat-actor": {
                    "identity": {"from_role": "attribution", "to_role": "origin"},
                    "organization": {"from_role": "attribution", "to_role": "origin"},
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
                "sector": {
                    "sector": {"from_role": "part_of", "to_role": "gather"},
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "organization": {
                    "sector": {"from_role": "part_of", "to_role": "gather"},
                },
                "person": {
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                },
                "observable": {
                    "organization": {"from_role": "part_of", "to_role": "gather"},
                    "person": {"from_role": "part_of", "to_role": "gather"},
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

    @deprecated(
        version="2.1.0",
        reason="Replaced by the same method in class OpenCTIStix2 in pycti",
    )
    def stix2_import_bundle_from_file(self, file_path, update=False, types=None):
        return self.stix2.import_bundle_from_file(file_path, update, types)

    @deprecated(
        version="2.1.0",
        reason="Replaced by the same method in class OpenCTIStix2 in pycti",
    )
    def stix2_import_bundle(self, json_data, update=False, types=None) -> List:
        return self.stix2.import_bundle_from_json(json_data, update, types)

    @deprecated(
        version="2.1.0",
        reason="Replaced by the same method in class OpenCTIStix2 in pycti",
    )
    def stix2_export_entity(
        self, entity_type, entity_id, mode="simple", max_marking_definition=None
    ):
        return self.stix2.export_entity(
            entity_type, entity_id, mode, max_marking_definition
        )
