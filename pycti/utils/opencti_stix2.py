# coding: utf-8

import time
import os
import json
import uuid
import base64
import datetime
from typing import List

import datefinder
import dateutil.parser
import pytz

from pycti.utils.constants import (
    ObservableTypes,
    IdentityTypes,
    CustomProperties,
    StixObservableRelationTypes,
)

datefinder.ValueError = ValueError, OverflowError
utc = pytz.UTC

# ObservableRelations
OBSERVABLE_RELATIONS = ["corresponds", "belongs"]

# Spec version
SPEC_VERSION = "2.1"


class OpenCTIStix2:
    """Python API for Stix2 in OpenCTI

    :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.mapping_cache = {}

    def unknown_type(self, stix_object):
        self.opencti.log(
            "error",
            'Unknown object type "' + stix_object["type"] + '", doing nothing...',
        )

    def convert_markdown(self, text) -> str:
        """converts input text to markdown style code annotation

        :param text: input text
        :type text: str
        :return: sanitized text with markdown style code annotation
        :rtype: str
        """

        return text.replace("<code>", "`").replace("</code>", "`")

    def format_date(self, date):
        """converts multiple input date formats to OpenCTI style dates

        :param date: input date
        :type date:
        :return: OpenCTI style date
        :rtype: datetime
        """

        if isinstance(date, datetime.date):
            return date.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if date is not None:
            return (
                dateutil.parser.parse(date)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        else:
            return (
                datetime.datetime.utcnow()
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )

    def filter_objects(self, uuids: list, objects: list) -> list:
        """filters objects based on UUIDs

        :param uuids: list of UUIDs
        :type uuids: list
        :param objects: list of objects to filter
        :type objects: list
        :return: list of filtered objects
        :rtype: list
        """

        result = []
        if objects is not None:
            for item in objects:
                if "id" in item and item["id"] not in uuids:
                    result.append(item)
        return result

    def pick_aliases(self, stix_object) -> list:
        """check stix2 object for multiple aliases and return a list

        :param stix_object: valid stix2 object
        :type stix_object:
        :return: list of aliases
        :rtype: list
        """

        # Add aliases
        if CustomProperties.ALIASES in stix_object:
            return stix_object[CustomProperties.ALIASES]
        elif "x_mitre_aliases" in stix_object:
            return stix_object["x_mitre_aliases"]
        elif "x_amitt_aliases" in stix_object:
            return stix_object["x_amitt_aliases"]
        elif "aliases" in stix_object:
            return stix_object["aliases"]
        return None

    def check_max_marking_definition(
        self, max_marking_definition_entity: str, entity_marking_definitions: list
    ) -> bool:
        """checks if a list of marking definitions conforms with a given max level

        :param max_marking_definition_entity: the maximum allowed marking definition level
        :type max_marking_definition_entity: str, optional
        :param entity_marking_definitions: list of entities to check
        :type entity_marking_definitions: list
        :return: `True` if the list conforms with max marking definition
        :rtype: bool
        """

        # Max is not set, return True
        if max_marking_definition_entity is None:
            return True
        # Filter entity markings definition to the max_marking_definition type
        typed_entity_marking_definitions = []
        for entity_marking_definition in entity_marking_definitions:
            if (
                entity_marking_definition["definition_type"]
                == max_marking_definition_entity["definition_type"]
            ):
                typed_entity_marking_definitions.append(entity_marking_definition)
        # No entity marking defintions of the max_marking_definition type
        if len(typed_entity_marking_definitions) == 0:
            return True

        # Check if level is less or equal to max
        for typed_entity_marking_definition in typed_entity_marking_definitions:
            if (
                typed_entity_marking_definition["level"]
                <= max_marking_definition_entity["level"]
            ):
                return True
        return False

    def import_bundle_from_file(self, file_path: str, update=False, types=None) -> List:
        """import a stix2 bundle from a file

        :param file_path: valid path to the file
        :type file_path: str
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :param types: list of stix2 types, defaults to None
        :type types: list, optional
        :return: list of imported stix2 objects
        :rtype: List
        """

        if types is None:
            types = []
        if not os.path.isfile(file_path):
            self.opencti.log("error", "The bundle file does not exists")
            return None

        with open(os.path.join(file_path)) as file:
            data = json.load(file)

        return self.import_bundle(data, update, types)

    def import_bundle_from_json(self, json_data, update=False, types=None) -> List:
        """import a stix2 bundle from JSON data

        :param json_data: JSON data
        :type json_data:
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :param types: list of stix2 types, defaults to None
        :type types: list, optional
        :return: list of imported stix2 objects
        :rtype: List
        """

        if types is None:
            types = []
        data = json.loads(json_data)
        return self.import_bundle(data, update, types)

    def extract_embedded_relationships(self, stix_object, types=None) -> dict:
        """extracts embedded relationship objects from a stix2 entity

        :param stix_object: valid stix2 object
        :type stix_object:
        :param types: list of stix2 types, defaults to None
        :type types: list, optional
        :return: embedded relationships as dict
        :rtype: dict
        """

        # Created By Ref
        created_by_ref_id = None
        if "created_by_ref" in stix_object:
            created_by_ref = stix_object["created_by_ref"]
            if created_by_ref in self.mapping_cache:
                created_by_ref_result = self.mapping_cache[created_by_ref]
            else:
                created_by_ref_result = self.opencti.stix_domain_entity.read(
                    id=created_by_ref
                )
                if created_by_ref_result is not None:
                    self.mapping_cache[created_by_ref] = {
                        "id": created_by_ref_result["id"],
                        "type": created_by_ref_result["entity_type"],
                    }
            if created_by_ref_result is not None:
                created_by_ref_id = created_by_ref_result["id"]

        # Object Marking Refs
        marking_definitions_ids = []
        if "object_marking_refs" in stix_object:
            for object_marking_ref in stix_object["object_marking_refs"]:
                if object_marking_ref in self.mapping_cache:
                    object_marking_ref_result = self.mapping_cache[object_marking_ref]
                else:
                    object_marking_ref_result = self.opencti.marking_definition.read(
                        id=object_marking_ref
                    )
                    if object_marking_ref_result is not None:
                        self.mapping_cache[object_marking_ref] = {
                            "id": object_marking_ref_result["id"],
                            "type": object_marking_ref_result["entity_type"],
                        }
                if object_marking_ref_result is not None:
                    marking_definitions_ids.append(object_marking_ref_result["id"])

        # Object Tags
        tags_ids = []
        if CustomProperties.TAG_TYPE in stix_object:
            for tag in stix_object[CustomProperties.TAG_TYPE]:
                tag_result = None
                if "id" in tag:
                    if tag["id"] in self.mapping_cache:
                        tag_result = self.mapping_cache[tag["id"]]
                    else:
                        tag_result = self.opencti.tag.read(id=tag["id"])
                if tag_result is not None:
                    self.mapping_cache[tag["id"]] = {"id": tag_result["id"]}
                else:
                    tag_result = self.opencti.tag.create(
                        tag_type=tag["tag_type"],
                        value=tag["value"],
                        color=tag["color"],
                        id=tag["id"] if "id" in tag else None,
                    )
                if tag_result is not None:
                    tags_ids.append(tag_result["id"])

        # Kill Chain Phases
        kill_chain_phases_ids = []
        if "kill_chain_phases" in stix_object:
            for kill_chain_phase in stix_object["kill_chain_phases"]:
                if kill_chain_phase["phase_name"] in self.mapping_cache:
                    kill_chain_phase = self.mapping_cache[
                        kill_chain_phase["phase_name"]
                    ]
                else:
                    kill_chain_phase = self.opencti.kill_chain_phase.create(
                        kill_chain_name=kill_chain_phase["kill_chain_name"],
                        phase_name=kill_chain_phase["phase_name"],
                        phase_order=kill_chain_phase[CustomProperties.PHASE_ORDER]
                        if CustomProperties.PHASE_ORDER in kill_chain_phase
                        else 0,
                        id=kill_chain_phase[CustomProperties.ID]
                        if CustomProperties.ID in kill_chain_phase
                        else None,
                        stix_id_key=kill_chain_phase["id"]
                        if "id" in kill_chain_phase
                        else None,
                        created=kill_chain_phase[CustomProperties.CREATED]
                        if CustomProperties.CREATED in kill_chain_phase
                        else None,
                        modified=kill_chain_phase[CustomProperties.MODIFIED]
                        if CustomProperties.MODIFIED in kill_chain_phase
                        else None,
                    )
                    self.mapping_cache[kill_chain_phase["phase_name"]] = {
                        "id": kill_chain_phase["id"],
                        "type": kill_chain_phase["entity_type"],
                    }
                kill_chain_phases_ids.append(kill_chain_phase["id"])

        # Object refs
        object_refs_ids = []
        if "object_refs" in stix_object:
            for object_ref in stix_object["object_refs"]:
                object_ref_result = None
                if object_ref in self.mapping_cache:
                    object_ref_result = self.mapping_cache[object_ref]
                elif "relationship" in object_ref:
                    object_ref_result = self.opencti.stix_relation.read(id=object_ref)
                    if object_ref_result is not None:
                        self.mapping_cache[object_ref] = {
                            "id": object_ref_result["id"],
                            "type": object_ref_result["entity_type"],
                        }
                elif "observed-data" not in object_ref:
                    object_ref_result = self.opencti.stix_entity.read(id=object_ref)
                    if object_ref_result is not None:
                        self.mapping_cache[object_ref] = {
                            "id": object_ref_result["id"],
                            "type": object_ref_result["entity_type"],
                        }
                if "observed-data" not in object_ref:
                    if object_ref_result is not None:
                        object_refs_ids.append(object_ref_result["id"])
                else:
                    object_refs_ids.append(object_ref)

        # External References
        reports = {}
        external_references_ids = []
        if "external_references" in stix_object:
            for external_reference in stix_object["external_references"]:
                if "url" in external_reference and "source_name" in external_reference:
                    url = external_reference["url"]
                    source_name = external_reference["source_name"]
                else:
                    continue
                if url in self.mapping_cache:
                    external_reference_id = self.mapping_cache[url]["id"]
                else:
                    external_reference_id = self.opencti.external_reference.create(
                        source_name=source_name,
                        url=url,
                        external_id=external_reference["external_id"]
                        if "external_id" in external_reference
                        else None,
                        description=external_reference["description"]
                        if "description" in external_reference
                        else None,
                        id=external_reference[CustomProperties.ID]
                        if CustomProperties.ID in external_reference
                        else None,
                        stix_id_key=external_reference["id"]
                        if "id" in external_reference
                        else None,
                        created=external_reference[CustomProperties.CREATED]
                        if CustomProperties.CREATED in external_reference
                        else None,
                        modified=external_reference[CustomProperties.MODIFIED]
                        if CustomProperties.MODIFIED in external_reference
                        else None,
                    )["id"]
                self.mapping_cache[url] = {"id": external_reference_id}
                external_references_ids.append(external_reference_id)

                if stix_object["type"] in [
                    "threat-actor",
                    "intrusion-set",
                    "campaign",
                    "incident",
                    "malware",
                    "relationship",
                ] and (types is None or "report" in types):
                    # Add a corresponding report
                    # Extract date
                    try:
                        if "description" in external_reference:
                            matches = datefinder.find_dates(
                                external_reference["description"]
                            )
                        else:
                            matches = datefinder.find_dates(source_name)
                    except:
                        matches = None
                    published = None
                    today = datetime.datetime.today()
                    if matches is not None:
                        try:
                            for match in matches:
                                if match < today:
                                    published = match.strftime("%Y-%m-%dT%H:%M:%SZ")
                                    break
                        except:
                            published = None
                    if published is None:
                        published = today.strftime("%Y-%m-%dT%H:%M:%SZ")

                    if "mitre" in source_name and "name" in stix_object:
                        title = "[MITRE ATT&CK] " + stix_object["name"]
                        if "modified" in stix_object:
                            published = stix_object["modified"]
                    elif "amitt" in source_name and "name" in stix_object:
                        title = "[AM!TT] " + stix_object["name"]
                        if "modified" in stix_object:
                            published = stix_object["modified"]
                    else:
                        title = source_name

                    if "external_id" in external_reference:
                        title = (
                            title + " (" + str(external_reference["external_id"]) + ")"
                        )

                    author = self.resolve_author(title)
                    report = self.opencti.report.create(
                        name=title,
                        external_reference_id=external_reference_id,
                        description=external_reference["description"]
                        if "description" in external_reference
                        else "",
                        published=published,
                        report_class="Threat Report",
                        object_status=2,
                        createdByRef=author["id"] if author is not None else None,
                        update=True,
                    )
                    # Add marking
                    if "marking_tlpwhite" in self.mapping_cache:
                        object_marking_ref_result = self.mapping_cache[
                            "marking_tlpwhite"
                        ]
                    else:
                        object_marking_ref_result = self.opencti.marking_definition.read(
                            filters=[
                                {"key": "definition_type", "values": ["TLP"]},
                                {"key": "definition", "values": ["TLP:WHITE"]},
                            ]
                        )
                    if object_marking_ref_result is not None:
                        self.mapping_cache["marking_tlpwhite"] = {
                            "id": object_marking_ref_result["id"]
                        }
                        self.opencti.stix_entity.add_marking_definition(
                            id=report["id"],
                            marking_definition_id=object_marking_ref_result["id"],
                        )

                    # Add external reference to report
                    self.opencti.stix_entity.add_external_reference(
                        id=report["id"], external_reference_id=external_reference_id,
                    )
                    reports[external_reference_id] = report

        return {
            "created_by_ref": created_by_ref_id,
            "marking_definitions": marking_definitions_ids,
            "tags": tags_ids,
            "kill_chain_phases": kill_chain_phases_ids,
            "object_refs": object_refs_ids,
            "external_references": external_references_ids,
            "reports": reports,
        }

    def import_object(self, stix_object, update=False, types=None) -> list:
        """import a stix2 object

        :param stix_object: valid stix2 object
        :type stix_object:
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :param types: list of stix2 types, defaults to None
        :type types: list, optional
        :return: list of imported stix2 objects
        :rtype: list
        """

        self.opencti.log(
            "info",
            "Importing a " + stix_object["type"] + " (id: " + stix_object["id"] + ")",
        )

        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object, types)
        created_by_ref_id = embedded_relationships["created_by_ref"]
        marking_definitions_ids = embedded_relationships["marking_definitions"]
        tags_ids = embedded_relationships["tags"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_ref_id": created_by_ref_id,
            "marking_definitions_ids": marking_definitions_ids,
            "tags_ids": tags_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_refs_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Import
        importer = {
            "marking-definition": self.create_marking_definition,
            "identity": self.create_identity,
            "threat-actor": self.create_threat_actor,
            "intrusion-set": self.create_intrusion_set,
            "campaign": self.create_campaign,
            "x-opencti-incident": self.create_incident,
            "malware": self.create_malware,
            "tool": self.create_tool,
            "vulnerability": self.create_vulnerability,
            "attack-pattern": self.create_attack_pattern,
            "course-of-action": self.create_course_of_action,
            "report": self.create_report,
            "note": self.create_note,
            "opinion": self.create_opinion,
            "indicator": self.create_indicator,
        }
        do_import = importer.get(
            stix_object["type"],
            lambda stix_object, extras, update: self.unknown_type(stix_object),
        )
        stix_object_results = do_import(stix_object, extras, update)

        if stix_object_results is None:
            return stix_object_results

        if not isinstance(stix_object_results, list):
            stix_object_results = [stix_object_results]

        for stix_object_result in stix_object_results:
            # Add embedded relationships
            self.mapping_cache[stix_object["id"]] = {
                "id": stix_object_result["id"],
                "type": stix_object_result["entity_type"],
                "observableRefs": stix_object_result["observableRefs"]
                if "observableRefs" in stix_object_result
                else [],
            }
            self.mapping_cache[stix_object_result["id"]] = {
                "id": stix_object_result["id"],
                "type": stix_object_result["entity_type"],
                "observableRefs": stix_object_result["observableRefs"]
                if "observableRefs" in stix_object_result
                else [],
            }

            # Add external references
            for external_reference_id in external_references_ids:
                self.opencti.stix_entity.add_external_reference(
                    id=stix_object_result["id"],
                    external_reference_id=external_reference_id,
                )
                if external_reference_id in reports:
                    self.opencti.report.add_stix_entity(
                        id=reports[external_reference_id]["id"],
                        entity_id=stix_object_result["id"],
                    )
            # Add object refs
            for object_refs_id in object_refs_ids:
                if "observed-data" in object_refs_id:
                    if object_refs_id in self.mapping_cache:
                        for observable in self.mapping_cache[object_refs_id]:
                            if stix_object_result["entity_type"] == "report":
                                self.opencti.report.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable["id"],
                                )
                            elif stix_object_result["entity_type"] == "note":
                                self.opencti.note.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable["id"],
                                )
                            elif stix_object_result["entity_type"] == "opinion":
                                self.opencti.opinion.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable["id"],
                                )
                else:
                    if stix_object_result["entity_type"] == "report":
                        self.opencti.report.add_stix_entity(
                            id=stix_object_result["id"], entity_id=object_refs_id,
                        )
                    elif stix_object_result["entity_type"] == "note":
                        self.opencti.note.add_stix_entity(
                            id=stix_object_result["id"], entity_id=object_refs_id,
                        )
                    elif stix_object_result["entity_type"] == "opinion":
                        self.opencti.opinion.add_stix_entity(
                            id=stix_object_result["id"], entity_id=object_refs_id,
                        )
                    if (
                        object_refs_id in self.mapping_cache
                        and "observableRefs" in self.mapping_cache[object_refs_id]
                        and self.mapping_cache[object_refs_id] is not None
                        and self.mapping_cache[object_refs_id]["observableRefs"]
                        is not None
                        and len(self.mapping_cache[object_refs_id]["observableRefs"])
                        > 0
                    ):
                        for observable_ref in self.mapping_cache[object_refs_id][
                            "observableRefs"
                        ]:
                            if stix_object_result["entity_type"] == "report":
                                self.opencti.report.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable_ref["id"],
                                )
                            elif stix_object_result["entity_type"] == "note":
                                self.opencti.note.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable_ref["id"],
                                )
                            elif stix_object_result["entity_type"] == "opinion":
                                self.opencti.opinion.add_stix_observable(
                                    id=stix_object_result["id"],
                                    stix_observable_id=observable_ref["id"],
                                )
            # Add files
            if CustomProperties.FILES in stix_object:
                for file in stix_object[CustomProperties.FILES]:
                    self.opencti.stix_domain_entity.add_file(
                        id=stix_object_result["id"],
                        file_name=file["name"],
                        data=base64.b64decode(file["data"]),
                        mime_type=file["mime_type"],
                    )

        return stix_object_results

    def import_relationship(self, stix_relation, update=False, types=None):
        # Extract
        embedded_relationships = self.extract_embedded_relationships(
            stix_relation, types
        )
        created_by_ref_id = embedded_relationships["created_by_ref"]
        marking_definitions_ids = embedded_relationships["marking_definitions"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_ref_id": created_by_ref_id,
            "marking_definitions_ids": marking_definitions_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Create the relation

        ### Get the SOURCE_REF
        if CustomProperties.SOURCE_REF in stix_relation:
            source_ref = stix_relation[CustomProperties.SOURCE_REF]
        else:
            source_ref = stix_relation["source_ref"]
        if source_ref in self.mapping_cache:
            if (
                StixObservableRelationTypes.has_value(
                    stix_relation["relationship_type"]
                )
                and "observableRefs" in self.mapping_cache[source_ref]
                and self.mapping_cache[source_ref]["observableRefs"] is not None
                and len(self.mapping_cache[source_ref]["observableRefs"]) > 0
            ):
                source_id = self.mapping_cache[source_ref]["observableRefs"][0]["id"]
                source_type = self.mapping_cache[source_ref]["observableRefs"][0][
                    "entity_type"
                ]
            else:
                source_id = self.mapping_cache[source_ref]["id"]
                source_type = self.mapping_cache[source_ref]["type"]
        else:
            stix_object_result = self.opencti.stix_entity.read(id=source_ref)
            if stix_object_result is not None:
                source_id = stix_object_result["id"]
                source_type = stix_object_result["entity_type"]
            else:
                self.opencti.log(
                    "error",
                    "Source ref of the relationship not found, doing nothing...",
                )
                return None

        ### Get the TARGET_REF
        if CustomProperties.TARGET_REF in stix_relation:
            target_ref = stix_relation[CustomProperties.TARGET_REF]
        else:
            target_ref = stix_relation["target_ref"]
        if target_ref in self.mapping_cache:
            if (
                StixObservableRelationTypes.has_value(
                    stix_relation["relationship_type"]
                )
                and "observableRefs" in self.mapping_cache[target_ref]
                and self.mapping_cache[target_ref]["observableRefs"] is not None
                and len(self.mapping_cache[target_ref]["observableRefs"]) > 0
            ):
                target_id = self.mapping_cache[target_ref]["observableRefs"][0]["id"]
                target_type = self.mapping_cache[target_ref]["observableRefs"][0][
                    "entity_type"
                ]
            else:
                target_id = self.mapping_cache[target_ref]["id"]
                target_type = self.mapping_cache[target_ref]["type"]
        else:
            stix_object_result = self.opencti.stix_entity.read(id=target_ref)
            if stix_object_result is not None:
                target_id = stix_object_result["id"]
                target_type = stix_object_result["entity_type"]
            else:
                self.opencti.log(
                    "error",
                    "Target ref of the relationship not found, doing nothing...",
                )
                return None

        date = None
        if "external_references" in stix_relation:
            for external_reference in stix_relation["external_references"]:
                try:
                    if "description" in external_reference:
                        matches = datefinder.find_dates(
                            external_reference["description"]
                        )
                    else:
                        matches = datefinder.find_dates(
                            external_reference["source_name"]
                        )
                except:
                    matches = None
                date = None
                today = datetime.datetime.today()
                if matches is not None:
                    try:
                        for match in matches:
                            if match < today:
                                date = match.strftime("%Y-%m-%dT%H:%M:%SZ")
                                break
                    except:
                        date = None
        if date is None:
            date = datetime.datetime.today().strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_relation_result = None
        if StixObservableRelationTypes.has_value(stix_relation["relationship_type"]):
            stix_relation_result = self.opencti.stix_observable_relation.create(
                fromId=source_id,
                fromType=source_type,
                toId=target_id,
                toType=target_type,
                relationship_type=stix_relation["relationship_type"],
                description=self.convert_markdown(stix_relation["description"])
                if "description" in stix_relation
                else None,
                first_seen=stix_relation[CustomProperties.FIRST_SEEN]
                if CustomProperties.FIRST_SEEN in stix_relation
                else date,
                last_seen=stix_relation[CustomProperties.LAST_SEEN]
                if CustomProperties.LAST_SEEN in stix_relation
                else date,
                weight=stix_relation[CustomProperties.WEIGHT]
                if CustomProperties.WEIGHT in stix_relation
                else 1,
                role_played=stix_relation[CustomProperties.ROLE_PLAYED]
                if CustomProperties.ROLE_PLAYED in stix_relation
                else None,
                id=stix_relation[CustomProperties.ID]
                if CustomProperties.ID in stix_relation
                else None,
                stix_id_key=stix_relation["id"] if "id" in stix_relation else None,
                created=stix_relation["created"]
                if "created" in stix_relation
                else None,
                modified=stix_relation["modified"]
                if "modified" in stix_relation
                else None,
                createdByRef=extras["created_by_ref_id"]
                if "created_by_ref_id" in extras
                else None,
                markingDefinitions=extras["marking_definitions_ids"]
                if "marking_definitions_ids" in extras
                else [],
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else [],
                update=update,
                ignore_dates=stix_relation[CustomProperties.IGNORE_DATES]
                if CustomProperties.IGNORE_DATES in stix_relation
                else None,
            )
        else:
            stix_relation_result = self.opencti.stix_relation.create(
                fromId=source_id,
                fromType=source_type,
                toId=target_id,
                toType=target_type,
                relationship_type=stix_relation["relationship_type"],
                description=self.convert_markdown(stix_relation["description"])
                if "description" in stix_relation
                else None,
                first_seen=stix_relation[CustomProperties.FIRST_SEEN]
                if CustomProperties.FIRST_SEEN in stix_relation
                else date,
                last_seen=stix_relation[CustomProperties.LAST_SEEN]
                if CustomProperties.LAST_SEEN in stix_relation
                else date,
                weight=stix_relation[CustomProperties.WEIGHT]
                if CustomProperties.WEIGHT in stix_relation
                else 1,
                role_played=stix_relation[CustomProperties.ROLE_PLAYED]
                if CustomProperties.ROLE_PLAYED in stix_relation
                else None,
                id=stix_relation[CustomProperties.ID]
                if CustomProperties.ID in stix_relation
                else None,
                stix_id_key=stix_relation["id"] if "id" in stix_relation else None,
                created=stix_relation["created"]
                if "created" in stix_relation
                else None,
                modified=stix_relation["modified"]
                if "modified" in stix_relation
                else None,
                createdByRef=extras["created_by_ref_id"]
                if "created_by_ref_id" in extras
                else None,
                markingDefinitions=extras["marking_definitions_ids"]
                if "marking_definitions_ids" in extras
                else [],
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else [],
                update=update,
                ignore_dates=stix_relation[CustomProperties.IGNORE_DATES]
                if CustomProperties.IGNORE_DATES in stix_relation
                else None,
            )
        if stix_relation_result is not None:
            self.mapping_cache[stix_relation["id"]] = {
                "id": stix_relation_result["id"],
                "type": stix_relation_result["entity_type"],
            }
        else:
            return None

        # Add external references
        for external_reference_id in external_references_ids:
            self.opencti.stix_entity.add_external_reference(
                id=stix_relation_result["id"],
                external_reference_id=external_reference_id,
            )
            if external_reference_id in reports:
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id]["id"],
                    entity_id=stix_relation_result["id"],
                )
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id]["id"], entity_id=source_id,
                )
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id]["id"], entity_id=target_id,
                )

    def import_observables(self, stix_object):
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object)
        created_by_ref_id = embedded_relationships["created_by_ref"]
        marking_definitions_ids = embedded_relationships["marking_definitions"]

        observables_to_create = {}
        relations_to_create = []
        for key, observable_item in stix_object["objects"].items():
            # TODO artifact
            if (
                CustomProperties.OBSERVABLE_TYPE in observable_item
                and CustomProperties.OBSERVABLE_VALUE in observable_item
            ):
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "stix_id": "observable--" + str(uuid.uuid4()),
                        "type": observable_item[CustomProperties.OBSERVABLE_TYPE],
                        "value": observable_item[CustomProperties.OBSERVABLE_VALUE],
                    }
                ]
            elif observable_item["type"] == "autonomous-system":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "stix_id": "observable--" + str(uuid.uuid4()),
                        "type": ObservableTypes.AUTONOMOUS_SYSTEM.value,
                        "value": "AS" + observable_item["number"],
                    }
                ]
            elif observable_item["type"] == "directory":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "stix_id": "observable--" + str(uuid.uuid4()),
                        "type": ObservableTypes.DIRECTORY.value,
                        "value": observable_item["path"],
                    }
                ]
            elif observable_item["type"] == "domain-name":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "stix_id": "observable--" + str(uuid.uuid4()),
                        "type": ObservableTypes.DOMAIN.value,
                        "value": observable_item["value"],
                    }
                ]
            elif observable_item["type"] == "email-addr":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "stix_id": "observable--" + str(uuid.uuid4()),
                        "type": ObservableTypes.EMAIL_ADDR.value,
                        "value": observable_item["value"],
                    }
                ]
                # TODO Belongs to ref
            # TODO email-message
            # TODO mime-part-type
            elif observable_item["type"] == "file":
                observables_to_create[key] = []
                if "name" in observable_item:
                    observables_to_create[key].append(
                        {
                            "id": str(uuid.uuid4()),
                            "type": ObservableTypes.FILE_NAME.value,
                            "value": observable_item["name"],
                        }
                    )
                if "hashes" in observable_item:
                    for keyfile, value in observable_item["hashes"].items():
                        if keyfile == "MD5":
                            observables_to_create[key].append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "type": ObservableTypes.FILE_HASH_MD5.value,
                                    "value": value,
                                }
                            )
                        if keyfile == "SHA-1":
                            observables_to_create[key].append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "type": ObservableTypes.FILE_HASH_SHA1.value,
                                    "value": value,
                                }
                            )
                        if keyfile == "SHA-256":
                            observables_to_create[key].append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "type": ObservableTypes.FILE_HASH_SHA256.value,
                                    "value": value,
                                }
                            )
            elif observable_item["type"] == "ipv4-addr":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "type": ObservableTypes.IPV4_ADDR.value,
                        "value": observable_item["value"],
                    }
                ]
            elif observable_item["type"] == "ipv6-addr":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "type": ObservableTypes.IPV6_ADDR.value,
                        "value": observable_item["value"],
                    }
                ]
            elif observable_item["type"] == "mac-addr":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "type": ObservableTypes.MAC_ADDR.value,
                        "value": observable_item["value"],
                    }
                ]
            elif observable_item["type"] == "windows-registry-key":
                observables_to_create[key] = [
                    {
                        "id": str(uuid.uuid4()),
                        "type": ObservableTypes.REGISTRY_KEY.value,
                        "value": observable_item["key"],
                    }
                ]

        for key, observable_item in stix_object["objects"].items():
            if observable_item["type"] == "directory":
                if "contains_refs" in observable_item:
                    for file in observable_item["contains_refs"]:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[file]:
                                if (
                                    observable_to_create_from["id"]
                                    != observables_to_create_to["id"]
                                ):
                                    relations_to_create.append(
                                        {
                                            "id": str(uuid.uuid4()),
                                            "from": observable_to_create_from["id"],
                                            "to": observables_to_create_to["id"],
                                            "type": "contains",
                                        }
                                    )
            if observable_item["type"] == "domain-name":
                if "resolves_to_refs" in observable_item:
                    for resolved in observable_item["resolves_to_refs"]:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[
                                resolved
                            ]:
                                if (
                                    observable_to_create_from["id"]
                                    != observables_to_create_to["id"]
                                ):
                                    relations_to_create.append(
                                        {
                                            "id": str(uuid.uuid4()),
                                            "from": observable_to_create_from["id"],
                                            "fromType": observable_to_create_from[
                                                "type"
                                            ],
                                            "to": observables_to_create_to["id"],
                                            "toType": observables_to_create_to["type"],
                                            "type": "resolves",
                                        }
                                    )
            if observable_item["type"] == "file":
                for observable_to_create_from in observables_to_create[key]:
                    for observables_to_create_to in observables_to_create[key]:
                        if (
                            observable_to_create_from["id"]
                            != observables_to_create_to["id"]
                        ):
                            relations_to_create.append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "from": observable_to_create_from["id"],
                                    "fromType": observable_to_create_from["type"],
                                    "to": observables_to_create_to["id"],
                                    "toType": observables_to_create_to["type"],
                                    "type": "corresponds",
                                }
                            )
            if observable_item["type"] == "ipv4-addr":
                if "belongs_to_refs" in observable_item:
                    for belonging in observable_item["belongs_to_refs"]:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[
                                belonging
                            ]:
                                if (
                                    observable_to_create_from["id"]
                                    != observables_to_create_to["id"]
                                ):
                                    relations_to_create.append(
                                        {
                                            "id": str(uuid.uuid4()),
                                            "from": observable_to_create_from["id"],
                                            "fromType": observable_to_create_from[
                                                "type"
                                            ],
                                            "to": observables_to_create_to["id"],
                                            "toType": observables_to_create_to["type"],
                                            "type": "belongs",
                                        }
                                    )

        stix_observables_mapping = {}
        self.mapping_cache[stix_object["id"]] = []
        for key, observable_to_create in observables_to_create.items():
            for observable in observable_to_create:
                observable_result = self.opencti.stix_observable.create(
                    type=observable["type"],
                    observable_value=observable["value"],
                    id=observable["id"],
                    createdByRef=created_by_ref_id,
                    markingDefinitions=marking_definitions_ids,
                    createIndicator=stix_object[CustomProperties.CREATE_INDICATOR]
                    if CustomProperties.CREATE_INDICATOR in stix_object
                    else False,
                )
                stix_observables_mapping[observable["id"]] = observable_result["id"]
                self.mapping_cache[stix_object["id"]].append(
                    {
                        "id": observable_result["id"],
                        "type": observable_result["entity_type"],
                    }
                )

        stix_observable_relations_mapping = {}
        for relation_to_create in relations_to_create:
            stix_observable_relation_result = self.opencti.stix_observable_relation.create(
                fromId=stix_observables_mapping[relation_to_create["from"]],
                fromType=relation_to_create["fromType"],
                toId=stix_observables_mapping[relation_to_create["to"]],
                toType=relation_to_create["toType"],
                relationship_type=relation_to_create["type"],
                createdByRef=created_by_ref_id,
                markingDefinitions=marking_definitions_ids,
            )
            stix_observable_relations_mapping[
                relation_to_create["id"]
            ] = stix_observable_relation_result["id"]

    def import_sighting(self, stix_sighting, from_id, to_id, update=False):
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_sighting)
        created_by_ref_id = embedded_relationships["created_by_ref"]
        marking_definitions_ids = embedded_relationships["marking_definitions"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_ref_id": created_by_ref_id,
            "marking_definitions_ids": marking_definitions_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Create the sighting

        ### Get the FROM
        if from_id in self.mapping_cache:
            final_from_id = self.mapping_cache[from_id]["id"]
        else:
            stix_object_result = self.opencti.stix_entity.read(id=from_id)
            if stix_object_result is not None:
                final_from_id = stix_object_result["id"]
            else:
                self.opencti.log(
                    "error", "From ref of the sithing not found, doing nothing...",
                )
                return None

        ### Get the TO
        final_to_id = None
        if to_id:
            if to_id in self.mapping_cache:
                final_to_id = self.mapping_cache[to_id]["id"]
            else:
                stix_object_result = self.opencti.stix_entity.read(id=to_id)
                if stix_object_result is not None:
                    final_to_id = stix_object_result["id"]
                else:
                    self.opencti.log(
                        "error", "To ref of the sithing not found, doing nothing...",
                    )
                    return None

        date = datetime.datetime.today().strftime("%Y-%m-%dT%H:%M:%SZ")
        stix_sighting_result = self.opencti.stix_sighting.create(
            fromId=final_from_id,
            toId=final_to_id,
            description=self.convert_markdown(stix_sighting["description"])
            if "description" in stix_sighting
            else None,
            first_seen=stix_sighting["first_seen"]
            if "first_seen" in stix_sighting
            else date,
            last_seen=stix_sighting["last_seen"]
            if "last_seen" in stix_sighting
            else date,
            confidence=stix_sighting["confidence"]
            if "confidence" in stix_sighting
            else 15,
            number=stix_sighting["count"] if "count" in stix_sighting else 1,
            negative=stix_sighting[CustomProperties.NEGATIVE]
            if CustomProperties.NEGATIVE in stix_sighting
            else False,
            id=stix_sighting[CustomProperties.ID]
            if CustomProperties.ID in stix_sighting
            else None,
            stix_id_key=stix_sighting["id"] if "id" in stix_sighting else None,
            created=stix_sighting["created"] if "created" in stix_sighting else None,
            modified=stix_sighting["modified"] if "modified" in stix_sighting else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            killChainPhases=extras["kill_chain_phases_ids"]
            if "kill_chain_phases_ids" in extras
            else [],
            update=update,
            ignore_dates=stix_sighting[CustomProperties.IGNORE_DATES]
            if CustomProperties.IGNORE_DATES in stix_sighting
            else None,
        )
        if stix_sighting_result is not None:
            self.mapping_cache[stix_sighting["id"]] = {
                "id": stix_sighting_result["id"],
                "type": stix_sighting_result["entity_type"],
            }
        else:
            return None

        # Add external references
        for external_reference_id in external_references_ids:
            self.opencti.stix_entity.add_external_reference(
                id=stix_sighting_result["id"],
                external_reference_id=external_reference_id,
            )

    def export_entity(
        self, entity_type, entity_id, mode="simple", max_marking_definition=None
    ):
        max_marking_definition_entity = (
            self.opencti.marking_definition.read(id=max_marking_definition)
            if max_marking_definition is not None
            else None
        )
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }
        # Map types
        if IdentityTypes.has_value(entity_type):
            entity_type = "identity"

        # Export
        exporter = {
            "identity": self.opencti.identity.to_stix2,
            "threat-actor": self.opencti.threat_actor.to_stix2,
            "intrusion-set": self.opencti.intrusion_set.to_stix2,
            "campaign": self.opencti.campaign.to_stix2,
            "incident": self.opencti.incident.to_stix2,
            "malware": self.opencti.malware.to_stix2,
            "tool": self.opencti.tool.to_stix2,
            "vulnerability": self.opencti.vulnerability.to_stix2,
            "attack-pattern": self.opencti.attack_pattern.to_stix2,
            "course-of-action": self.opencti.course_of_action.to_stix2,
            "report": self.opencti.report.to_stix2,
            "note": self.opencti.note.to_stix2,
            "opinion": self.opencti.opinion.to_stix2,
            "indicator": self.opencti.indicator.to_stix2,
        }
        do_export = exporter.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        objects = do_export(
            id=entity_id,
            mode=mode,
            max_marking_definition_entity=max_marking_definition_entity,
        )
        if objects is not None:
            bundle["objects"].extend(objects)
        return bundle

    def export_list(
        self,
        entity_type,
        search=None,
        filters=None,
        order_by=None,
        order_mode=None,
        max_marking_definition=None,
    ):
        max_marking_definition_entity = (
            self.opencti.marking_definition.read(id=max_marking_definition)
            if max_marking_definition is not None
            else None
        )
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }

        if IdentityTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "identity"

        # List
        lister = {
            "identity": self.opencti.identity.list,
            "threat-actor": self.opencti.threat_actor.list,
            "intrusion-set": self.opencti.intrusion_set.list,
            "campaign": self.opencti.campaign.list,
            "incident": self.opencti.incident.list,
            "malware": self.opencti.malware.list,
            "tool": self.opencti.tool.list,
            "vulnerability": self.opencti.vulnerability.list,
            "attack-pattern": self.opencti.attack_pattern.list,
            "course-of-action": self.opencti.course_of_action.list,
            "report": self.opencti.report.list,
            "note": self.opencti.note.list,
            "opinion": self.opencti.opinion.list,
            "indicator": self.opencti.indicator.list,
        }
        do_list = lister.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        entities_list = do_list(
            search=search,
            filters=filters,
            orderBy=order_by,
            orderMode=order_mode,
            getAll=True,
        )

        if entities_list is not None:
            # Export
            exporter = {
                "identity": self.opencti.identity.to_stix2,
                "threat-actor": self.opencti.threat_actor.to_stix2,
                "intrusion-set": self.opencti.intrusion_set.to_stix2,
                "campaign": self.opencti.campaign.to_stix2,
                "incident": self.opencti.incident.to_stix2,
                "malware": self.opencti.malware.to_stix2,
                "tool": self.opencti.tool.to_stix2,
                "vulnerability": self.opencti.vulnerability.to_stix2,
                "attack-pattern": self.opencti.attack_pattern.to_stix2,
                "course-of-action": self.opencti.course_of_action.to_stix2,
                "report": self.opencti.report.to_stix2,
                "note": self.opencti.note.to_stix2,
                "opinion": self.opencti.opinion.to_stix2,
                "indicator": self.opencti.indicator.to_stix2,
            }
            do_export = exporter.get(
                entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
            )
            uuids = []
            for entity in entities_list:
                entity_bundle = do_export(
                    entity=entity,
                    max_marking_definition_entity=max_marking_definition_entity,
                )
                if entity_bundle is not None:
                    entity_bundle_filtered = self.filter_objects(uuids, entity_bundle)
                    for x in entity_bundle_filtered:
                        uuids.append(x["id"])
                    bundle["objects"] = bundle["objects"] + entity_bundle_filtered

        return bundle

    def prepare_export(
        self, entity, stix_object, mode="simple", max_marking_definition_entity=None
    ):
        if (
            self.check_max_marking_definition(
                max_marking_definition_entity, entity["markingDefinitions"]
            )
            is False
        ):
            self.opencti.log(
                "info",
                "Marking definitions of "
                + stix_object["type"]
                + ' "'
                + stix_object["name"]
                + '" are less than max definition, not exporting.',
            )
            return []
        result = []
        objects_to_get = []
        relations_to_get = []
        if "createdByRef" in entity and entity["createdByRef"] is not None:
            entity_created_by_ref = entity["createdByRef"]
            if entity_created_by_ref["entity_type"] == "user":
                identity_class = "individual"
            elif entity_created_by_ref["entity_type"] == "sector":
                identity_class = "class"
            else:
                identity_class = entity_created_by_ref["entity_type"]

            created_by_ref = dict()
            created_by_ref["id"] = entity_created_by_ref["stix_id_key"]
            created_by_ref["type"] = "identity"
            created_by_ref["spec_version"] = SPEC_VERSION
            created_by_ref["name"] = entity_created_by_ref["name"]
            created_by_ref["identity_class"] = identity_class
            if self.opencti.not_empty(entity_created_by_ref["stix_label"]):
                created_by_ref["labels"] = entity_created_by_ref["stix_label"]
            else:
                created_by_ref["labels"] = ["identity"]
            created_by_ref["created"] = self.format_date(
                entity_created_by_ref["created"]
            )
            created_by_ref["modified"] = self.format_date(
                entity_created_by_ref["modified"]
            )
            if (
                entity_created_by_ref["entity_type"] == "organization"
                and "organization_class" in entity_created_by_ref
                and self.opencti.not_empty(entity_created_by_ref["organization_class"])
            ):
                created_by_ref[CustomProperties.ORG_CLASS] = entity_created_by_ref[
                    "organization_class"
                ]
            if self.opencti.not_empty(entity_created_by_ref["alias"]):
                created_by_ref[CustomProperties.ALIASES] = entity_created_by_ref[
                    "alias"
                ]
            created_by_ref[CustomProperties.IDENTITY_TYPE] = entity_created_by_ref[
                "entity_type"
            ]
            created_by_ref[CustomProperties.ID] = entity_created_by_ref["id"]

            stix_object["created_by_ref"] = created_by_ref["id"]
            result.append(created_by_ref)
        if "markingDefinitions" in entity and len(entity["markingDefinitions"]) > 0:
            marking_definitions = []
            for entity_marking_definition in entity["markingDefinitions"]:
                if entity_marking_definition["definition_type"] == "TLP":
                    created = "2017-01-20T00:00:00.000Z"
                else:
                    created = entity_marking_definition["created"]
                marking_definition = {
                    "type": "marking-definition",
                    "spec_version": SPEC_VERSION,
                    "id": entity_marking_definition["stix_id_key"],
                    "created": created,
                    "definition_type": entity_marking_definition[
                        "definition_type"
                    ].lower(),
                    "name": entity_marking_definition["definition"],
                    "definition": {
                        entity_marking_definition["definition_type"]
                        .lower(): entity_marking_definition["definition"]
                        .lower()
                        .replace("tlp:", "")
                    },
                }
                marking_definitions.append(marking_definition["id"])
                result.append(marking_definition)
            stix_object["object_marking_refs"] = marking_definitions
        if "tags" in entity and len(entity["tags"]) > 0:
            tags = []
            for entity_tag in entity["tags"]:
                tag = dict()
                tag["id"] = entity_tag["id"]
                tag["tag_type"] = entity_tag["tag_type"]
                tag["value"] = entity_tag["value"]
                tag["color"] = entity_tag["color"]
                tags.append(tag)
            stix_object[CustomProperties.TAG_TYPE] = tags
        if "killChainPhases" in entity and len(entity["killChainPhases"]) > 0:
            kill_chain_phases = []
            for entity_kill_chain_phase in entity["killChainPhases"]:
                kill_chain_phase = {
                    "id": entity_kill_chain_phase["stix_id_key"],
                    "kill_chain_name": entity_kill_chain_phase["kill_chain_name"],
                    "phase_name": entity_kill_chain_phase["phase_name"],
                    CustomProperties.ID: entity_kill_chain_phase["id"],
                    CustomProperties.PHASE_ORDER: entity_kill_chain_phase[
                        "phase_order"
                    ],
                    CustomProperties.CREATED: entity_kill_chain_phase["created"],
                    CustomProperties.MODIFIED: entity_kill_chain_phase["modified"],
                }
                kill_chain_phases.append(kill_chain_phase)
            stix_object["kill_chain_phases"] = kill_chain_phases
        if "externalReferences" in entity and len(entity["externalReferences"]) > 0:
            external_references = []
            for entity_external_reference in entity["externalReferences"]:
                external_reference = dict()
                external_reference["id"] = entity_external_reference["stix_id_key"]
                if self.opencti.not_empty(entity_external_reference["source_name"]):
                    external_reference["source_name"] = entity_external_reference[
                        "source_name"
                    ]
                if self.opencti.not_empty(entity_external_reference["description"]):
                    external_reference["description"] = entity_external_reference[
                        "description"
                    ]
                if self.opencti.not_empty(entity_external_reference["url"]):
                    external_reference["url"] = entity_external_reference["url"]
                if self.opencti.not_empty(entity_external_reference["hash"]):
                    external_reference["hash"] = entity_external_reference["hash"]
                if self.opencti.not_empty(entity_external_reference["external_id"]):
                    external_reference["external_id"] = entity_external_reference[
                        "external_id"
                    ]
                external_reference[CustomProperties.ID] = entity_external_reference[
                    "id"
                ]
                external_reference[
                    CustomProperties.CREATED
                ] = entity_external_reference["created"]
                external_reference[
                    CustomProperties.MODIFIED
                ] = entity_external_reference["modified"]
                external_references.append(external_reference)
            stix_object["external_references"] = external_references
        if "objectRefs" in entity and len(entity["objectRefs"]) > 0:
            object_refs = []
            objects_to_get = entity["objectRefs"]
            for entity_object_ref in entity["objectRefs"]:
                object_refs.append(entity_object_ref["stix_id_key"])
            if "relationRefs" in entity and len(entity["relationRefs"]) > 0:
                relations_to_get = entity["relationRefs"]
                for entity_relation_ref in entity["relationRefs"]:
                    if entity_relation_ref["stix_id_key"] not in object_refs:
                        object_refs.append(entity_relation_ref["stix_id_key"])
            stix_object["object_refs"] = object_refs

        uuids = [stix_object["id"]]
        for x in result:
            uuids.append(x["id"])

        observables_stix_ids = []
        observable_object_data = None
        if "observableRefs" in entity and len(entity["observableRefs"]) > 0:
            observable_object_data = self.export_stix_observables(entity)
            if observable_object_data is not None:
                observable_object_bundle = self.filter_objects(
                    uuids, [observable_object_data["observedData"]]
                )
                uuids = uuids + [x["id"] for x in observable_object_bundle]
                result = result + observable_object_bundle
                observables_stix_ids = (
                    observables_stix_ids + observable_object_data["stixIds"]
                )
                if stix_object["type"] == "report":
                    if "object_refs" in stix_object:
                        stix_object["object_refs"].append(
                            observable_object_data["observedData"]["id"]
                        )
                    else:
                        stix_object["object_refs"] = [
                            observable_object_data["observedData"]["id"]
                        ]
        result.append(stix_object)

        if mode == "simple":
            return result
        elif mode == "full":
            # Get extra relations
            stix_relations = self.opencti.stix_relation.list(
                fromId=entity["id"], forceNatural=True
            )
            for stix_relation in stix_relations:
                if self.check_max_marking_definition(
                    max_marking_definition_entity, stix_relation["markingDefinitions"]
                ):
                    if stix_relation["to"]["id"] == entity["id"]:
                        other_side_entity = stix_relation["from"]
                    else:
                        other_side_entity = stix_relation["to"]
                    objects_to_get.append(other_side_entity)
                    if other_side_entity["stix_id_key"] in observables_stix_ids:
                        other_side_entity["stix_id_key"] = observable_object_data[
                            "observedData"
                        ]["id"]
                    relation_object_data = self.opencti.stix_relation.to_stix2(
                        entity=stix_relation
                    )
                    relation_object_bundle = self.filter_objects(
                        uuids, relation_object_data
                    )
                    uuids = uuids + [x["id"] for x in relation_object_bundle]
                    result = result + relation_object_bundle
                else:
                    self.opencti.log(
                        "info",
                        "Marking definitions of "
                        + stix_relation["entity_type"]
                        + ' "'
                        + stix_relation["id"]
                        + '" are less than max definition, not exporting the relation AND the target entity.',
                    )

            # Export
            exporter = {
                "identity": self.opencti.identity.to_stix2,
                "threat-actor": self.opencti.threat_actor.to_stix2,
                "intrusion-set": self.opencti.intrusion_set.to_stix2,
                "campaign": self.opencti.campaign.to_stix2,
                "incident": self.opencti.incident.to_stix2,
                "malware": self.opencti.malware.to_stix2,
                "tool": self.opencti.tool.to_stix2,
                "vulnerability": self.opencti.vulnerability.to_stix2,
                "attack-pattern": self.opencti.attack_pattern.to_stix2,
                "course-of-action": self.opencti.course_of_action.to_stix2,
                "report": self.opencti.report.to_stix2,
                "note": self.opencti.note.to_stix2,
                "opinion": self.opencti.opinion.to_stix2,
                "indicator": self.opencti.indicator.to_stix2,
            }

            # Get extra objects
            for entity_object in objects_to_get:
                # Map types
                if IdentityTypes.has_value(entity_object["entity_type"]):
                    entity_object["entity_type"] = "identity"
                do_export = exporter.get(
                    entity_object["entity_type"],
                    lambda **kwargs: self.unknown_type(
                        {"type": entity_object["entity_type"]}
                    ),
                )
                entity_object_data = do_export(id=entity_object["id"])
                # Add to result
                entity_object_bundle = self.filter_objects(uuids, entity_object_data)
                uuids = uuids + [x["id"] for x in entity_object_bundle]
                result = result + entity_object_bundle
            for relation_object in relations_to_get:
                relation_object_data = self.opencti.stix_relation.to_stix2(
                    id=relation_object["id"]
                )
                relation_object_bundle = self.filter_objects(
                    uuids, relation_object_data
                )
                uuids = uuids + [x["id"] for x in relation_object_bundle]
                result = result + relation_object_bundle

            # Get extra reports
            """
            for uuid in uuids:
                if "marking-definition" not in uuid:
                    reports = self.opencti.stix_entity.reports(id=uuid)
                    for report in reports:
                        report_object_data = self.opencti.report.to_stix2(
                            entity=report,
                            mode="simple",
                            max_marking_definition_entity=max_marking_definition_entity,
                        )
                        report_object_bundle = self.filter_objects(
                            uuids, report_object_data
                        )
                        uuids = uuids + [x["id"] for x in report_object_bundle]
                        result = result + report_object_bundle
            """

            # Get notes
            for export_uuid in uuids:
                if "marking-definition" not in export_uuid:
                    notes = self.opencti.stix_entity.notes(id=export_uuid)
                    for note in notes:
                        note_object_data = self.opencti.note.to_stix2(
                            entity=note,
                            mode="simple",
                            max_marking_definition_entity=max_marking_definition_entity,
                        )
                        note_object_bundle = self.filter_objects(
                            uuids, note_object_data
                        )
                        uuids = uuids + [x["id"] for x in note_object_bundle]
                        result = result + note_object_bundle

            # Refilter all the reports object refs
            final_result = []
            for entity in result:
                if entity["type"] == "report" or entity["type"] == "note":
                    if "object_refs" in entity:
                        entity["object_refs"] = [
                            k for k in entity["object_refs"] if k in uuids
                        ]
                    final_result.append(entity)
                else:
                    final_result.append(entity)
            return final_result
        else:
            return []

    # TODO move in MarkingDefinition
    def create_marking_definition(self, stix_object, extras, update=False):
        definition_type = stix_object["definition_type"]
        definition = stix_object["definition"][stix_object["definition_type"]]
        if stix_object["definition_type"] == "tlp":
            definition_type = definition_type.upper()
            definition = (
                definition_type + ":" + stix_object["definition"]["tlp"].upper()
            )
        return self.opencti.marking_definition.create(
            definition_type=definition_type,
            definition=definition,
            level=stix_object[CustomProperties.LEVEL]
            if CustomProperties.LEVEL in stix_object
            else 0,
            color=stix_object[CustomProperties.COLOR]
            if CustomProperties.COLOR in stix_object
            else None,
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"],
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object[CustomProperties.MODIFIED]
            if CustomProperties.MODIFIED in stix_object
            else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
        )

    # TODO move in Identity
    def create_identity(self, stix_object, extras, update=False):
        if CustomProperties.IDENTITY_TYPE in stix_object:
            type = stix_object[CustomProperties.IDENTITY_TYPE].capitalize()
        else:
            if stix_object["identity_class"] == "individual":
                type = "User"
            elif stix_object["identity_class"] == "organization":
                type = "Organization"
            elif stix_object["identity_class"] == "group":
                type = "Organization"
            elif stix_object["identity_class"] == "class":
                type = "Sector"
            else:
                return None
        return self.opencti.identity.create(
            type=type,
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            organization_class=stix_object[CustomProperties.ORG_CLASS]
            if CustomProperties.ORG_CLASS in stix_object
            else None,
            update=update,
        )

    # TODO move in ThreatActor
    def create_threat_actor(self, stix_object, extras, update=False):
        return self.opencti.threat_actor.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            goal=stix_object["goals"] if "goals" in stix_object else None,
            sophistication=stix_object["sophistication"]
            if "sophistication" in stix_object
            else None,
            resource_level=stix_object["resource_level"]
            if "resource_level" in stix_object
            else None,
            primary_motivaton=stix_object["primary_motivation"]
            if "primary_motivation" in stix_object
            else None,
            secondary_motivation=stix_object["secondary_motivations"]
            if "secondary_motivations" in stix_object
            else None,
            personal_motivation=stix_object["personal_motivations"]
            if "personal_motivations" in stix_object
            else None,
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    # TODO move in IntrusionSet
    def create_intrusion_set(self, stix_object, extras, update=False):
        return self.opencti.intrusion_set.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            first_seen=stix_object[CustomProperties.FIRST_SEEN]
            if CustomProperties.FIRST_SEEN in stix_object
            else None,
            last_seen=stix_object[CustomProperties.LAST_SEEN]
            if CustomProperties.LAST_SEEN in stix_object
            else None,
            goal=stix_object["goals"] if "goals" in stix_object else None,
            sophistication=stix_object["sophistication"]
            if "sophistication" in stix_object
            else None,
            resource_level=stix_object["resource_level"]
            if "resource_level" in stix_object
            else None,
            primary_motivation=stix_object["primary_motivation"]
            if "primary_motivation" in stix_object
            else None,
            secondary_motivation=stix_object["secondary_motivations"]
            if "secondary_motivations" in stix_object
            else None,
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    # TODO move in Campaign
    def create_campaign(self, stix_object, extras, update=False):
        return self.opencti.campaign.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            objective=stix_object["objective"] if "objective" in stix_object else None,
            first_seen=stix_object[CustomProperties.FIRST_SEEN]
            if CustomProperties.FIRST_SEEN in stix_object
            else None,
            last_seen=stix_object[CustomProperties.LAST_SEEN]
            if CustomProperties.LAST_SEEN in stix_object
            else None,
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            uodate=update,
        )

    # TODO move in Incident
    def create_incident(self, stix_object, extras, update=False):
        return self.opencti.incident.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            objective=stix_object["objective"] if "objective" in stix_object else None,
            first_seen=stix_object["first_seen"]
            if "first_seen" in stix_object
            else None,
            last_seen=stix_object["last_seen"] if "last_seen" in stix_object else None,
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    # TODO move in Malware
    def create_malware(self, stix_object, extras, update=False):
        return self.opencti.malware.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            is_family=stix_object["is_family"] if "is_family" in stix_object else False,
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            killChainPhases=extras["kill_chain_phases_ids"]
            if "kill_chain_phases_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    # TODO move in Tool
    def create_tool(self, stix_object, extras, update=False):
        return self.opencti.tool.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            killChainPhases=extras["kill_chain_phases_ids"]
            if "kill_chain_phases_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    # TODO move in Vulnerability
    def create_vulnerability(self, stix_object, extras, update=False):
        return self.opencti.vulnerability.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            base_score=stix_object[CustomProperties.BASE_SCORE]
            if CustomProperties.BASE_SCORE in stix_object
            else None,
            base_severity=stix_object[CustomProperties.BASE_SEVERITY]
            if CustomProperties.BASE_SEVERITY in stix_object
            else None,
            attack_vector=stix_object[CustomProperties.ATTACK_VECTOR]
            if CustomProperties.ATTACK_VECTOR in stix_object
            else None,
            integrity_impact=stix_object[CustomProperties.INTEGRITY_IMPACT]
            if CustomProperties.INTEGRITY_IMPACT in stix_object
            else None,
            availability_impact=stix_object[CustomProperties.AVAILABILITY_IMPACT]
            if CustomProperties.AVAILABILITY_IMPACT in stix_object
            else None,
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    def create_attack_pattern(self, stix_object, extras, update=False):
        return self.opencti.attack_pattern.import_from_stix2(
            stixObject=stix_object, extras=extras, update=update
        )

    # TODO move in Course Of Action
    def create_course_of_action(self, stix_object, extras, update=False):
        return self.opencti.course_of_action.create(
            name=stix_object["name"],
            description=self.convert_markdown(stix_object["description"])
            if "description" in stix_object
            else "",
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID]
            if CustomProperties.ID in stix_object
            else None,
            stix_id_key=stix_object["id"] if "id" in stix_object else None,
            created=stix_object["created"] if "created" in stix_object else None,
            modified=stix_object["modified"] if "modified" in stix_object else None,
            createdByRef=extras["created_by_ref_id"]
            if "created_by_ref_id" in extras
            else None,
            markingDefinitions=extras["marking_definitions_ids"]
            if "marking_definitions_ids" in extras
            else [],
            tags=extras["tags_ids"] if "tags_ids" in extras else [],
            update=update,
        )

    def create_report(self, stix_object, extras, update=False):
        return self.opencti.report.import_from_stix2(
            stixObject=stix_object, extras=extras, update=update
        )

    def create_note(self, stix_object, extras, update=False):
        return self.opencti.note.import_from_stix2(
            stixObject=stix_object, extras=extras, update=update
        )

    def create_opinion(self, stix_object, extras, update=False):
        return self.opencti.opinion.import_from_stix2(
            stixObject=stix_object, extras=extras, update=update
        )

    def create_indicator(self, stix_object, extras, update=False):
        return self.opencti.indicator.import_from_stix2(
            stixObject=stix_object, extras=extras, update=update
        )

    def export_stix_observables(self, entity):
        stix_ids = []
        observed_data = dict()
        observed_data["id"] = "observed-data--" + str(uuid.uuid4())
        observed_data["type"] = "observed-data"
        observed_data["number_observed"] = len(entity["observableRefs"])
        observed_data["objects"] = []
        for observable in entity["observableRefs"]:
            stix_observable = dict()
            stix_observable[CustomProperties.OBSERVABLE_TYPE] = observable[
                "entity_type"
            ]
            stix_observable[CustomProperties.OBSERVABLE_VALUE] = observable[
                "observable_value"
            ]
            stix_observable["type"] = observable["entity_type"]
            observed_data["objects"].append(stix_observable)
            stix_ids.append(observable["stix_id_key"])

        return {"observedData": observed_data, "stixIds": stix_ids}

    def resolve_author(self, title):
        if "fireeye" in title.lower() or "mandiant" in title.lower():
            return self.get_author("FireEye")
        if "eset" in title.lower():
            return self.get_author("ESET")
        if "dragos" in title.lower():
            return self.get_author("Dragos")
        if "us-cert" in title.lower():
            return self.get_author("US-CERT")
        if (
            "unit 42" in title.lower()
            or "unit42" in title.lower()
            or "palo alto" in title.lower()
        ):
            return self.get_author("Palo Alto Networks")
        if "accenture" in title.lower():
            return self.get_author("Accenture")
        if "symantec" in title.lower():
            return self.get_author("Symantec")
        if "trendmicro" in title.lower() or "trend micro" in title.lower():
            return self.get_author("Trend Micro")
        if "mcafee" in title.lower():
            return self.get_author("McAfee")
        if "crowdstrike" in title.lower():
            return self.get_author("CrowdStrike")
        if "securelist" in title.lower() or "kaspersky" in title.lower():
            return self.get_author("Kaspersky")
        if "f-secure" in title.lower():
            return self.get_author("F-Secure")
        if "checkpoint" in title.lower():
            return self.get_author("CheckPoint")
        if "talos" in title.lower():
            return self.get_author("Cisco Talos")
        if "secureworks" in title.lower():
            return self.get_author("Dell SecureWorks")
        if "microsoft" in title.lower():
            return self.get_author("Microsoft")
        if "mitre att&ck" in title.lower():
            return self.get_author("The MITRE Corporation")
        return None

    def get_author(self, name):
        if name in self.mapping_cache:
            return self.mapping_cache[name]
        else:
            author = self.opencti.identity.create(
                type="Organization", name=name, description="",
            )
            self.mapping_cache[name] = author
            return author

    def import_bundle(self, stix_bundle, update=False, types=None) -> List:
        if types is None:
            types = []

        # Check if the bundle is correctly formatted
        if "type" not in stix_bundle or stix_bundle["type"] != "bundle":
            raise ValueError("JSON data type is not a STIX2 bundle")
        if "objects" not in stix_bundle or len(stix_bundle["objects"]) == 0:
            raise ValueError("JSON data objects is empty")

        # Import every elements in a specific order
        imported_elements = []

        # Marking definitions
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "marking-definition":
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info",
            "Marking definitions imported in: %ssecs" % round(end_time - start_time),
        )

        # Identities
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "identity" and (
                len(types) == 0
                or "identity" in types
                or (
                    CustomProperties.IDENTITY_TYPE in item
                    and item[CustomProperties.IDENTITY_TYPE] in types
                )
            ):
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Identities imported in: %ssecs" % round(end_time - start_time)
        )

        # StixDomainObjects except Report/Opinion/Notes
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if (
                item["type"] != "relationship"
                and item["type"] != "sighting"
                and item["type"] != "report"
                and item["type"] != "note"
                and item["type"] != "opinion"
                and item["type"] != "observed-data"
                and (len(types) == 0 or item["type"] in types)
            ):
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Objects imported in: %ssecs" % round(end_time - start_time)
        )

        # StixCyberObservables
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "observed-data" and (
                len(types) == 0 or "observed-data" in types
            ):
                self.import_observables(item)
        end_time = time.time()
        self.opencti.log(
            "info", "Observables imported in: %ssecs" % round(end_time - start_time)
        )

        # StixRelationObjects
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "relationship":
                # Import only relationships between entities
                if (
                    CustomProperties.SOURCE_REF not in item
                    or "relationship" not in item[CustomProperties.SOURCE_REF]
                ) and (
                    CustomProperties.TARGET_REF not in item
                    or "relationship" not in item[CustomProperties.TARGET_REF]
                ):
                    source_ref = (
                        item[CustomProperties.SOURCE_REF]
                        if CustomProperties.SOURCE_REF in item
                        else item["source_ref"]
                    )
                    target_ref = (
                        item[CustomProperties.TARGET_REF]
                        if CustomProperties.TARGET_REF in item
                        else item["target_ref"]
                    )
                    if "observed-data" in source_ref:
                        if source_ref in self.mapping_cache:
                            for observable in self.mapping_cache[source_ref]:
                                item[CustomProperties.SOURCE_REF] = observable["id"]
                                self.import_relationship(item, update, types)
                    elif "observed-data" in target_ref:
                        if target_ref in self.mapping_cache:
                            for observable in self.mapping_cache[target_ref]:
                                item[CustomProperties.TARGET_REF] = observable["id"]
                                self.import_relationship(item, update, types)
                    else:
                        self.import_relationship(item, update, types)
                    imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Relationships imported in: %ssecs" % round(end_time - start_time)
        )

        # StixRelationObjects (with relationships)
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "relationship":
                if (
                    CustomProperties.SOURCE_REF in item
                    and "relationship" in item[CustomProperties.SOURCE_REF]
                ) or (
                    CustomProperties.TARGET_REF in item
                    and "relationship" in item[CustomProperties.TARGET_REF]
                ):
                    self.import_relationship(item, update, types)
                    imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info",
            "Relationships to relationships imported in: %ssecs"
            % round(end_time - start_time),
        )

        # StixSightingsObjects
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "sighting":
                # Resolve the to
                to_ids = []
                if "where_sighted_refs" in item:
                    for where_sighted_ref in item["where_sighted_refs"]:
                        to_ids.append(where_sighted_ref)

                # Import sighting_of_ref
                from_id = item["sighting_of_ref"]
                if len(to_ids) > 0:
                    for to_id in to_ids:
                        self.import_sighting(item, from_id, to_id, update)
                else:
                    self.import_sighting(item, from_id, None, update)

                # Import observed_data_refs
                if "observed_data_refs" in item:
                    for observed_data_ref in item["observed_data_refs"]:
                        if observed_data_ref in self.mapping_cache:
                            for from_element in self.mapping_cache[observed_data_ref]:
                                if len(to_ids) > 0:
                                    for to_id in to_ids:
                                        self.import_sighting(
                                            item, from_element["id"], to_id, update
                                        )
                                else:
                                    self.import_sighting(item, from_id, None, update)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Sightings imported in: %ssecs" % round(end_time - start_time)
        )

        # Reports
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "report" and (len(types) == 0 or "report" in types):
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Reports imported in: %ssecs" % round(end_time - start_time)
        )

        # Notes
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "note" and (len(types) == 0 or "note" in types):
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Notes imported in: %ssecs" % round(end_time - start_time)
        )

        # Opinions
        start_time = time.time()
        for item in stix_bundle["objects"]:
            if item["type"] == "opinion" and (len(types) == 0 or "opinion" in types):
                self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})
        end_time = time.time()
        self.opencti.log(
            "info", "Opinions imported in: %ssecs" % round(end_time - start_time)
        )
        return imported_elements
