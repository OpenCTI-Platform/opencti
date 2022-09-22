# coding: utf-8

import base64
import datetime
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Union

import datefinder
import dateutil.parser
import pytz

from pycti.entities.opencti_identity import Identity
from pycti.utils.constants import (
    IdentityTypes,
    LocationTypes,
    MultipleStixCyberObservableRelationship,
    StixCyberObservableTypes,
)
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter
from pycti.utils.opencti_stix2_update import OpenCTIStix2Update
from pycti.utils.opencti_stix2_utils import (
    OBSERVABLES_VALUE_INT,
    STIX_CYBER_OBSERVABLE_MAPPING,
)

datefinder.ValueError = ValueError, OverflowError
utc = pytz.UTC

# Spec version
SPEC_VERSION = "2.1"


class OpenCTIStix2:
    """Python API for Stix2 in OpenCTI

    :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.stix2_update = OpenCTIStix2Update(opencti)
        self.mapping_cache = {}

    ######### UTILS
    # region utils
    def unknown_type(self, stix_object: Dict) -> None:
        self.opencti.log(
            "error",
            'Unknown object type "' + stix_object["type"] + '", doing nothing...',
        )

    def convert_markdown(self, text: str) -> str:
        """converts input text to markdown style code annotation

        :param text: input text
        :type text: str
        :return: sanitized text with markdown style code annotation
        :rtype: str
        """

        return text.replace("<code>", "`").replace("</code>", "`")

    def format_date(self, date: Any = None) -> str:
        """converts multiple input date formats to OpenCTI style dates

        :param date: input date
        :type date: Any [datetime, date, str or none]
        :return: OpenCTI style date
        :rtype: string
        """
        if isinstance(date, datetime.datetime):
            date_value = date
        elif isinstance(date, datetime.date):
            date_value = datetime.datetime.combine(date, datetime.datetime.min.time())
        elif isinstance(date, str):
            try:
                date_value = dateutil.parser.parse(date)
            except (dateutil.parser.ParserError, TypeError, OverflowError) as e:
                raise ValueError(f"{e}: {date} does not contain a valid date string")
        else:
            date_value = datetime.datetime.utcnow()

        if not date_value.tzinfo:
            self.opencti.log("No timezone found. Setting to UTC", "info")
            date_value = date_value.replace(tzinfo=datetime.timezone.utc)

        return date_value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def filter_objects(self, uuids: List, objects: List) -> List:
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

    def pick_aliases(self, stix_object: Dict) -> Optional[List]:
        """check stix2 object for multiple aliases and return a list

        :param stix_object: valid stix2 object
        :type stix_object:
        :return: list of aliases
        :rtype: list
        """

        # Add aliases
        if "x_opencti_aliases" in stix_object:
            return stix_object["x_opencti_aliases"]
        elif "x_mitre_aliases" in stix_object:
            return stix_object["x_mitre_aliases"]
        elif "x_amitt_aliases" in stix_object:
            return stix_object["x_amitt_aliases"]
        elif "aliases" in stix_object:
            return stix_object["aliases"]
        return None

    def check_max_marking_definition(
        self, max_marking_definition_entity: Dict, entity_marking_definitions: List
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
                typed_entity_marking_definition["x_opencti_order"]
                <= max_marking_definition_entity["x_opencti_order"]
            ):
                return True
        return False

    def import_bundle_from_file(
        self, file_path: str, update: bool = False, types: List = None
    ) -> Optional[List]:
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
        if not os.path.isfile(file_path):
            self.opencti.log("error", "The bundle file does not exists")
            return None
        with open(os.path.join(file_path)) as file:
            data = json.load(file)
        return self.import_bundle(data, update, types)

    def import_bundle_from_json(
        self,
        json_data: Union[str, bytes],
        update: bool = False,
        types: List = None,
        retry_number: int = None,
    ) -> List:
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
        data = json.loads(json_data)
        return self.import_bundle(
            data,
            update,
            types,
            retry_number,
        )

    def resolve_author(self, title: str) -> Optional[Identity]:
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

    def get_author(self, name: str) -> Identity:
        if name in self.mapping_cache:
            return self.mapping_cache[name]
        else:
            author = self.opencti.identity.create(
                type="Organization",
                name=name,
                description="",
            )
            self.mapping_cache[name] = author
            return author

    def extract_embedded_relationships(
        self, stix_object: Dict, types: List = None
    ) -> Dict:
        """extracts embedded relationship objects from a stix2 entity

        :param stix_object: valid stix2 object
        :type stix_object:
        :param types: list of stix2 types, defaults to None
        :type types: list, optional
        :return: embedded relationships as dict
        :rtype: dict
        """

        # Created By Ref
        created_by_id = None
        if "created_by_ref" in stix_object:
            created_by_id = stix_object["created_by_ref"]
        elif "x_opencti_created_by_ref" in stix_object:
            created_by_id = stix_object["x_opencti_created_by_ref"]
        elif (
            self.opencti.get_attribute_in_extension("created_by_ref", stix_object)
            is not None
        ):
            created_by_id = self.opencti.get_attribute_in_extension(
                "created_by_ref", stix_object
            )
        # Object Marking Refs
        object_marking_ids = (
            stix_object["object_marking_refs"]
            if "object_marking_refs" in stix_object
            else []
        )
        # Object Labels
        object_label_ids = []
        if (
            "labels" not in stix_object
            and self.opencti.get_attribute_in_extension("labels", stix_object)
            is not None
        ):
            stix_object["labels"] = self.opencti.get_attribute_in_extension(
                "labels", stix_object
            )
        if "labels" in stix_object:
            for label in stix_object["labels"]:
                if "label_" + label in self.mapping_cache:
                    label_data = self.mapping_cache["label_" + label]
                else:
                    label_data = self.opencti.label.create(value=label)
                if label_data is not None and "id" in label_data:
                    self.mapping_cache["label_" + label] = label_data
                    object_label_ids.append(label_data["id"])
        elif "x_opencti_labels" in stix_object:
            for label in stix_object["x_opencti_labels"]:
                if "label_" + label in self.mapping_cache:
                    label_data = self.mapping_cache["label_" + label]
                else:
                    label_data = self.opencti.label.create(value=label)
                if label_data is not None and "id" in label_data:
                    self.mapping_cache["label_" + label] = label_data
                    object_label_ids.append(label_data["id"])
        elif "x_opencti_tags" in stix_object:
            for tag in stix_object["x_opencti_tags"]:
                label = tag["value"]
                color = tag["color"] if "color" in tag else None
                if "label_" + label in self.mapping_cache:
                    label_data = self.mapping_cache["label_" + label]
                else:
                    label_data = self.opencti.label.create(value=label, color=color)
                if label_data is not None and "id" in label_data:
                    self.mapping_cache["label_" + label] = label_data
                    object_label_ids.append(label_data["id"])
        # Kill Chain Phases
        kill_chain_phases_ids = []
        if (
            "kill_chain_phases" not in stix_object
            and self.opencti.get_attribute_in_extension(
                "kill_chain_phases", stix_object
            )
            is not None
        ):
            stix_object["kill_chain_phases"] = self.opencti.get_attribute_in_extension(
                "kill_chain_phases", stix_object
            )
        if "kill_chain_phases" in stix_object:
            for kill_chain_phase in stix_object["kill_chain_phases"]:
                if (
                    kill_chain_phase["kill_chain_name"] + kill_chain_phase["phase_name"]
                    in self.mapping_cache
                ):
                    kill_chain_phase = self.mapping_cache[
                        kill_chain_phase["kill_chain_name"]
                        + kill_chain_phase["phase_name"]
                    ]
                else:
                    if (
                        "x_opencti_order" not in kill_chain_phase
                        and self.opencti.get_attribute_in_extension(
                            "order", kill_chain_phase
                        )
                        is not None
                    ):
                        kill_chain_phase[
                            "x_opencti_order"
                        ] = self.opencti.get_attribute_in_extension(
                            "order", kill_chain_phase
                        )
                    kill_chain_phase = self.opencti.kill_chain_phase.create(
                        kill_chain_name=kill_chain_phase["kill_chain_name"],
                        phase_name=kill_chain_phase["phase_name"],
                        x_opencti_order=kill_chain_phase["x_opencti_order"]
                        if "x_opencti_order" in kill_chain_phase
                        else 0,
                        stix_id=kill_chain_phase["id"]
                        if "id" in kill_chain_phase
                        else None,
                    )
                    self.mapping_cache[
                        kill_chain_phase["kill_chain_name"]
                        + kill_chain_phase["phase_name"]
                    ] = {
                        "id": kill_chain_phase["id"],
                        "type": kill_chain_phase["entity_type"],
                    }
                kill_chain_phases_ids.append(kill_chain_phase["id"])
        # Object refs
        object_refs_ids = (
            stix_object["object_refs"] if "object_refs" in stix_object else []
        )
        # External References
        reports = {}
        external_references_ids = []
        if (
            "external_references" not in stix_object
            and self.opencti.get_attribute_in_extension(
                "external_references", stix_object
            )
            is not None
        ):
            stix_object[
                "external_references"
            ] = self.opencti.get_attribute_in_extension(
                "external_references", stix_object
            )
        if "external_references" in stix_object:
            for external_reference in stix_object["external_references"]:
                url = external_reference["url"] if "url" in external_reference else None
                source_name = (
                    external_reference["source_name"]
                    if "source_name" in external_reference
                    else None
                )
                external_id = (
                    external_reference["external_id"]
                    if "external_id" in external_reference
                    else None
                )
                generated_ref_id = self.opencti.external_reference.generate_id(
                    url, source_name, external_id
                )
                if generated_ref_id is None:
                    continue
                if generated_ref_id in self.mapping_cache:
                    external_reference_id = self.mapping_cache[generated_ref_id]
                else:
                    external_reference_id = self.opencti.external_reference.create(
                        source_name=source_name,
                        url=url,
                        external_id=external_id,
                        description=external_reference["description"]
                        if "description" in external_reference
                        else None,
                    )["id"]
                if "x_opencti_files" in external_reference:
                    for file in external_reference["x_opencti_files"]:
                        self.opencti.external_reference.add_file(
                            id=external_reference_id,
                            file_name=file["name"],
                            data=base64.b64decode(file["data"]),
                            mime_type=file["mime_type"],
                        )
                if (
                    self.opencti.get_attribute_in_extension("files", external_reference)
                    is not None
                ):
                    for file in self.opencti.get_attribute_in_extension(
                        "files", external_reference
                    ):
                        self.opencti.external_reference.add_file(
                            id=external_reference_id,
                            file_name=file["name"],
                            data=base64.b64decode(file["data"]),
                            mime_type=file["mime_type"],
                        )
                self.mapping_cache[generated_ref_id] = generated_ref_id
                external_references_ids.append(external_reference_id)
                if stix_object["type"] in [
                    "threat-actor",
                    "intrusion-set",
                    "campaign",
                    "incident",
                    "malware",
                    "relationship",
                ] and (types is not None and "external-reference-as-report" in types):
                    # Add a corresponding report
                    # Extract date
                    try:
                        if "description" in external_reference:
                            matches = datefinder.find_dates(
                                external_reference["description"],
                                base_date=datetime.datetime.fromtimestamp(0),
                            )
                        else:
                            matches = datefinder.find_dates(
                                source_name,
                                base_date=datetime.datetime.fromtimestamp(0),
                            )
                    except:
                        matches = None
                    published = None
                    yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
                    default_date = datetime.datetime.fromtimestamp(1)
                    if matches is not None:
                        try:
                            for match in matches:
                                if (
                                    match.timestamp() < yesterday.timestamp()
                                    and len(str(match.year)) == 4
                                ):
                                    published = match.strftime("%Y-%m-%dT%H:%M:%SZ")
                                    break
                        except:
                            pass
                    if published is None:
                        published = default_date.strftime("%Y-%m-%dT%H:%M:%SZ")

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

                    if "marking_tlpclear" in self.mapping_cache:
                        object_marking_ref_result = self.mapping_cache[
                            "marking_tlpclear"
                        ]
                    else:
                        object_marking_ref_result = (
                            self.opencti.marking_definition.read(
                                filters=[
                                    {"key": "definition_type", "values": ["TLP"]},
                                    {"key": "definition", "values": ["TLP:CLEAR"]},
                                ]
                            )
                        )
                        self.mapping_cache["marking_tlpclear"] = {
                            "id": object_marking_ref_result["id"]
                        }

                    author = self.resolve_author(title)
                    report = self.opencti.report.create(
                        name=title,
                        createdBy=author["id"] if author is not None else None,
                        objectMarking=[object_marking_ref_result["id"]],
                        externalReferences=[external_reference_id],
                        description=external_reference["description"]
                        if "description" in external_reference
                        else "",
                        report_types="threat-report",
                        published=published,
                        update=True,
                    )
                    reports[external_reference_id] = report

        return {
            "created_by": created_by_id,
            "object_marking": object_marking_ids,
            "object_label": object_label_ids,
            "kill_chain_phases": kill_chain_phases_ids,
            "object_refs": object_refs_ids,
            "external_references": external_references_ids,
            "reports": reports,
        }

    # endregion

    # region import
    def import_object(
        self, stix_object: Dict, update: bool = False, types: List = None
    ) -> Optional[List]:
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
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Import
        importer = {
            "marking-definition": self.opencti.marking_definition.import_from_stix2,
            "attack-pattern": self.opencti.attack_pattern.import_from_stix2,
            "campaign": self.opencti.campaign.import_from_stix2,
            "event": self.opencti.event.import_from_stix2,
            "note": self.opencti.note.import_from_stix2,
            "observed-data": self.opencti.observed_data.import_from_stix2,
            "opinion": self.opencti.opinion.import_from_stix2,
            "report": self.opencti.report.import_from_stix2,
            "course-of-action": self.opencti.course_of_action.import_from_stix2,
            "identity": self.opencti.identity.import_from_stix2,
            "indicator": self.opencti.indicator.import_from_stix2,
            "infrastructure": self.opencti.infrastructure.import_from_stix2,
            "intrusion-set": self.opencti.intrusion_set.import_from_stix2,
            "location": self.opencti.location.import_from_stix2,
            "malware": self.opencti.malware.import_from_stix2,
            "threat-actor": self.opencti.threat_actor.import_from_stix2,
            "tool": self.opencti.tool.import_from_stix2,
            "channel": self.opencti.channel.import_from_stix2,
            "narrative": self.opencti.narrative.import_from_stix2,
            "vulnerability": self.opencti.vulnerability.import_from_stix2,
            "incident": self.opencti.incident.import_from_stix2,
        }
        do_import = importer.get(
            stix_object["type"],
            lambda **kwargs: self.unknown_type(stix_object),
        )
        stix_object_results = do_import(
            stixObject=stix_object, extras=extras, update=update
        )

        if stix_object_results is None:
            return None

        if not isinstance(stix_object_results, list):
            stix_object_results = [stix_object_results]

        for stix_object_result in stix_object_results:
            self.mapping_cache[stix_object["id"]] = {
                "id": stix_object_result["id"],
                "type": stix_object_result["entity_type"],
                "observables": stix_object_result["observables"]
                if "observables" in stix_object_result
                else [],
            }
            self.mapping_cache[stix_object_result["id"]] = {
                "id": stix_object_result["id"],
                "type": stix_object_result["entity_type"],
                "observables": stix_object_result["observables"]
                if "observables" in stix_object_result
                else [],
            }
            # Add reports from external references
            for external_reference_id in external_references_ids:
                if external_reference_id in reports:
                    self.opencti.report.add_stix_object_or_stix_relationship(
                        id=reports[external_reference_id]["id"],
                        stixObjectOrStixRelationshipId=stix_object_result["id"],
                    )
            # Add files
            if "x_opencti_files" in stix_object:
                for file in stix_object["x_opencti_files"]:
                    self.opencti.stix_domain_object.add_file(
                        id=stix_object_result["id"],
                        file_name=file["name"],
                        data=base64.b64decode(file["data"]),
                        mime_type=file["mime_type"],
                    )
            if (
                self.opencti.get_attribute_in_extension("files", stix_object)
                is not None
            ):
                for file in self.opencti.get_attribute_in_extension(
                    "files", stix_object
                ):
                    self.opencti.stix_domain_object.add_file(
                        id=stix_object_result["id"],
                        file_name=file["name"],
                        data=base64.b64decode(file["data"]),
                        mime_type=file["mime_type"],
                    )
        return stix_object_results

    def import_observable(
        self, stix_object: Dict, update: bool = False, types: List = None
    ) -> None:
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object, types)
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }
        if stix_object["type"] == "simple-observable":
            stix_observable_result = self.opencti.stix_cyber_observable.create(
                simple_observable_id=stix_object["id"],
                simple_observable_key=stix_object["key"],
                simple_observable_value=stix_object["value"]
                if stix_object["key"] not in OBSERVABLES_VALUE_INT
                else int(stix_object["value"]),
                simple_observable_description=stix_object["description"]
                if "description" in stix_object
                else None,
                x_opencti_score=stix_object["x_opencti_score"]
                if "x_opencti_score" in stix_object
                else None,
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else [],
                objectLabel=extras["object_label_ids"]
                if "object_label_ids" in extras
                else [],
                externalReferences=extras["external_references_ids"]
                if "external_references_ids" in extras
                else [],
                createIndicator=stix_object["x_opencti_create_indicator"]
                if "x_opencti_create_indicator" in stix_object
                else None,
                update=update,
            )
        else:
            stix_observable_result = self.opencti.stix_cyber_observable.create(
                observableData=stix_object,
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else [],
                objectLabel=extras["object_label_ids"]
                if "object_label_ids" in extras
                else [],
                externalReferences=extras["external_references_ids"]
                if "external_references_ids" in extras
                else [],
                update=update,
            )
        if stix_observable_result is not None:
            # Add files
            if "x_opencti_files" in stix_object:
                for file in stix_object["x_opencti_files"]:
                    self.opencti.stix_cyber_observable.add_file(
                        id=stix_observable_result["id"],
                        file_name=file["name"],
                        data=base64.b64decode(file["data"]),
                        mime_type=file["mime_type"],
                    )
            if (
                self.opencti.get_attribute_in_extension("files", stix_object)
                is not None
            ):
                for file in self.opencti.get_attribute_in_extension(
                    "files", stix_object
                ):
                    self.opencti.stix_cyber_observable.add_file(
                        id=stix_observable_result["id"],
                        file_name=file["name"],
                        data=base64.b64decode(file["data"]),
                        mime_type=file["mime_type"],
                    )
            if "id" in stix_object:
                self.mapping_cache[stix_object["id"]] = {
                    "id": stix_observable_result["id"],
                    "type": stix_observable_result["entity_type"],
                }
            self.mapping_cache[stix_observable_result["id"]] = {
                "id": stix_observable_result["id"],
                "type": stix_observable_result["entity_type"],
            }
            # Iterate over refs to create appropriate relationships
            for key in stix_object.keys():
                if key not in [
                    "created_by_ref",
                    "object_marking_refs",
                    "x_opencti_created_by_ref",
                ]:
                    if key.endswith("_ref"):
                        relationship_type = key.replace("_ref", "").replace("_", "-")
                        self.opencti.stix_cyber_observable_relationship.create(
                            fromId=stix_observable_result["id"],
                            toId=stix_object[key],
                            relationship_type=relationship_type,
                        )
                    elif key.endswith("_refs"):
                        relationship_type = key.replace("_refs", "").replace("_", "-")
                        for value in stix_object[key]:
                            self.opencti.stix_cyber_observable_relationship.create(
                                fromId=stix_observable_result["id"],
                                toId=value,
                                relationship_type=relationship_type,
                            )
        else:
            return None

    def import_relationship(
        self, stix_relation: Dict, update: bool = False, types: List = None
    ) -> None:
        # Extract
        embedded_relationships = self.extract_embedded_relationships(
            stix_relation, types
        )
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Create the relation

        ## Try to guess start_time / stop_time from external reference
        date = None
        if "external_references" in stix_relation:
            for external_reference in stix_relation["external_references"]:
                try:
                    if "description" in external_reference:
                        matches = datefinder.find_dates(
                            external_reference["description"],
                            base_date=datetime.datetime.fromtimestamp(0),
                        )
                    else:
                        matches = datefinder.find_dates(
                            external_reference["source_name"],
                            base_date=datetime.datetime.fromtimestamp(0),
                        )
                except:
                    matches = None
                date = None
                yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
                if matches is not None:
                    try:
                        for match in matches:
                            if (
                                match.timestamp() < yesterday.timestamp()
                                and len(str(match.year)) == 4
                            ):
                                date = match.strftime("%Y-%m-%dT%H:%M:%SZ")
                                break
                    except:
                        date = None

        stix_relation_result = self.opencti.stix_core_relationship.import_from_stix2(
            stixRelation=stix_relation, extras=extras, update=update, defaultDate=date
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
            if external_reference_id in reports:
                self.opencti.report.add_stix_object_or_stix_relationship(
                    id=reports[external_reference_id]["id"],
                    stixObjectOrStixRelationshipId=stix_relation_result["id"],
                )
                self.opencti.report.add_stix_object_or_stix_relationship(
                    id=reports[external_reference_id]["id"],
                    stixObjectOrStixRelationshipId=stix_relation["source_ref"],
                )
                self.opencti.report.add_stix_object_or_stix_relationship(
                    id=reports[external_reference_id]["id"],
                    stixObjectOrStixRelationshipId=stix_relation["target_ref"],
                )

    def import_sighting(
        self,
        stix_sighting: Dict,
        from_id: str,
        to_id: str,
        update: bool = False,
        types: List = None,
    ) -> None:
        # Extract
        embedded_relationships = self.extract_embedded_relationships(
            stix_sighting, types
        )
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
        }

        # Create the sighting

        ### Get the FROM
        if from_id in self.mapping_cache:
            final_from_id = self.mapping_cache[from_id]["id"]
        else:
            stix_object_result = (
                self.opencti.opencti_stix_object_or_stix_relationship.read(id=from_id)
            )
            if stix_object_result is not None:
                final_from_id = stix_object_result["id"]
            else:
                self.opencti.log(
                    "error",
                    "From ref of the sithing not found, doing nothing...",
                )
                return None

        ### Get the TO
        final_to_id = None
        if to_id:
            if to_id in self.mapping_cache:
                final_to_id = self.mapping_cache[to_id]["id"]
            else:
                stix_object_result = (
                    self.opencti.opencti_stix_object_or_stix_relationship.read(id=to_id)
                )
                if stix_object_result is not None:
                    final_to_id = stix_object_result["id"]
                else:
                    self.opencti.log(
                        "error",
                        "To ref of the sithing not found, doing nothing...",
                    )
                    return None
        date = datetime.datetime.today().strftime("%Y-%m-%dT%H:%M:%SZ")
        if (
            "x_opencti_negative" not in stix_sighting
            and self.opencti.get_attribute_in_extension("negative", stix_sighting)
            is not None
        ):
            stix_sighting[
                "x_opencti_negative"
            ] = self.opencti.get_attribute_in_extension("negative", stix_sighting)
        stix_sighting_result = self.opencti.stix_sighting_relationship.create(
            fromId=final_from_id,
            toId=final_to_id,
            stix_id=stix_sighting["id"] if "id" in stix_sighting else None,
            description=self.convert_markdown(stix_sighting["description"])
            if "description" in stix_sighting
            else None,
            first_seen=stix_sighting["first_seen"]
            if "first_seen" in stix_sighting
            else date,
            last_seen=stix_sighting["last_seen"]
            if "last_seen" in stix_sighting
            else date,
            count=stix_sighting["count"] if "count" in stix_sighting else 1,
            x_opencti_negative=stix_sighting["x_opencti_negative"]
            if "x_opencti_negative" in stix_sighting
            else False,
            created=stix_sighting["created"] if "created" in stix_sighting else None,
            modified=stix_sighting["modified"] if "modified" in stix_sighting else None,
            confidence=stix_sighting["confidence"]
            if "confidence" in stix_sighting
            else 15,
            createdBy=extras["created_by_id"] if "created_by_id" in extras else None,
            objectMarking=extras["object_marking_ids"]
            if "object_marking_ids" in extras
            else [],
            objectLabel=extras["object_label_ids"]
            if "object_label_ids" in extras
            else [],
            externalReferences=extras["external_references_ids"]
            if "external_references_ids" in extras
            else [],
            update=update,
            ignore_dates=stix_sighting["x_opencti_ignore_dates"]
            if "x_opencti_ignore_dates" in stix_sighting
            else None,
        )
        if stix_sighting_result is not None:
            self.mapping_cache[stix_sighting["id"]] = {
                "id": stix_sighting_result["id"],
                "type": stix_sighting_result["entity_type"],
            }
        else:
            return None

    # endregion

    # region export
    def generate_export(self, entity: Dict, no_custom_attributes: bool = False) -> Dict:
        # Handle model deviation
        # Identities
        if IdentityTypes.has_value(entity["entity_type"]):
            entity["entity_type"] = "Identity"

        # Locations
        if LocationTypes.has_value(entity["entity_type"]):
            if not not no_custom_attributes:
                entity["x_opencti_location_type"] = entity["entity_type"]
            if entity["entity_type"] == "City":
                entity["city"] = entity["name"]
            elif entity["entity_type"] == "Country":
                entity["country"] = entity["name"]
            elif entity["entity_type"] == "Region":
                entity["region"] = entity["name"]
            entity["entity_type"] = "Location"

        # Files
        if entity["entity_type"] == "StixFile":
            entity["entity_type"] = "File"

        # Dates
        if (
            "valid_from" in entity
            and "valid_until" in entity
            and entity["valid_from"] == entity["valid_until"]
        ):
            del entity["valid_from"]

        # Flatten
        if "objectLabel" in entity and len(entity["objectLabel"]) > 0:
            entity["labels"] = []
            for object_label in entity["objectLabel"]:
                entity["labels"].append(object_label["value"])
        if "objectLabel" in entity:
            del entity["objectLabel"]
            del entity["objectLabelIds"]
        if (
            not no_custom_attributes
            and "killChainPhases" in entity
            and len(entity["killChainPhases"]) > 0
        ):
            entity["kill_chain_phases"] = []
            for object_kill_chain_phase in entity["killChainPhases"]:
                kill_chain_phase = {
                    "kill_chain_name": object_kill_chain_phase["kill_chain_name"],
                    "phase_name": object_kill_chain_phase["phase_name"],
                    "x_opencti_order": object_kill_chain_phase["x_opencti_order"],
                }
                entity["kill_chain_phases"].append(kill_chain_phase)
        if "killChainPhases" in entity:
            del entity["killChainPhases"]
            del entity["killChainPhasesIds"]
        if (
            not no_custom_attributes
            and "externalReferences" in entity
            and len(entity["externalReferences"]) > 0
        ):
            entity["external_references"] = []
            for entity_external_reference in entity["externalReferences"]:
                external_reference = dict()
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
                if (
                    "importFiles" in entity_external_reference
                    and len(entity_external_reference["importFiles"]) > 0
                ):
                    external_reference["x_opencti_files"] = []
                    for file in entity_external_reference["importFiles"]:
                        url = (
                            self.opencti.api_url.replace("graphql", "storage/get/")
                            + file["id"]
                        )
                        data = self.opencti.fetch_opencti_file(
                            url, binary=True, serialize=True
                        )
                        external_reference["x_opencti_files"].append(
                            {
                                "name": file["name"],
                                "data": data,
                                "mime_type": file["metaData"]["mimetype"],
                                "version": file["metaData"]["version"],
                            }
                        )
                entity["external_references"].append(external_reference)
        if "externalReferences" in entity:
            del entity["externalReferences"]
            del entity["externalReferencesIds"]
        if "indicators" in entity:
            del entity["indicators"]
            del entity["indicatorsIds"]
        if "hashes" in entity:
            hashes = entity["hashes"]
            entity["hashes"] = {}
            for hash in hashes:
                entity["hashes"][hash["algorithm"]] = hash["hash"]

        # Final
        if not no_custom_attributes:
            entity["x_opencti_id"] = entity["id"]
        entity["id"] = entity["standard_id"]
        entity["type"] = entity["entity_type"].lower()
        del entity["standard_id"]
        del entity["entity_type"]
        del entity["parent_types"]
        if "created_at" in entity:
            del entity["created_at"]
        if "updated_at" in entity:
            del entity["updated_at"]

        return {k: v for k, v in entity.items() if self.opencti.not_empty(v)}

    def prepare_export(
        self,
        entity: Dict,
        mode: str = "simple",
        max_marking_definition_entity: Dict = None,
        no_custom_attributes: bool = False,
    ) -> List:
        if (
            self.check_max_marking_definition(
                max_marking_definition_entity,
                entity["objectMarking"] if "objectMarking" in entity else [],
            )
            is False
        ):
            self.opencti.log(
                "info",
                "Marking definitions of "
                + entity["type"]
                + " are less than max definition, not exporting.",
            )
            return []
        result = []
        objects_to_get = []
        relations_to_get = []
        # CreatedByRef
        if (
            not no_custom_attributes
            and "createdBy" in entity
            and entity["createdBy"] is not None
        ):
            created_by = self.generate_export(entity["createdBy"])
            entity["created_by_ref"] = created_by["id"]
            result.append(created_by)
        if "createdBy" in entity:
            del entity["createdBy"]
            del entity["createdById"]
        if "observables" in entity:
            del entity["observables"]
            del entity["observablesIds"]

        entity_copy = entity.copy()
        if no_custom_attributes:
            if "external_references" in entity:
                del entity["external_references"]
            for key in entity_copy.keys():
                if key.startswith("x_"):
                    del entity[key]
        # ObjectMarkingRefs
        if (
            not no_custom_attributes
            and "objectMarking" in entity
            and len(entity["objectMarking"]) > 0
        ):
            entity["object_marking_refs"] = []
            for entity_marking_definition in entity["objectMarking"]:
                if entity_marking_definition["definition_type"] == "TLP":
                    created = "2017-01-20T00:00:00.000Z"
                else:
                    created = entity_marking_definition["created"]
                marking_definition = {
                    "type": "marking-definition",
                    "spec_version": SPEC_VERSION,
                    "id": entity_marking_definition["standard_id"],
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
                result.append(marking_definition)
                entity["object_marking_refs"].append(marking_definition["id"])
        if "objectMarking" in entity:
            del entity["objectMarking"]
            del entity["objectMarkingIds"]
        # ObjectRefs
        if (
            not no_custom_attributes
            and "objects" in entity
            and len(entity["objects"]) > 0
        ):
            entity["object_refs"] = []
            objects_to_get = entity["objects"]
            for entity_object in entity["objects"]:
                if entity["type"] == "report" and entity_object["entity_type"] not in [
                    "Note",
                    "Report",
                    "Opinion",
                ]:
                    entity["object_refs"].append(entity_object["standard_id"])
                elif entity["type"] == "note" and entity_object["entity_type"] not in [
                    "Note",
                    "Opinion",
                ]:
                    entity["object_refs"].append(entity_object["standard_id"])
                elif entity["type"] == "opinion" and entity_object[
                    "entity_type"
                ] not in ["Opinion"]:
                    entity["object_refs"].append(entity_object["standard_id"])
        if "objects" in entity:
            del entity["objects"]
            del entity["objectsIds"]
        # Stix Sighting Relationship
        if entity["type"] == "stix-sighting-relationship":
            entity["type"] = "sighting"
            entity["count"] = entity["attribute_count"]
            del entity["attribute_count"]
            entity["sighting_of_ref"] = entity["from"]["standard_id"]
            objects_to_get.append(entity["from"]["standard_id"])
            entity["where_sighted_refs"] = [entity["to"]["standard_id"]]
            objects_to_get.append(entity["to"]["standard_id"])
            del entity["from"]
            del entity["to"]
        # Stix Core Relationship
        if "from" in entity or "to" in entity:
            entity["type"] = "relationship"
        if "from" in entity:
            entity["source_ref"] = entity["from"]["standard_id"]
            objects_to_get.append(entity["from"]["standard_id"])
        if "from" in entity:
            del entity["from"]
        if "to" in entity:
            entity["target_ref"] = entity["to"]["standard_id"]
            objects_to_get.append(entity["to"]["standard_id"])
        if "to" in entity:
            del entity["to"]
        # Stix Domain Object
        if "attribute_abstract" in entity:
            entity["abstract"] = entity["attribute_abstract"]
            del entity["attribute_abstract"]
        # Stix Cyber Observable
        if "observable_value" in entity:
            del entity["observable_value"]
        if "attribute_key" in entity:
            entity["key"] = entity["attribute_key"]
            del entity["attribute_key"]
        if "attribute_date" in entity:
            entity["date"] = entity["attribute_date"]
            del entity["attribute_date"]
        # Artifact
        if entity["type"] == "artifact" and "importFiles" in entity:
            first_file = entity["importFiles"][0]["id"]
            url = self.opencti.api_url.replace("graphql", "storage/get/") + first_file
            file = self.opencti.fetch_opencti_file(url, binary=True, serialize=True)
            if file:
                entity["payload_bin"] = file
        # Files
        if "importFiles" in entity and len(entity["importFiles"]) > 0:
            entity["x_opencti_files"] = []
            for file in entity["importFiles"]:
                url = (
                    self.opencti.api_url.replace("graphql", "storage/get/") + file["id"]
                )
                data = self.opencti.fetch_opencti_file(url, binary=True, serialize=True)
                entity["x_opencti_files"].append(
                    {
                        "name": file["name"],
                        "data": data,
                        "mime_type": file["metaData"]["mimetype"],
                        "version": file["metaData"]["version"],
                    }
                )
            del entity["importFiles"]
            del entity["importFilesIds"]

        # StixCyberObservable
        if entity["type"] in STIX_CYBER_OBSERVABLE_MAPPING:
            stix_observable_relationships = (
                self.opencti.stix_cyber_observable_relationship.list(
                    fromId=entity["x_opencti_id"]
                )
            )
            for stix_observable_relationship in stix_observable_relationships:
                if "standard_id" in stix_observable_relationship["to"]:
                    if MultipleStixCyberObservableRelationship.has_value(
                        stix_observable_relationship["relationship_type"]
                    ):
                        key = (
                            stix_observable_relationship["relationship_type"]
                            .replace("obs_", "")
                            .replace("-", "_")
                            + "_refs"
                        )
                        if key in entity:
                            entity[key].append(
                                stix_observable_relationship["to"]["standard_id"]
                            )
                        else:
                            entity[key] = [
                                stix_observable_relationship["to"]["standard_id"]
                            ]
                    else:
                        key = (
                            stix_observable_relationship["relationship_type"]
                            .replace("obs_", "")
                            .replace("-", "_")
                            + "_ref"
                        )
                        entity[key] = stix_observable_relationship["to"]["standard_id"]

        result.append(entity)

        if mode == "simple":
            return result
        elif mode == "full":
            uuids = [entity["id"]]
            for x in result:
                uuids.append(x["id"])
            # Get extra refs
            for key in entity.keys():
                if entity["type"] in STIX_CYBER_OBSERVABLE_MAPPING:
                    if key.endswith("_ref"):
                        type = entity[key].split("--")[0]
                        if type in STIX_CYBER_OBSERVABLE_MAPPING:
                            objects_to_get.append(
                                {
                                    "id": entity[key],
                                    "entity_type": "Stix-Cyber-Observable",
                                    "parent_types": ["Styx-Cyber-Observable"],
                                }
                            )
                    elif key.endswith("_refs"):
                        for value in entity[key]:
                            type = value.split("--")[0]
                            if type in STIX_CYBER_OBSERVABLE_MAPPING:
                                objects_to_get.append(
                                    {
                                        "id": value,
                                        "entity_type": "Stix-Cyber-Observable",
                                        "parent_types": ["Styx-Cyber-Observable"],
                                    }
                                )
            # Get extra relations (from)
            stix_core_relationships = self.opencti.stix_core_relationship.list(
                elementId=entity["x_opencti_id"]
            )
            for stix_core_relationship in stix_core_relationships:
                if self.check_max_marking_definition(
                    max_marking_definition_entity,
                    stix_core_relationship["objectMarking"]
                    if "objectMarking" in stix_core_relationship
                    else None,
                ):
                    objects_to_get.append(
                        stix_core_relationship["to"]
                        if stix_core_relationship["to"]["id"] != entity["x_opencti_id"]
                        else stix_core_relationship["from"]
                    )
                    relation_object_data = self.prepare_export(
                        self.generate_export(stix_core_relationship),
                        "simple",
                        max_marking_definition_entity,
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
                        + stix_core_relationship["entity_type"]
                        + ' "'
                        + stix_core_relationship["id"]
                        + '" are less than max definition, not exporting the relation AND the target entity.',
                    )
            # Get sighting
            stix_sighting_relationships = self.opencti.stix_sighting_relationship.list(
                elementId=entity["x_opencti_id"]
            )
            for stix_sighting_relationship in stix_sighting_relationships:
                if self.check_max_marking_definition(
                    max_marking_definition_entity,
                    stix_sighting_relationship["objectMarking"]
                    if "objectMarking" in stix_sighting_relationship
                    else None,
                ):
                    objects_to_get.append(
                        stix_sighting_relationship["to"]
                        if stix_sighting_relationship["to"]["id"]
                        != entity["x_opencti_id"]
                        else stix_sighting_relationship["from"]
                    )
                    relation_object_data = self.prepare_export(
                        self.generate_export(stix_sighting_relationship),
                        "simple",
                        max_marking_definition_entity,
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
                        + stix_sighting_relationship["entity_type"]
                        + ' "'
                        + stix_sighting_relationship["id"]
                        + '" are less than max definition, not exporting the relation AND the target entity.',
                    )

            # Export
            reader = {
                "Attack-Pattern": self.opencti.attack_pattern.read,
                "Campaign": self.opencti.campaign.read,
                "Note": self.opencti.note.read,
                "Observed-Data": self.opencti.observed_data.read,
                "Opinion": self.opencti.opinion.read,
                "Report": self.opencti.report.read,
                "Course-Of-Action": self.opencti.course_of_action.read,
                "Identity": self.opencti.identity.read,
                "Indicator": self.opencti.indicator.read,
                "Infrastructure": self.opencti.infrastructure.read,
                "Intrusion-Set": self.opencti.intrusion_set.read,
                "Location": self.opencti.location.read,
                "Language": self.opencti.language.read,
                "Malware": self.opencti.malware.read,
                "Threat-Actor": self.opencti.threat_actor.read,
                "Tool": self.opencti.tool.read,
                "Vulnerability": self.opencti.vulnerability.read,
                "Incident": self.opencti.incident.read,
                "Stix-Cyber-Observable": self.opencti.stix_cyber_observable.read,
                "stix-core-relationship": self.opencti.stix_core_relationship.read,
                "stix-sighting-relationship": self.opencti.stix_sighting_relationship.read,
            }
            # Get extra objects
            for entity_object in objects_to_get:
                # Map types
                if entity_object["entity_type"] == "StixFile":
                    entity_object["entity_type"] = "File"

                if IdentityTypes.has_value(entity_object["entity_type"]):
                    entity_object["entity_type"] = "Identity"
                elif LocationTypes.has_value(entity_object["entity_type"]):
                    entity_object["entity_type"] = "Location"
                elif StixCyberObservableTypes.has_value(entity_object["entity_type"]):
                    entity_object["entity_type"] = "Stix-Cyber-Observable"
                elif "stix-core-relationship" in entity_object["parent_types"]:
                    entity_object["entity_type"] = "stix-core-relationship"
                elif (
                    "stix-cyber-observable-relationship"
                    in entity_object["parent_types"]
                ):
                    entity_object["entity_type"] = "stix-cyber-observable-relationship"

                do_read = reader.get(
                    entity_object["entity_type"],
                    lambda **kwargs: self.unknown_type(
                        {"type": entity_object["entity_type"]}
                    ),
                )
                entity_object_data = do_read(id=entity_object["id"])
                stix_entity_object = self.prepare_export(
                    self.generate_export(entity_object_data),
                    "simple",
                    max_marking_definition_entity,
                )
                # Add to result
                entity_object_bundle = self.filter_objects(uuids, stix_entity_object)
                uuids = uuids + [x["id"] for x in entity_object_bundle]
                result = result + entity_object_bundle
            for relation_object in relations_to_get:
                relation_object_data = self.prepare_export(
                    self.opencti.stix_core_relationship.read(id=relation_object["id"])
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
                    reports = self.opencti.opencti_stix_object_or_stix_relationship.reports(id=uuid)
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
            # for export_uuid in uuids:
            #    if "marking-definition" not in export_uuid:
            #        notes = self.opencti.opencti_stix_object_or_stix_relationship.notes(
            #            id=export_uuid
            #        )
            #        for note in notes:
            #            note_object_data = self.opencti.note.to_stix2(
            #                entity=note,
            #                mode="simple",
            #                max_marking_definition_entity=max_marking_definition_entity,
            #            )
            #            note_object_bundle = self.filter_objects(
            #                uuids, note_object_data
            #            )
            #            uuids = uuids + [x["id"] for x in note_object_bundle]
            #            result = result + note_object_bundle

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

    def export_entity(
        self,
        entity_type: str,
        entity_id: str,
        mode: str = "simple",
        max_marking_definition: Dict = None,
        no_custom_attributes: bool = False,
    ) -> Dict:
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
            entity_type = "Identity"
        if LocationTypes.has_value(entity_type):
            entity_type = "Location"

        # Reader
        reader = {
            "Attack-Pattern": self.opencti.attack_pattern.read,
            "Campaign": self.opencti.campaign.read,
            "Event": self.opencti.campaign.read,
            "Note": self.opencti.note.read,
            "Observed-Data": self.opencti.observed_data.read,
            "Opinion": self.opencti.opinion.read,
            "Report": self.opencti.report.read,
            "Course-Of-Action": self.opencti.course_of_action.read,
            "Identity": self.opencti.identity.read,
            "Indicator": self.opencti.indicator.read,
            "Infrastructure": self.opencti.infrastructure.read,
            "Intrusion-Set": self.opencti.intrusion_set.read,
            "Location": self.opencti.location.read,
            "Language": self.opencti.language.read,
            "Malware": self.opencti.malware.read,
            "Threat-Actor": self.opencti.threat_actor.read,
            "Tool": self.opencti.tool.read,
            "Channel": self.opencti.channel.read,
            "Narrative": self.opencti.narrative.read,
            "Vulnerability": self.opencti.vulnerability.read,
            "Incident": self.opencti.incident.read,
            "Stix-Cyber-Observable": self.opencti.stix_cyber_observable.read,
            "stix-core-relationship": self.opencti.stix_core_relationship.read,
        }
        if StixCyberObservableTypes.has_value(entity_type):
            entity_type = "Stix-Cyber-Observable"
        do_read = reader.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        entity = do_read(id=entity_id)
        if entity is None:
            self.opencti.log("error", "Cannot export entity (not found)")
            return bundle
        stix_objects = self.prepare_export(
            self.generate_export(entity, no_custom_attributes),
            mode,
            max_marking_definition_entity,
            no_custom_attributes,
        )
        if stix_objects is not None:
            bundle["objects"].extend(stix_objects)
        return bundle

    def export_list(
        self,
        entity_type: str,
        search: Dict = None,
        filters: List = None,
        order_by: str = None,
        order_mode: str = None,
        max_marking_definition: Dict = None,
        types: List = None,
        fromId: str = None,
        toId: str = None,
        fromTypes: [str] = None,
        toTypes: [str] = None,
    ) -> Dict:
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
        if entity_type == "StixFile":
            entity_type = "File"

        if IdentityTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Identity"

        if LocationTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Location"

        if StixCyberObservableTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Stix-Cyber-Observable"

        # List
        lister = {
            "Stix-Domain-Object": self.opencti.stix_domain_object.list,
            "Attack-Pattern": self.opencti.attack_pattern.list,
            "Campaign": self.opencti.campaign.list,
            "Event": self.opencti.event.list,
            "Note": self.opencti.note.list,
            "Observed-Data": self.opencti.observed_data.list,
            "Opinion": self.opencti.opinion.list,
            "Report": self.opencti.report.list,
            "Course-Of-Action": self.opencti.course_of_action.list,
            "Identity": self.opencti.identity.list,
            "Indicator": self.opencti.indicator.list,
            "Infrastructure": self.opencti.infrastructure.list,
            "Intrusion-Set": self.opencti.intrusion_set.list,
            "Location": self.opencti.location.list,
            "Language": self.opencti.language.list,
            "Malware": self.opencti.malware.list,
            "Threat-Actor": self.opencti.threat_actor.list,
            "Tool": self.opencti.tool.list,
            "Channel": self.opencti.channel.list,
            "Narrative": self.opencti.narrative.list,
            "Vulnerability": self.opencti.vulnerability.list,
            "Incident": self.opencti.incident.list,
            "Stix-Cyber-Observable": self.opencti.stix_cyber_observable.list,
            "stix-sighting-relationship": self.opencti.stix_sighting_relationship.list,
            "stix-core-relationship": self.opencti.stix_core_relationship.list,
        }
        do_list = lister.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        entities_list = do_list(
            search=search,
            filters=filters,
            orderBy=order_by,
            orderMode=order_mode,
            types=types,
            getAll=True,
            fromId=fromId,
            toId=toId,
            fromTypes=fromTypes,
            toTypes=toTypes,
        )
        if entities_list is not None:
            uuids = []
            for entity in entities_list:
                entity_bundle = self.prepare_export(
                    self.generate_export(entity),
                    "simple",
                    max_marking_definition_entity,
                )
                if entity_bundle is not None:
                    entity_bundle_filtered = self.filter_objects(uuids, entity_bundle)
                    for x in entity_bundle_filtered:
                        uuids.append(x["id"])
                    bundle["objects"] = bundle["objects"] + entity_bundle_filtered
        return bundle

    def import_bundle(
        self,
        stix_bundle: Dict,
        update: bool = False,
        types: List = None,
        retry_number: int = None,
    ) -> List:
        # Check if the bundle is correctly formatted
        if "type" not in stix_bundle or stix_bundle["type"] != "bundle":
            raise ValueError("JSON data type is not a STIX2 bundle")
        if "objects" not in stix_bundle or len(stix_bundle["objects"]) == 0:
            raise ValueError("JSON data objects is empty")
        event_version = (
            stix_bundle["x_opencti_event_version"]
            if "x_opencti_event_version" in stix_bundle
            else None
        )
        if retry_number is not None:
            self.opencti.set_retry_number(retry_number)
        stix2_splitter = OpenCTIStix2Splitter()
        try:
            bundles = stix2_splitter.split_bundle(stix_bundle, False, event_version)
        except RecursionError:
            bundles = [stix_bundle]
        # Import every elements in a specific order
        imported_elements = []

        # Marking definitions
        for bundle in bundles:
            for item in bundle["objects"]:
                if "x_opencti_event_version" in bundle:
                    if bundle["x_opencti_event_version"] == "3":
                        if "x_opencti_patch" in item:
                            self.stix2_update.process_update(item)
                            continue
                if item["type"] == "relationship":
                    self.import_relationship(item, update, types)
                elif item["type"] == "sighting":
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
                    # Import observed_data_refs
                    if "observed_data_refs" in item:
                        for observed_data_ref in item["observed_data_refs"]:
                            if len(to_ids) > 0:
                                for to_id in to_ids:
                                    self.import_sighting(
                                        item, observed_data_ref, to_id, update
                                    )
                elif item["type"] == "label":
                    stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
                    self.opencti.label.create(
                        stix_id=item["id"],
                        value=item["value"],
                        color=item["color"],
                        x_opencti_stix_ids=stix_ids,
                        update=update,
                    )
                elif item["type"] == "external-reference":
                    stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
                    self.opencti.external_reference.create(
                        stix_id=item["id"],
                        source_name=item["source_name"]
                        if "source_name" in item
                        else None,
                        url=item["url"] if "url" in item else None,
                        external_id=item["external_id"]
                        if "external_id" in item
                        else None,
                        description=item["description"]
                        if "description" in item
                        else None,
                        x_opencti_stix_ids=stix_ids,
                        update=update,
                    )
                elif item["type"] == "kill-chain-phase":
                    stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
                    self.opencti.kill_chain_phase.create(
                        stix_id=item["id"],
                        kill_chain_name=item["kill_chain_name"],
                        phase_name=item["phase_name"],
                        x_opencti_order=item["order"] if "order" in item else 0,
                        x_opencti_stix_ids=stix_ids,
                        update=update,
                    )
                elif StixCyberObservableTypes.has_value(item["type"]):
                    if types is None or len(types) == 0:
                        self.import_observable(item, update, types)
                    elif item["type"] in types or "observable" in types:
                        self.import_observable(item, update, types)
                else:
                    # Check the scope
                    if (
                        item["type"] == "marking-definition"
                        or types is None
                        or len(types) == 0
                    ):
                        self.import_object(item, update, types)
                    # Handle identity & location if part of the scope
                    elif item["type"] in types:
                        self.import_object(item, update, types)
                    else:
                        # Specific OpenCTI scopes
                        if item["type"] == "identity":
                            if "identity_class" in item:
                                if ("class" in types or "sector" in types) and item[
                                    "identity_class"
                                ] == "class":
                                    self.import_object(item, update, types)
                                elif item["identity_class"] in types:
                                    self.import_object(item, update, types)
                        elif item["type"] == "location":
                            if "x_opencti_location_type" in item:
                                if item["x_opencti_location_type"].lower() in types:
                                    self.import_object(item, update, types)
                            elif (
                                self.opencti.get_attribute_in_extension(
                                    "location_type", item
                                )
                                is not None
                            ):
                                if (
                                    self.opencti.get_attribute_in_extension(
                                        "location_type", item
                                    ).lower()
                                    in types
                                ):
                                    self.import_object(item, update, types)
                imported_elements.append({"id": item["id"], "type": item["type"]})

        return imported_elements
