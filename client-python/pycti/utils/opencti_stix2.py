import base64
import datetime
import json
import os
import random
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

import datefinder
import dateutil.parser
import pytz
from cachetools import LRUCache
from opentelemetry import metrics
from requests import RequestException, Timeout
from typing_extensions import deprecated

from pycti.entities.opencti_identity import Identity
from pycti.utils.constants import (
    IdentityTypes,
    LocationTypes,
    MultipleRefRelationship,
    StixCyberObservableTypes,
    ThreatActorTypes,
)
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter
from pycti.utils.opencti_stix2_update import OpenCTIStix2Update
from pycti.utils.opencti_stix2_utils import (
    OBSERVABLES_VALUE_INT,
    STIX_CORE_OBJECTS,
    STIX_CYBER_OBSERVABLE_MAPPING,
    STIX_META_OBJECTS,
    OpenCTIStix2Utils,
)

datefinder.ValueError = ValueError, OverflowError
utc = pytz.UTC

# For Python 3.11+, datetime.UTC is preferred over datetime.timezone.utc
# Fallback to datetime.timezone.utc for older Python versions
UTC = getattr(datetime, "UTC", datetime.timezone.utc)

# Spec version
SPEC_VERSION = "2.1"
ERROR_TYPE_LOCK = "LOCK_ERROR"
ERROR_TYPE_MISSING_REFERENCE = "MISSING_REFERENCE_ERROR"
ERROR_TYPE_BAD_GATEWAY = "Bad Gateway"
ERROR_TYPE_DRAFT_LOCK = "DRAFT_LOCKED"
ERROR_TYPE_TIMEOUT = "Request timed out"

# Extensions
STIX_EXT_OCTI = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
STIX_EXT_OCTI_SCO = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
STIX_EXT_MITRE = "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
PROCESSING_COUNT: int = 4
MAX_PROCESSING_COUNT: int = 100

meter = metrics.get_meter(__name__)
bundles_timeout_error_counter = meter.create_counter(
    name="opencti_bundles_timeout_error_counter",
    description="number of bundles in timeout error",
)
bundles_lock_error_counter = meter.create_counter(
    name="opencti_bundles_lock_error_counter",
    description="number of bundles in lock error",
)
bundles_missing_reference_error_counter = meter.create_counter(
    name="opencti_bundles_missing_reference_error_counter",
    description="number of bundles in missing reference error",
)
bundles_bad_gateway_error_counter = meter.create_counter(
    name="opencti_bundles_bad_gateway_error_counter",
    description="number of bundles in bad gateway error",
)
bundles_timed_out_error_counter = meter.create_counter(
    name="opencti_bundles_timed_out_error_counter",
    description="number of bundles in timed out error",
)
bundles_technical_error_counter = meter.create_counter(
    name="opencti_bundles_technical_error_counter",
    description="number of bundles in technical error",
)
bundles_success_counter = meter.create_counter(
    name="opencti_bundles_success_counter",
    description="number of bundles successfully processed",
)


class OpenCTIStix2:
    """Python API for Stix2 in OpenCTI.

    Handles conversion between STIX2 format and OpenCTI internal format,
    including import/export operations and bundle processing.

    :param opencti: OpenCTI API client instance
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the OpenCTIStix2 helper.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.stix2_update = OpenCTIStix2Update(opencti)
        self.mapping_cache = LRUCache(maxsize=50000)
        self.mapping_cache_permanent = {}

    def get_in_cache(self, data_id):
        """Get an item from the cache.

        :param data_id: ID of the data to retrieve
        :type data_id: str
        :return: Cached data or None if not found
        :rtype: dict or None
        """
        api_draft_id = self.opencti.get_draft_id()
        if data_id + api_draft_id in self.mapping_cache:
            return self.mapping_cache[data_id + api_draft_id]
        return None

    def set_in_cache(self, data_id, data):
        """Store an item in the cache.

        :param data_id: ID of the data to store
        :type data_id: str
        :param data: Data to cache
        :type data: dict
        """
        api_draft_id = self.opencti.get_draft_id()
        self.mapping_cache[data_id + api_draft_id] = data

    ######### UTILS
    # region utils
    def unknown_type(self, stix_object: Dict) -> None:
        """Log an error for unknown STIX object types.

        :param stix_object: STIX object with unknown type
        :type stix_object: Dict
        """
        self.opencti.app_logger.error(
            "Unknown object type, doing nothing...", {"type": stix_object["type"]}
        )

    def convert_markdown(self, text: str) -> str:
        """Convert input text to markdown style code annotation.

        :param text: Input text to convert
        :type text: str
        :return: Sanitized text with markdown style code annotation
        :rtype: str
        """
        if text is not None:
            return text.replace("<code>", "`").replace("</code>", "`")
        else:
            return None

    def format_date(self, date: Any = None) -> str:
        """Convert multiple input date formats to OpenCTI style dates.

        :param date: Input date (datetime, date, str or None)
        :type date: Any
        :return: ISO 8601 formatted date string
        :rtype: str
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
            date_value = datetime.datetime.now(tz=UTC)

        if not date_value.tzinfo:
            self.opencti.app_logger.info("No timezone found. Setting to UTC")
            date_value = date_value.replace(tzinfo=UTC)

        return date_value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def filter_objects(self, uuids: List, objects: List) -> List:
        """Filter objects based on UUIDs.

        :param uuids: List of UUIDs to filter by
        :type uuids: list
        :param objects: List of objects to filter
        :type objects: list
        :return: List of filtered objects not in the uuids list
        :rtype: list
        """

        result = []
        if objects is not None:
            for item in objects:
                if "id" in item and item["id"] not in uuids:
                    result.append(item)
        return result

    def pick_aliases(self, stix_object: Dict) -> Optional[List]:
        """Check STIX2 object for multiple aliases and return a list.

        :param stix_object: Valid STIX2 object
        :type stix_object: Dict
        :return: List of aliases or None if no aliases found
        :rtype: list or None
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

    def import_bundle_from_file(
        self,
        file_path: str,
        update: bool = False,
        types: List = None,
    ) -> Optional[Tuple[list, list]]:
        """Import a STIX2 bundle from a file.

        :param file_path: Valid path to the file
        :type file_path: str
        :param update: Whether to update data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        :return: Tuple of (imported objects, failed objects) or None if file not found
        :rtype: Tuple[list, list] or None
        """
        if not os.path.isfile(file_path):
            self.opencti.app_logger.error("The bundle file does not exist")
            return None
        with open(os.path.join(file_path), encoding="utf-8") as file:
            data = json.load(file)
        return self.import_bundle(data, update, types, None)

    def import_bundle_from_json(
        self,
        json_data: Union[str, bytes],
        update: bool = False,
        types: List = None,
        work_id: str = None,
        objects_max_refs: int = 0,
    ) -> Tuple[list, list]:
        """Import a STIX2 bundle from JSON data.

        :param json_data: JSON data as string or bytes
        :type json_data: str or bytes
        :param update: Whether to update data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        :param work_id: Work ID for tracking import progress
        :type work_id: str, optional
        :param objects_max_refs: Maximum object references; rejects import if exceeded
        :type objects_max_refs: int, optional
        :return: Tuple of (imported objects, objects with too many dependencies)
        :rtype: Tuple[list, list]
        """
        data = json.loads(json_data)
        return self.import_bundle(data, update, types, work_id, objects_max_refs)

    def resolve_author(self, title: str) -> Optional[Identity]:
        """Resolve an author identity from a title string.

        :param title: Title to search for known author names
        :type title: str
        :return: Identity object if author found, None otherwise
        :rtype: Identity or None
        """
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
        """Get or create an author identity by name.

        :param name: Name of the author organization
        :type name: str
        :return: Identity object for the author
        :rtype: Identity
        """
        name_in_cache = self.get_in_cache(name)
        if name_in_cache is not None:
            return name_in_cache
        else:
            author = self.opencti.identity.create(
                type="Organization",
                name=name,
                description="",
            )
            self.set_in_cache(name, author)
            return author

    def extract_embedded_relationships(
        self, stix_object: Dict, types: List = None
    ) -> Dict:
        """Extract embedded relationship objects from a STIX2 entity.

        :param stix_object: Valid STIX2 object
        :type stix_object: Dict
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        :return: Dictionary containing embedded relationships and references
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
            else None
        )

        # Open vocabularies
        object_open_vocabularies = {}
        if self.mapping_cache_permanent.get("vocabularies_definition_fields") is None:
            self.mapping_cache_permanent["vocabularies_definition_fields"] = []
            query = """
                    query getVocabCategories {
                      vocabularyCategories {
                        key
                        fields{
                          key
                          required
                        }
                      }
                    }
                """
            result = self.opencti.query(query)
            for category in result["data"]["vocabularyCategories"]:
                for field in category["fields"]:
                    self.mapping_cache_permanent[
                        "vocabularies_definition_fields"
                    ].append(field)
                    self.mapping_cache_permanent["category_" + field["key"]] = category[
                        "key"
                    ]
        if any(
            field["key"] in stix_object
            for field in self.mapping_cache_permanent["vocabularies_definition_fields"]
        ):
            for f in self.mapping_cache_permanent["vocabularies_definition_fields"]:
                if (
                    stix_object.get(f["key"]) is None
                    or len(stix_object.get(f["key"])) == 0
                ):
                    continue
                if isinstance(stix_object.get(f["key"]), list):
                    object_open_vocabularies[f["key"]] = []
                    for vocab in stix_object[f["key"]]:
                        resolved_vocab = (
                            self.opencti.vocabulary.read_or_create_unchecked_with_cache(
                                vocab, self.mapping_cache_permanent, field=f
                            )
                        )
                        if resolved_vocab is not None:
                            object_open_vocabularies[f["key"]].append(
                                resolved_vocab["name"]
                            )
                else:
                    resolved_vocab = (
                        self.opencti.vocabulary.read_or_create_unchecked_with_cache(
                            stix_object[f["key"]], self.mapping_cache_permanent, field=f
                        )
                    )
                    if resolved_vocab is not None:
                        object_open_vocabularies[f["key"]] = resolved_vocab["name"]

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
                label_key = "label_" + label
                label_in_cache = self.get_in_cache(label_key)
                if label_in_cache is not None:
                    label_data = label_in_cache
                else:
                    # Fail in label creation is allowed
                    label_data = self.opencti.label.read_or_create_unchecked(
                        value=label
                    )
                if label_data is not None:
                    self.set_in_cache(label_key, label_data)
                    object_label_ids.append(label_data["id"])
        elif "x_opencti_labels" in stix_object:
            for label in stix_object["x_opencti_labels"]:
                label_key = "label_" + label
                label_in_cache = self.get_in_cache(label_key)
                if label_in_cache is not None:
                    label_data = label_in_cache
                else:
                    # Fail in label creation is allowed
                    label_data = self.opencti.label.read_or_create_unchecked(
                        value=label
                    )
                if label_data is not None:
                    self.set_in_cache(label_key, label_data)
                    object_label_ids.append(label_data["id"])
        elif "x_opencti_tags" in stix_object:
            for tag in stix_object["x_opencti_tags"]:
                label = tag["value"]
                color = tag["color"] if "color" in tag else None
                label_key = "label_" + label
                label_in_cache = self.get_in_cache(label_key)
                if label_in_cache is not None:
                    label_data = label_in_cache
                else:
                    # Fail in label creation is allowed
                    label_data = self.opencti.label.read_or_create_unchecked(
                        value=label, color=color
                    )
                if label_data is not None:
                    self.set_in_cache(label_key, label_data)
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
        if (
            "kill_chain_phases" in stix_object
            and stix_object["kill_chain_phases"] is not None
        ):
            for kill_chain_phase in stix_object["kill_chain_phases"]:
                kill_chain_phase_key = (
                    kill_chain_phase["kill_chain_name"] + kill_chain_phase["phase_name"]
                )
                kill_chain_phase_in_cache = self.get_in_cache(kill_chain_phase_key)
                if kill_chain_phase_in_cache is not None:
                    kill_chain_phase = kill_chain_phase_in_cache
                else:
                    if (
                        "x_opencti_order" not in kill_chain_phase
                        and self.opencti.get_attribute_in_extension(
                            "order", kill_chain_phase
                        )
                        is not None
                    ):
                        kill_chain_phase["x_opencti_order"] = (
                            self.opencti.get_attribute_in_extension(
                                "order", kill_chain_phase
                            )
                        )
                    kill_chain_phase = self.opencti.kill_chain_phase.create(
                        kill_chain_name=kill_chain_phase["kill_chain_name"],
                        phase_name=kill_chain_phase["phase_name"],
                        x_opencti_order=(
                            kill_chain_phase["x_opencti_order"]
                            if "x_opencti_order" in kill_chain_phase
                            else 0
                        ),
                        stix_id=(
                            kill_chain_phase["id"] if "id" in kill_chain_phase else None
                        ),
                    )
                    kill_chain_phase_cache_data = {
                        "id": kill_chain_phase["id"],
                        "type": kill_chain_phase["entity_type"],
                    }
                    self.set_in_cache(kill_chain_phase_key, kill_chain_phase_cache_data)
                kill_chain_phases_ids.append(kill_chain_phase["id"])
        elif (
            "x_opencti_kill_chain_phases" in stix_object
            and stix_object["x_opencti_kill_chain_phases"] is not None
        ):
            for kill_chain_phase in stix_object["x_opencti_kill_chain_phases"]:
                kill_chain_phase_key = (
                    kill_chain_phase["kill_chain_name"] + kill_chain_phase["phase_name"]
                )
                kill_chain_phase_in_cache = self.get_in_cache(kill_chain_phase_key)
                if kill_chain_phase_in_cache is not None:
                    kill_chain_phase = kill_chain_phase_in_cache
                else:
                    if (
                        "x_opencti_order" not in kill_chain_phase
                        and self.opencti.get_attribute_in_extension(
                            "order", kill_chain_phase
                        )
                        is not None
                    ):
                        kill_chain_phase["x_opencti_order"] = (
                            self.opencti.get_attribute_in_extension(
                                "order", kill_chain_phase
                            )
                        )
                    kill_chain_phase = self.opencti.kill_chain_phase.create(
                        kill_chain_name=kill_chain_phase["kill_chain_name"],
                        phase_name=kill_chain_phase["phase_name"],
                        x_opencti_order=(
                            kill_chain_phase["x_opencti_order"]
                            if "x_opencti_order" in kill_chain_phase
                            else 0
                        ),
                        stix_id=(
                            kill_chain_phase["id"] if "id" in kill_chain_phase else None
                        ),
                    )
                    kill_chain_phase_cache_data = {
                        "id": kill_chain_phase["id"],
                        "type": kill_chain_phase["entity_type"],
                    }
                    self.set_in_cache(kill_chain_phase_key, kill_chain_phase_cache_data)
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
            stix_object["external_references"] = (
                self.opencti.get_attribute_in_extension(
                    "external_references", stix_object
                )
            )
        if (
            "external_references" in stix_object
            and stix_object["external_references"] is not None
        ):
            for external_reference in stix_object["external_references"]:
                try:
                    url = (
                        external_reference["url"]
                        if "url" in external_reference
                        else None
                    )
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
                    else:
                        # Collect files for external reference
                        ext_ref_files = []
                        if "x_opencti_files" in external_reference:
                            ext_ref_files.extend(external_reference["x_opencti_files"])
                        if (
                            self.opencti.get_attribute_in_extension(
                                "files", external_reference
                            )
                            is not None
                        ):
                            ext_ref_files.extend(
                                self.opencti.get_attribute_in_extension(
                                    "files", external_reference
                                )
                            )

                        # Prepare first file for upload during creation
                        file_to_upload = None
                        file_markings = None
                        if len(ext_ref_files) > 0:
                            first_file = ext_ref_files[0]
                            data = None
                            if "data" in first_file:
                                data = base64.b64decode(first_file["data"])
                            elif "uri" in first_file:
                                file_url = self.opencti.api_url.replace(
                                    "/graphql", first_file["uri"]
                                )
                                data = self.opencti.fetch_opencti_file(
                                    fetch_uri=file_url, binary=True, serialize=False
                                )
                            if data is not None:
                                file_to_upload = self.opencti.file(
                                    first_file["name"],
                                    data,
                                    first_file.get(
                                        "mime_type", "application/octet-stream"
                                    ),
                                )
                                file_markings = first_file.get(
                                    "object_marking_refs", None
                                )

                        # Create external reference with first file attached
                        external_reference_id = self.opencti.external_reference.create(
                            source_name=source_name,
                            url=url,
                            external_id=external_id,
                            description=(
                                external_reference["description"]
                                if "description" in external_reference
                                else None
                            ),
                            file=file_to_upload,
                            fileMarkings=file_markings,
                        )["id"]

                    # Upload additional files after creation (first file attached during creation)
                    if len(ext_ref_files) > 1:
                        for file in ext_ref_files[1:]:
                            data = None
                            if "data" in file:
                                data = base64.b64decode(file["data"])
                            elif "uri" in file:
                                file_url = self.opencti.api_url.replace(
                                    "/graphql", file["uri"]
                                )
                                data = self.opencti.fetch_opencti_file(
                                    fetch_uri=file_url, binary=True, serialize=False
                                )
                            if data is not None:
                                self.opencti.external_reference.add_file(
                                    id=external_reference_id,
                                    file_name=file["name"],
                                    version=file.get("version", None),
                                    data=data,
                                    fileMarkings=file.get("object_marking_refs", None),
                                    mime_type=file.get(
                                        "mime_type", "application/octet-stream"
                                    ),
                                    no_trigger_import=file.get(
                                        "no_trigger_import", False
                                    ),
                                )
                    external_references_ids.append(external_reference_id)
                    if stix_object["type"] in [
                        "threat-actor",
                        "intrusion-set",
                        "campaign",
                        "incident",
                        "malware",
                        "relationship",
                    ] and (
                        types is not None and "external-reference-as-report" in types
                    ):
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
                        except (TypeError, OverflowError):
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
                            except (TypeError, OverflowError):
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
                                title
                                + " ("
                                + str(external_reference["external_id"])
                                + ")"
                            )
                        marking_tlp_clear = self.get_in_cache("marking_tlpclear")
                        if marking_tlp_clear is not None:
                            object_marking_ref_result = marking_tlp_clear
                        else:
                            object_marking_ref_result = (
                                self.opencti.marking_definition.read(
                                    filters={
                                        "mode": "and",
                                        "filters": [
                                            {
                                                "key": "definition_type",
                                                "values": ["TLP"],
                                            },
                                            {
                                                "key": "definition",
                                                "values": ["TLP:CLEAR"],
                                            },
                                        ],
                                        "filterGroups": [],
                                    }
                                )
                            )
                            self.set_in_cache(
                                "marking_tlpclear",
                                {"id": object_marking_ref_result["id"]},
                            )

                        author = self.resolve_author(title)
                        report = self.opencti.report.create(
                            id=self.opencti.report.generate_fixed_fake_id(
                                title, published
                            ),
                            name=title,
                            createdBy=author["id"] if author is not None else None,
                            objectMarking=[object_marking_ref_result["id"]],
                            externalReferences=[external_reference_id],
                            description=(
                                external_reference["description"]
                                if "description" in external_reference
                                else ""
                            ),
                            report_types="threat-report",
                            published=published,
                            update=True,
                        )
                        reports[external_reference_id] = report
                except Exception:
                    self.opencti.app_logger.warning(
                        "Cannot generate external reference"
                    )
        elif (
            "x_opencti_external_references" in stix_object
            and stix_object["x_opencti_external_references"] is not None
        ):
            for external_reference in stix_object["x_opencti_external_references"]:
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
                else:
                    # Prepare file for direct upload during creation
                    file_to_upload = None
                    file_markings = None
                    all_files = []
                    if "x_opencti_files" in external_reference:
                        all_files = external_reference["x_opencti_files"]
                    elif (
                        self.opencti.get_attribute_in_extension(
                            "files", external_reference
                        )
                        is not None
                    ):
                        all_files = self.opencti.get_attribute_in_extension(
                            "files", external_reference
                        )

                    if len(all_files) > 0:
                        file = all_files[0]
                        data = None
                        if "data" in file:
                            data = base64.b64decode(file["data"])
                        elif "uri" in file:
                            file_url = self.opencti.api_url.replace(
                                "/graphql", file["uri"]
                            )
                            data = self.opencti.fetch_opencti_file(
                                fetch_uri=file_url, binary=True, serialize=False
                            )
                        if data is not None:
                            file_to_upload = self.opencti.file(
                                file["name"],
                                data,
                                file.get("mime_type", "application/octet-stream"),
                            )
                            file_markings = file.get("object_marking_refs", None)

                    external_reference_id = self.opencti.external_reference.create(
                        source_name=source_name,
                        url=url,
                        external_id=external_id,
                        description=(
                            external_reference["description"]
                            if "description" in external_reference
                            else None
                        ),
                        file=file_to_upload,
                        fileMarkings=file_markings,
                    )["id"]

                    # Upload additional files (beyond the first one)
                    for file in all_files[1:]:
                        data = None
                        if "data" in file:
                            data = base64.b64decode(file["data"])
                        elif "uri" in file:
                            file_url = self.opencti.api_url.replace(
                                "/graphql", file["uri"]
                            )
                            data = self.opencti.fetch_opencti_file(
                                fetch_uri=file_url, binary=True, serialize=False
                            )
                        if data is not None:
                            self.opencti.external_reference.add_file(
                                id=external_reference_id,
                                file_name=file["name"],
                                version=file.get("version", None),
                                data=data,
                                fileMarkings=file.get("object_marking_refs", None),
                                mime_type=file.get(
                                    "mime_type", "application/octet-stream"
                                ),
                                no_trigger_import=file.get("no_trigger_import", False),
                                embedded=file.get("embedded", False),
                            )
                external_references_ids.append(external_reference_id)
        # Granted refs
        granted_refs_ids = []
        if (
            "x_opencti_granted_refs" not in stix_object
            and self.opencti.get_attribute_in_extension("granted_refs", stix_object)
            is not None
        ):
            granted_refs_ids = self.opencti.get_attribute_in_extension(
                "granted_refs", stix_object
            )
        elif (
            "x_opencti_granted_refs" in stix_object
            and stix_object["x_opencti_granted_refs"] is not None
        ):
            granted_refs_ids = stix_object["x_opencti_granted_refs"]
        # Sample refs
        sample_refs_ids = (
            stix_object["sample_refs"] if "sample_refs" in stix_object else []
        )

        return {
            "created_by": created_by_id,
            "object_marking": object_marking_ids,
            "object_label": object_label_ids,
            "open_vocabs": object_open_vocabularies,
            "kill_chain_phases": kill_chain_phases_ids,
            "object_refs": object_refs_ids,
            "granted_refs": granted_refs_ids,
            "sample_refs": sample_refs_ids,
            "external_references": external_references_ids,
            "reports": reports,
        }

    # Please use get_reader instead of this definition
    def get_readers(self):
        """Get a dictionary mapping entity types to their read methods.

        :return: Dictionary mapping entity types to read functions
        :rtype: dict
        """
        return {
            "Attack-Pattern": self.opencti.attack_pattern.read,
            "Campaign": self.opencti.campaign.read,
            "Case-Incident": self.opencti.case_incident.read,
            "Case-Rfi": self.opencti.case_rfi.read,
            "Case-Rft": self.opencti.case_rft.read,
            "Channel": self.opencti.channel.read,
            "Course-Of-Action": self.opencti.course_of_action.read,
            "Data-Component": self.opencti.data_component.read,
            "Data-Source": self.opencti.data_source.read,
            "Event": self.opencti.event.read,
            "External-Reference": self.opencti.external_reference.read,
            "Feedback": self.opencti.feedback.read,
            "Grouping": self.opencti.grouping.read,
            "Incident": self.opencti.incident.read,
            "Identity": self.opencti.identity.read,
            "Indicator": self.opencti.indicator.read,
            "Infrastructure": self.opencti.infrastructure.read,
            "Intrusion-Set": self.opencti.intrusion_set.read,
            "Kill-Chain-Phase": self.opencti.kill_chain_phase.read,
            "Label": self.opencti.label.read,
            "Location": self.opencti.location.read,
            "Language": self.opencti.language.read,
            "Malware": self.opencti.malware.read,
            "Malware-Analysis": self.opencti.malware_analysis.read,
            "Marking-Definition": self.opencti.marking_definition.read,
            "Narrative": self.opencti.narrative.read,
            "Note": self.opencti.note.read,
            "Observed-Data": self.opencti.observed_data.read,
            "Opinion": self.opencti.opinion.read,
            "Report": self.opencti.report.read,
            "Stix-Core-Object": self.opencti.stix_core_object.read,
            "Stix-Cyber-Observable": self.opencti.stix_cyber_observable.read,
            "Stix-Domain-Object": self.opencti.stix_domain_object.read,
            "stix-core-relationship": self.opencti.stix_core_relationship.read,
            "stix-sighting-relationship": self.opencti.stix_sighting_relationship.read,
            "stix-nested-relationship": self.opencti.stix_nested_ref_relationship.read,
            "Task": self.opencti.task.read,
            "Threat-Actor": self.opencti.threat_actor.read,
            "Threat-Actor-Group": self.opencti.threat_actor_group.read,
            "Threat-Actor-Individual": self.opencti.threat_actor_individual.read,
            "Tool": self.opencti.tool.read,
            "Vocabulary": self.opencti.vocabulary.read,
            "Vulnerability": self.opencti.vulnerability.read,
            "Security-Coverage": self.opencti.security_coverage.read,
        }

    def get_reader(self, entity_type: str):
        """Get the appropriate reader function for a given entity type.

        :param entity_type: Type of the entity
        :type entity_type: str
        :return: Reader function for the entity type
        :rtype: callable or None
        """
        # Map types
        if entity_type == "StixFile":
            entity_type = "File"
        if IdentityTypes.has_value(entity_type):
            entity_type = "Identity"
        if LocationTypes.has_value(entity_type):
            entity_type = "Location"
        if entity_type == "Container":
            entity_type = "Stix-Domain-Object"
        if StixCyberObservableTypes.has_value(entity_type):
            entity_type = "Stix-Cyber-Observable"

        readers = self.get_readers()
        return readers.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )

    # endregion

    def get_stix_helper(self):
        """Get a dictionary mapping STIX types to their helper functions.

        :return: Dictionary mapping STIX types to generate_id functions
        :rtype: dict
        """
        # Import
        return {
            # entities
            "attack-pattern": self.opencti.attack_pattern,
            "campaign": self.opencti.campaign,
            "note": self.opencti.note,
            "observed-data": self.opencti.observed_data,
            "opinion": self.opencti.opinion,
            "report": self.opencti.report,
            "course-of-action": self.opencti.course_of_action,
            "identity": self.opencti.identity,
            "infrastructure": self.opencti.infrastructure,
            "intrusion-set": self.opencti.intrusion_set,
            "location": self.opencti.location,
            "malware": self.opencti.malware,
            "threat-actor": self.opencti.threat_actor,
            "tool": self.opencti.tool,
            "vulnerability": self.opencti.vulnerability,
            "incident": self.opencti.incident,
            "x-opencti-incident": self.opencti.incident,
            "marking-definition": self.opencti.marking_definition,
            "case-rfi": self.opencti.case_rfi,
            "x-opencti-case-rfi": self.opencti.case_rfi,
            "case-rft": self.opencti.case_rft,
            "x-opencti-case-rft": self.opencti.case_rft,
            "case-incident": self.opencti.case_incident,
            "x-opencti-case-incident": self.opencti.case_incident,
            "feedback": self.opencti.feedback,
            "x-opencti-feedback": self.opencti.feedback,
            "channel": self.opencti.channel,
            "data-component": self.opencti.data_component,
            "x-mitre-data-component": self.opencti.data_component,
            "data-source": self.opencti.data_source,
            "x-mitre-data-source": self.opencti.data_source,
            "event": self.opencti.event,
            "grouping": self.opencti.grouping,
            "indicator": self.opencti.indicator,
            "language": self.opencti.language,
            "malware-analysis": self.opencti.malware_analysis,
            "narrative": self.opencti.narrative,
            "task": self.opencti.task,
            "x-opencti-task": self.opencti.task,
            "security-coverage": self.opencti.security_coverage,
            "vocabulary": self.opencti.vocabulary,
            # relationships
            "relationship": self.opencti.stix_core_relationship,
            "sighting": self.opencti.stix_sighting_relationship,
        }

    def get_internal_helper(self):
        """Get a dictionary mapping internal types to their helper functions.

        :return: Dictionary mapping internal types to generate_id functions
        :rtype: dict
        """
        # Import
        return {
            "user": self.opencti.user,
            "group": self.opencti.group,
            "capability": self.opencti.capability,
            "role": self.opencti.role,
            "settings": self.opencti.settings,
            "work": self.opencti.work,
            "deleteoperation": self.opencti.trash,
            "draftworkspace": self.opencti.draft,
            "playbook": self.opencti.playbook,
            "workspace": self.opencti.workspace,
            "publicdashboard": self.opencti.public_dashboard,
            "notification": self.opencti.notification,
            "internalfile": self.opencti.internal_file,
        }

    def generate_standard_id_from_stix(self, data):
        """Generate a standard ID from STIX data.

        :param data: STIX data dictionary
        :type data: dict
        :return: Generated standard ID or None
        :rtype: str or None
        """
        stix_helpers = self.get_stix_helper()
        helper = stix_helpers.get(data["type"])
        return helper.generate_id_from_data(data)

    # region import
    def import_object(
        self, stix_object: Dict, update: bool = False, types: List = None
    ) -> Optional[List]:
        """Import a STIX2 object into OpenCTI.

        :param stix_object: Valid STIX2 object to import
        :type stix_object: Dict
        :param update: Whether to update data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        :return: List of imported STIX2 objects or None on failure
        :rtype: list or None
        """

        self.opencti.app_logger.info(
            "Importing an object",
            {"type": stix_object["type"], "id": stix_object["id"]},
        )

        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object, types)
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        open_vocabs = embedded_relationships["open_vocabs"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]
        sample_refs_ids = embedded_relationships["sample_refs"]

        # Extract files
        x_opencti_files = []
        if "x_opencti_files" in stix_object:
            x_opencti_files.extend(stix_object["x_opencti_files"])
        if self.opencti.get_attribute_in_extension("files", stix_object) is not None:
            x_opencti_files.extend(
                self.opencti.get_attribute_in_extension("files", stix_object)
            )

        # Prepare first file for direct upload during creation
        file_to_upload = None
        file_markings = None
        if len(x_opencti_files) > 0:
            first_file = x_opencti_files[0]
            data = None
            if "data" in first_file:
                data = base64.b64decode(first_file["data"])
            elif "uri" in first_file:
                url = self.opencti.api_url.replace("/graphql", first_file["uri"])
                data = self.opencti.fetch_opencti_file(
                    fetch_uri=url, binary=True, serialize=False
                )
            if data is not None:
                file_to_upload = self.opencti.file(
                    first_file["name"],
                    data,
                    first_file.get("mime_type", "application/octet-stream"),
                )
                file_markings = first_file.get("object_marking_refs", None)

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "open_vocabs": open_vocabs,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
            "sample_ids": sample_refs_ids,
            "file": file_to_upload,
            "fileMarkings": file_markings,
        }

        stix_helper = self.get_stix_helper().get(stix_object["type"])
        if stix_helper:
            stix_object_results = stix_helper.import_from_stix2(
                stixObject=stix_object, extras=extras, update=update
            )
        else:
            stix_object_results = None
            self.opencti.app_logger.error(
                "Unknown object type, doing nothing...", {"type": stix_object["type"]}
            )

        if stix_object_results is None:
            return None

        if not isinstance(stix_object_results, list):
            stix_object_results = [stix_object_results]

        for stix_object_result in stix_object_results:
            self.set_in_cache(
                stix_object["id"],
                {
                    "id": stix_object_result["id"],
                    "type": stix_object_result["entity_type"],
                    "observables": (
                        stix_object_result["observables"]
                        if "observables" in stix_object_result
                        else []
                    ),
                },
            )
            self.set_in_cache(
                stix_object_result["id"],
                {
                    "id": stix_object_result["id"],
                    "type": stix_object_result["entity_type"],
                    "observables": (
                        stix_object_result["observables"]
                        if "observables" in stix_object_result
                        else []
                    ),
                },
            )
            # Add reports from external references
            for external_reference_id in external_references_ids:
                if external_reference_id in reports:
                    self.opencti.report.add_stix_object_or_stix_relationship(
                        id=reports[external_reference_id]["id"],
                        stixObjectOrStixRelationshipId=stix_object_result["id"],
                    )
            # Add additional files (first file is attached during creation)
            # Upload remaining files after entity creation
            if x_opencti_files is not None and len(x_opencti_files) > 1:
                for file in x_opencti_files[1:]:
                    data = None
                    if "data" in file:
                        data = base64.b64decode(file["data"])
                    elif "uri" in file:
                        url = self.opencti.api_url.replace("/graphql", file["uri"])
                        data = self.opencti.fetch_opencti_file(
                            fetch_uri=url, binary=True, serialize=False
                        )
                    if data is not None:
                        self.opencti.stix_domain_object.add_file(
                            id=stix_object_result["id"],
                            file_name=file["name"],
                            version=file.get("version", None),
                            data=data,
                            fileMarkings=file.get("object_marking_refs", None),
                            mime_type=file.get("mime_type", "application/octet-stream"),
                            no_trigger_import=file.get("no_trigger_import", False),
                            embedded=file.get("embedded", False),
                        )
        return stix_object_results

    def import_observable(
        self, stix_object: Dict, update: bool = False, types: List = None
    ) -> None:
        """Import a STIX cyber observable into OpenCTI.

        :param stix_object: Valid STIX2 cyber observable object
        :type stix_object: Dict
        :param update: Whether to update existing data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        """
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object, types)
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        open_vocabs = embedded_relationships["open_vocabs"]
        granted_refs_ids = embedded_relationships["granted_refs"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]
        sample_refs_ids = embedded_relationships["sample_refs"]

        # Extract files
        x_opencti_files = []
        if "x_opencti_files" in stix_object:
            x_opencti_files.extend(stix_object["x_opencti_files"])
        if self.opencti.get_attribute_in_extension("files", stix_object) is not None:
            x_opencti_files.extend(
                self.opencti.get_attribute_in_extension("files", stix_object)
            )

        # Prepare first file for direct upload during creation (all observable types support files)
        file_to_upload = None
        file_markings = None
        if len(x_opencti_files) > 0:
            first_file = x_opencti_files[0]
            data = None
            if "data" in first_file:
                data = base64.b64decode(first_file["data"])
            elif "uri" in first_file:
                url = self.opencti.api_url.replace("/graphql", first_file["uri"])
                data = self.opencti.fetch_opencti_file(
                    fetch_uri=url, binary=True, serialize=False
                )
            if data is not None:
                file_to_upload = self.opencti.file(
                    first_file["name"],
                    data,
                    first_file.get("mime_type", "application/octet-stream"),
                )
                file_markings = first_file.get("object_marking_refs", None)

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "open_vocabs": open_vocabs,
            "granted_refs_ids": granted_refs_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
            "sample_ids": sample_refs_ids,
            "file": file_to_upload,
            "fileMarkings": file_markings,
        }
        if stix_object["type"] == "simple-observable":
            stix_observable_result = self.opencti.stix_cyber_observable.create(
                simple_observable_id=stix_object["id"],
                simple_observable_key=stix_object["key"],
                simple_observable_value=(
                    stix_object["value"]
                    if stix_object["key"] not in OBSERVABLES_VALUE_INT
                    else int(stix_object["value"])
                ),
                simple_observable_description=(
                    stix_object["description"] if "description" in stix_object else None
                ),
                x_opencti_score=(
                    stix_object["x_opencti_score"]
                    if "x_opencti_score" in stix_object
                    else None
                ),
                createdBy=(
                    extras["created_by_id"] if "created_by_id" in extras else None
                ),
                objectMarking=(
                    extras["object_marking_ids"]
                    if "object_marking_ids" in extras
                    else []
                ),
                objectLabel=(
                    extras["object_label_ids"] if "object_label_ids" in extras else None
                ),
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                createIndicator=(
                    stix_object["x_opencti_create_indicator"]
                    if "x_opencti_create_indicator" in stix_object
                    else None
                ),
                objectOrganization=(
                    extras["granted_refs_ids"] if "granted_refs_ids" in extras else []
                ),
                update=update,
                file=file_to_upload,
                fileMarkings=file_markings,
            )
        else:
            stix_observable_result = self.opencti.stix_cyber_observable.create(
                observableData=stix_object,
                createdBy=(
                    extras["created_by_id"] if "created_by_id" in extras else None
                ),
                objectMarking=(
                    extras["object_marking_ids"]
                    if "object_marking_ids" in extras
                    else []
                ),
                objectLabel=(
                    extras["object_label_ids"] if "object_label_ids" in extras else None
                ),
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                objectOrganization=(
                    extras["granted_refs_ids"] if "granted_refs_ids" in extras else []
                ),
                update=update,
                file=file_to_upload,
                fileMarkings=file_markings,
            )
        if stix_observable_result is not None:
            # Upload files after observable creation
            # All observable types support file at creation, skip the first file
            # and upload additional files after creation
            files_to_upload_after = (
                x_opencti_files[1:] if len(x_opencti_files) > 1 else []
            )
            if files_to_upload_after is not None and len(files_to_upload_after) > 0:
                for file in files_to_upload_after:
                    data = None
                    if "data" in file:
                        data = base64.b64decode(file["data"])
                    elif "uri" in file:
                        url = self.opencti.api_url.replace("/graphql", file["uri"])
                        data = self.opencti.fetch_opencti_file(
                            fetch_uri=url, binary=True, serialize=False
                        )
                    if data is not None:
                        self.opencti.stix_cyber_observable.add_file(
                            id=stix_observable_result["id"],
                            file_name=file["name"],
                            version=file.get("version", None),
                            data=data,
                            fileMarkings=file.get("object_marking_refs", None),
                            mime_type=file.get("mime_type", "application/octet-stream"),
                            no_trigger_import=file.get("no_trigger_import", False),
                            embedded=file.get("embedded", False),
                        )
            if "id" in stix_object:
                self.set_in_cache(
                    stix_object["id"],
                    {
                        "id": stix_observable_result["id"],
                        "type": stix_observable_result["entity_type"],
                    },
                )
            self.set_in_cache(
                stix_observable_result["id"],
                {
                    "id": stix_observable_result["id"],
                    "type": stix_observable_result["entity_type"],
                },
            )
            # Iterate over refs to create appropriate relationships
            for key in stix_object.keys():
                if key not in [
                    "created_by_ref",
                    "object_marking_refs",
                    "x_opencti_created_by_ref",
                    "x_opencti_granted_refs",
                ]:
                    if key.endswith("_ref"):
                        relationship_type = key.replace("_ref", "")
                        if relationship_type.startswith("x_opencti_"):
                            relationship_type = relationship_type.split(
                                "x_opencti_", 1
                            )[1]
                            relationship_type = relationship_type.replace("_", "-")
                            relationship_type = "x_opencti_" + relationship_type
                        else:
                            relationship_type = relationship_type.replace("_", "-")
                        self.opencti.stix_nested_ref_relationship.create(
                            fromId=stix_observable_result["id"],
                            toId=stix_object[key],
                            relationship_type=relationship_type,
                        )
                    elif key.endswith("_refs"):
                        relationship_type = key.replace("_refs", "")
                        if relationship_type.startswith("x_opencti_"):
                            relationship_type = relationship_type.split(
                                "x_opencti_", 1
                            )[1]
                            relationship_type = relationship_type.replace("_", "-")
                            relationship_type = "x_opencti_" + relationship_type
                        else:
                            relationship_type = relationship_type.replace("_", "-")
                        for value in stix_object[key]:
                            self.opencti.stix_nested_ref_relationship.create(
                                fromId=stix_observable_result["id"],
                                toId=value,
                                relationship_type=relationship_type,
                            )
        else:
            return None

    def import_relationship(
        self, stix_relation: Dict, update: bool = False, types: List = None
    ) -> None:
        """Import a STIX core relationship into OpenCTI.

        :param stix_relation: Valid STIX2 relationship object
        :type stix_relation: Dict
        :param update: Whether to update existing data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        """
        # Extract
        embedded_relationships = self.extract_embedded_relationships(
            stix_relation, types
        )
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        open_vocabs = embedded_relationships["open_vocabs"]
        granted_refs_ids = embedded_relationships["granted_refs"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]
        sample_refs_ids = embedded_relationships["sample_refs"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "open_vocabs": open_vocabs,
            "granted_refs_ids": granted_refs_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
            "sample_ids": sample_refs_ids,
        }

        # Create the relation

        # Try to guess start_time / stop_time from external reference
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
                except (TypeError, OverflowError):
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
                    except (TypeError, OverflowError):
                        date = None

        stix_relation_result = self.opencti.stix_core_relationship.import_from_stix2(
            stixRelation=stix_relation, extras=extras, update=update, defaultDate=date
        )
        if stix_relation_result is not None:
            self.set_in_cache(
                stix_relation["id"],
                {
                    "id": stix_relation_result["id"],
                    "type": stix_relation_result["entity_type"],
                },
            )
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
        """Import a STIX sighting relationship into OpenCTI.

        :param stix_sighting: Valid STIX2 sighting object
        :type stix_sighting: Dict
        :param from_id: ID of the source entity (sighting_of_ref)
        :type from_id: str
        :param to_id: ID of the target entity (where_sighted_ref)
        :type to_id: str
        :param update: Whether to update existing data in the database, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: list, optional
        """
        # Extract
        embedded_relationships = self.extract_embedded_relationships(
            stix_sighting, types
        )
        created_by_id = embedded_relationships["created_by"]
        object_marking_ids = embedded_relationships["object_marking"]
        object_label_ids = embedded_relationships["object_label"]
        open_vocabs = embedded_relationships["open_vocabs"]
        granted_refs_ids = embedded_relationships["granted_refs"]
        kill_chain_phases_ids = embedded_relationships["kill_chain_phases"]
        object_refs_ids = embedded_relationships["object_refs"]
        external_references_ids = embedded_relationships["external_references"]
        reports = embedded_relationships["reports"]
        sample_refs_ids = embedded_relationships["sample_refs"]

        # Extra
        extras = {
            "created_by_id": created_by_id,
            "object_marking_ids": object_marking_ids,
            "object_label_ids": object_label_ids,
            "open_vocabs": open_vocabs,
            "granted_refs_ids": granted_refs_ids,
            "kill_chain_phases_ids": kill_chain_phases_ids,
            "object_ids": object_refs_ids,
            "external_references_ids": external_references_ids,
            "reports": reports,
            "sample_ids": sample_refs_ids,
        }

        # Create the sighting

        if (
            "x_opencti_negative" not in stix_sighting
            and self.opencti.get_attribute_in_extension("negative", stix_sighting)
            is not None
        ):
            stix_sighting["x_opencti_negative"] = (
                self.opencti.get_attribute_in_extension("negative", stix_sighting)
            )
        if "x_opencti_workflow_id" not in stix_sighting:
            stix_sighting["x_opencti_workflow_id"] = (
                self.opencti.get_attribute_in_extension("workflow_id", stix_sighting)
            )
        stix_sighting_result = self.opencti.stix_sighting_relationship.create(
            fromId=from_id,
            toId=to_id,
            stix_id=stix_sighting["id"] if "id" in stix_sighting else None,
            description=(
                self.convert_markdown(stix_sighting["description"])
                if "description" in stix_sighting
                else None
            ),
            first_seen=(
                stix_sighting["first_seen"] if "first_seen" in stix_sighting else None
            ),
            last_seen=(
                stix_sighting["last_seen"] if "last_seen" in stix_sighting else None
            ),
            count=stix_sighting["count"] if "count" in stix_sighting else 1,
            x_opencti_negative=(
                stix_sighting["x_opencti_negative"]
                if "x_opencti_negative" in stix_sighting
                else False
            ),
            created=stix_sighting["created"] if "created" in stix_sighting else None,
            modified=stix_sighting["modified"] if "modified" in stix_sighting else None,
            confidence=(
                stix_sighting["confidence"] if "confidence" in stix_sighting else None
            ),
            createdBy=extras["created_by_id"] if "created_by_id" in extras else None,
            objectMarking=(
                extras["object_marking_ids"] if "object_marking_ids" in extras else []
            ),
            objectLabel=(
                extras["object_label_ids"] if "object_label_ids" in extras else None
            ),
            externalReferences=(
                extras["external_references_ids"]
                if "external_references_ids" in extras
                else None
            ),
            objectOrganization=(
                extras["granted_refs_ids"] if "granted_refs_ids" in extras else []
            ),
            x_opencti_workflow_id=(
                stix_sighting["x_opencti_workflow_id"]
                if "x_opencti_workflow_id" in stix_sighting
                else None
            ),
            x_opencti_stix_ids=(
                stix_sighting["x_opencti_stix_ids"]
                if "x_opencti_stix_ids" in stix_sighting
                else None
            ),
            update=update,
            ignore_dates=(
                stix_sighting["x_opencti_ignore_dates"]
                if "x_opencti_ignore_dates" in stix_sighting
                else None
            ),
        )
        if stix_sighting_result is not None:
            self.set_in_cache(
                stix_sighting["id"],
                {
                    "id": stix_sighting_result["id"],
                    "type": stix_sighting_result["entity_type"],
                },
            )
        else:
            return None

    # endregion

    # region export
    def generate_export(self, entity: Dict, no_custom_attributes: bool = False) -> Dict:
        """Generate a STIX2 export from an OpenCTI entity.

        :param entity: OpenCTI entity dictionary to export
        :type entity: Dict
        :param no_custom_attributes: Whether to exclude custom x_opencti attributes, defaults to False
        :type no_custom_attributes: bool, optional
        :return: STIX2 formatted entity dictionary
        :rtype: Dict
        """
        # Handle model deviation
        original_entity_type = entity["entity_type"]

        # Identities
        if IdentityTypes.has_value(entity["entity_type"]):
            entity["entity_type"] = "Identity"

        # Threat-Actors
        if ThreatActorTypes.has_value(entity["entity_type"]):
            if not no_custom_attributes:
                entity["x_opencti_type"] = entity["entity_type"]
            if entity["entity_type"] == "Threat-Actor-Group":
                entity["threat_actor_group"] = entity["name"]
            entity["entity_type"] = "Threat-Actor"

        # Locations
        if LocationTypes.has_value(entity["entity_type"]):
            if not no_custom_attributes:
                entity["x_opencti_location_type"] = entity["entity_type"]
            if entity["entity_type"] == "City":
                entity["city"] = entity["name"]
            elif entity["entity_type"] == "Country":
                entity["country"] = entity["name"]
            elif entity["entity_type"] == "Region":
                entity["region"] = entity["name"]
            entity["entity_type"] = "Location"

        # Malware
        if entity["entity_type"] == "Malware":
            if "is_family" not in entity or not isinstance(entity["is_family"], bool):
                entity["is_family"] = True

        # Threat Actor
        if entity["entity_type"] == "Threat-Actor-Group":
            entity["entity_type"] = "Threat-Actor"
        if entity["entity_type"] == "Threat-Actor-Individual":
            entity["entity_type"] = "Threat-Actor"

        # Files
        if entity["entity_type"] == "StixFile":
            entity["entity_type"] = "File"

        # Case Incident
        if entity["entity_type"] == "Case-Incident":
            entity["standard_id"] = "x-opencti-" + entity["standard_id"]
            entity["entity_type"] = "x-opencti-" + entity["entity_type"]

        # Case RFI
        if entity["entity_type"] == "Case-Rfi":
            entity["standard_id"] = "x-opencti-" + entity["standard_id"]
            entity["entity_type"] = "x-opencti-" + entity["entity_type"]

        # Case RFT
        if entity["entity_type"] == "Case-Rft":
            entity["standard_id"] = "x-opencti-" + entity["standard_id"]
            entity["entity_type"] = "x-opencti-" + entity["entity_type"]

        # Feedback
        if entity["entity_type"] == "Feedback":
            entity["standard_id"] = "x-opencti-" + entity["standard_id"]
            entity["entity_type"] = "x-opencti-" + entity["entity_type"]

        # Task
        if entity["entity_type"] == "Task":
            entity["standard_id"] = "x-opencti-" + entity["standard_id"]
            entity["entity_type"] = "x-opencti-" + entity["entity_type"]

        # Data component
        if entity["entity_type"] == "Data-Component":
            entity["standard_id"] = "x-mitre-" + entity["standard_id"]
            entity["entity_type"] = "x-mitre-" + entity["entity_type"]

        # Data source
        if entity["entity_type"] == "Data-Source":
            entity["standard_id"] = "x-mitre-" + entity["standard_id"]
            entity["entity_type"] = "x-mitre-" + entity["entity_type"]
            if "platforms" in entity and entity["platforms"] is not None:
                entity["x_mitre_platforms"] = entity["platforms"]
                del entity["platforms"]
            if (
                "collection_layers" in entity
                and entity["collection_layers"] is not None
            ):
                entity["x_mitre_collection_layers"] = entity["collection_layers"]
                del entity["collection_layers"]

        # Dates
        if (
            "valid_from" in entity
            and "valid_until" in entity
            and entity["valid_from"] == entity["valid_until"]
        ):
            valid_until_converted_datetime = datetime.datetime.strptime(
                entity["valid_until"], "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            new_valid_until = valid_until_converted_datetime + datetime.timedelta(
                seconds=1
            )
            valid_until_converted_string = new_valid_until.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            entity["valid_until"] = valid_until_converted_string

        # Flatten
        if "tasks" in entity:
            del entity["tasks"]

        if "status" in entity and entity["status"] is not None:
            entity["x_opencti_workflow_id"] = entity["status"].get("id")
        if "status" in entity:
            del entity["status"]

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
                        url = self.opencti.api_url.replace("/graphql", file["uri"])
                        data = self.opencti.fetch_opencti_file(
                            url, binary=True, serialize=True
                        )
                        external_reference["x_opencti_files"].append(
                            {
                                "name": file["name"],
                                "data": data,
                                "mime_type": file["metaData"]["mimetype"],
                                "version": file["metaData"].get("version", None),
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
            for hash_item in hashes:
                entity["hashes"][hash_item["algorithm"]] = hash_item["hash"]

        # Final
        entity["x_opencti_id"] = entity["id"]
        if not no_custom_attributes:
            entity["x_opencti_type"] = original_entity_type
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

    @staticmethod
    def prepare_id_filters_export(
        entity_id: Union[str, List[str]], access_filter: Dict = None
    ) -> Dict:
        """Prepare filter configuration for entity ID-based export queries.

        :param entity_id: Single entity ID or list of entity IDs to filter
        :type entity_id: Union[str, List[str]]
        :param access_filter: Additional access filter to combine, defaults to None
        :type access_filter: Dict, optional
        :return: Filter configuration dictionary for API queries
        :rtype: Dict
        """
        if access_filter is not None:
            return {
                "mode": "and",
                "filterGroups": [
                    {
                        "mode": "or",
                        "filters": [
                            {
                                "key": "ids",
                                "values": (
                                    entity_id
                                    if isinstance(entity_id, list)
                                    else [entity_id]
                                ),
                            }
                        ],
                        "filterGroups": [],
                    },
                    access_filter,
                ],
                "filters": [],
            }
        else:
            return {
                "mode": "and",
                "filterGroups": [],
                "filters": [
                    {
                        "key": "ids",
                        "mode": "or",
                        "values": (
                            entity_id if isinstance(entity_id, list) else [entity_id]
                        ),
                    }
                ],
            }

    def prepare_export(
        self,
        entity: Dict,
        mode: str = "simple",
        access_filter: Dict = None,
        no_custom_attributes: bool = False,
    ) -> List:
        """Prepare an entity for STIX2 export with related objects.

        :param entity: Entity dictionary to prepare for export
        :type entity: Dict
        :param mode: Export mode - 'simple' for entity only, 'full' for entity with relations
        :type mode: str
        :param access_filter: Access filter for the export, defaults to None
        :type access_filter: Dict, optional
        :param no_custom_attributes: Whether to exclude custom attributes, defaults to False
        :type no_custom_attributes: bool, optional
        :return: List of STIX2 objects ready for export
        :rtype: List
        """
        result = []
        objects_to_get = []

        # CreatedByRef
        if (
            not no_custom_attributes
            and "createdBy" in entity
            and entity["createdBy"] is not None
        ):
            created_by = self.generate_export(entity=entity["createdBy"])
            if entity["type"] in STIX_CYBER_OBSERVABLE_MAPPING:
                entity["x_opencti_created_by_ref"] = created_by["id"]
            else:
                entity["created_by_ref"] = created_by["id"]
            result.append(created_by)
        # Labels
        if entity["type"] in STIX_CYBER_OBSERVABLE_MAPPING and "labels" in entity:
            entity["x_opencti_labels"] = entity["labels"]
            del entity["labels"]

        if "createdBy" in entity:
            del entity["createdBy"]
            del entity["createdById"]
        if "observables" in entity:
            del entity["observables"]
            del entity["observablesIds"]
        if "creators" in entity:
            del entity["creators"]

        # DataSource
        if (
            not no_custom_attributes
            and "dataSource" in entity
            and entity["dataSource"] is not None
        ):
            data_source = self.generate_export(entity["dataSource"])
            entity["x_mitre_data_source_ref"] = data_source["id"]
            result.append(data_source)
        if "dataSource" in entity:
            del entity["dataSource"]
            del entity["dataSourceId"]

        # Dates
        if "first_seen" in entity and entity["first_seen"].startswith("1970"):
            del entity["first_seen"]
        if "start_time" in entity and entity["start_time"].startswith("1970"):
            del entity["start_time"]
        if "last_seen" in entity and entity["last_seen"].startswith("5138"):
            del entity["last_seen"]
        if "stop_time" in entity and entity["stop_time"].startswith("5138"):
            del entity["stop_time"]

        entity_copy = entity.copy()
        if no_custom_attributes:
            if "external_references" in entity:
                del entity["external_references"]
            for key in entity_copy.keys():
                if key.startswith("x_"):
                    del entity[key]
            entity["x_opencti_id"] = entity_copy["x_opencti_id"]
        # ObjectOrganization
        if (
            not no_custom_attributes
            and "objectOrganization" in entity
            and len(entity["objectOrganization"]) > 0
        ):
            entity["x_opencti_granted_refs"] = []
            for entity_organization in entity["objectOrganization"]:
                entity["x_opencti_granted_refs"].append(
                    entity_organization["standard_id"]
                )
        if "objectOrganization" in entity:
            del entity["objectOrganization"]

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
            objects_to_get = entity["objects"]  # To do differently
            for entity_object in entity["objects"]:
                if (
                    entity["type"] == "report"
                    and entity_object["entity_type"]
                    not in [
                        "Note",
                        "Report",
                        "Opinion",
                    ]
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "note"
                    and entity_object["entity_type"]
                    not in [
                        "Note",
                        "Opinion",
                    ]
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "opinion"
                    and entity_object["entity_type"] not in ["Opinion"]
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "observed-data"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "grouping"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "x-opencti-case-incident"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "x-opencti-feedback"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "x-opencti-case-rfi"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "x-opencti-case-rft"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
                elif (
                    entity["type"] == "x-opencti-task"
                    and "stix-ref-relationship" not in entity_object["parent_types"]
                ):
                    entity["object_refs"].append(entity_object["standard_id"])
        if "objects" in entity:
            del entity["objects"]
            del entity["objectsIds"]
        # Stix Sighting Relationship
        if entity["type"] == "stix-sighting-relationship":
            entity["type"] = "sighting"
            entity["count"] = entity["attribute_count"]
            del entity["attribute_count"]
            from_to_check = entity["from"]["id"]
            relationships_from_filter = self.prepare_id_filters_export(
                entity_id=from_to_check, access_filter=access_filter
            )
            x = self.opencti.opencti_stix_object_or_stix_relationship.list(
                filters=relationships_from_filter
            )
            if len(x) > 0:
                entity["sighting_of_ref"] = entity["from"]["standard_id"]
                # handle from and to separately like Stix Core Relationship and call 2 requests
                objects_to_get.append(
                    entity["from"]
                )  # what happen with unauthorized objects ?

            to_to_check = [entity["to"]["id"]]
            relationships_to_filter = self.prepare_id_filters_export(
                entity_id=to_to_check, access_filter=access_filter
            )
            y = self.opencti.opencti_stix_object_or_stix_relationship.list(
                filters=relationships_to_filter
            )
            if len(y) > 0:
                entity["where_sighted_refs"] = [entity["to"]["standard_id"]]
                objects_to_get.append(entity["to"])

            del entity["from"]
            del entity["to"]
        # Stix Core Relationship
        if "from" in entity or "to" in entity:
            entity["type"] = "relationship"
        if "from" in entity:
            from_to_check = entity["from"]["id"]
            relationships_from_filter = self.prepare_id_filters_export(
                entity_id=from_to_check, access_filter=access_filter
            )
            x = self.opencti.opencti_stix_object_or_stix_relationship.list(
                filters=relationships_from_filter
            )
            if len(x) > 0:
                entity["source_ref"] = entity["from"]["standard_id"]
                # handle from and to separately like Stix Core Relationship and call 2 requests
                objects_to_get.append(
                    entity["from"]
                )  # what happen with unauthorized objects ?
            del entity["from"]
        if "to" in entity:
            to_to_check = [entity["to"]["id"]]
            relationships_to_filter = self.prepare_id_filters_export(
                entity_id=to_to_check, access_filter=access_filter
            )
            y = self.opencti.opencti_stix_object_or_stix_relationship.list(
                filters=relationships_to_filter
            )
            if len(y) > 0:
                entity["target_ref"] = entity["to"]["standard_id"]
                objects_to_get.append(entity["to"])
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
                        "version": file["metaData"].get("version", None),
                    }
                )
            del entity["importFiles"]
            del entity["importFilesIds"]

        # StixRefRelationship
        stix_nested_ref_relationships = self.opencti.stix_nested_ref_relationship.list(
            fromId=entity["x_opencti_id"], filters=access_filter
        )
        for stix_nested_ref_relationship in stix_nested_ref_relationships:
            if "standard_id" in stix_nested_ref_relationship["to"]:
                # dirty fix because the sample and operating-system ref are not multiple for a Malware Analysis
                # will be replaced by a proper toStix converter in the back
                if not MultipleRefRelationship.has_value(
                    stix_nested_ref_relationship["relationship_type"]
                ) or (
                    entity["type"] == "malware-analysis"
                    and stix_nested_ref_relationship["relationship_type"]
                    in ["operating-system", "sample"]
                ):
                    key = (
                        stix_nested_ref_relationship["relationship_type"]
                        .replace("obs_", "")
                        .replace("-", "_")
                        + "_ref"
                    )
                    entity[key] = stix_nested_ref_relationship["to"]["standard_id"]

                else:
                    key = (
                        stix_nested_ref_relationship["relationship_type"]
                        .replace("obs_", "")
                        .replace("-", "_")
                        + "_refs"
                    )
                    if key in entity and isinstance(entity[key], list):
                        entity[key].append(
                            stix_nested_ref_relationship["to"]["standard_id"]
                        )
                    else:
                        entity[key] = [
                            stix_nested_ref_relationship["to"]["standard_id"]
                        ]
        result.append(entity)

        if mode == "simple":
            if no_custom_attributes:
                del entity["x_opencti_id"]
            return result
        elif mode == "full":
            uuids = [entity["id"]]
            for y in result:
                uuids.append(y["id"])
            # Get extra refs
            for key in entity.keys():
                if key.endswith("_ref"):
                    stix_type = entity[key].split("--")[0]
                    if stix_type in STIX_CYBER_OBSERVABLE_MAPPING:
                        objects_to_get.append(
                            {
                                "id": entity[key],
                                "entity_type": "Stix-Cyber-Observable",
                                "parent_types": ["Stix-Cyber-Observable"],
                            }
                        )
                    else:
                        objects_to_get.append(
                            {
                                "id": entity[key],
                                "entity_type": "Stix-Domain-Object",
                                "parent_types": ["Stix-Domain-Object"],
                            }
                        )
                elif key.endswith("_refs"):
                    for value in entity[key]:
                        stix_type = value.split("--")[0]
                        if stix_type in STIX_CYBER_OBSERVABLE_MAPPING:
                            objects_to_get.append(
                                {
                                    "id": value,
                                    "entity_type": "Stix-Cyber-Observable",
                                    "parent_types": ["Stix-Cyber-Observable"],
                                }
                            )
                        else:
                            objects_to_get.append(
                                {
                                    "id": value,
                                    "entity_type": "Stix-Domain-Object",
                                    "parent_types": ["Stix-Domain-Object"],
                                }
                            )
            # Get extra relations (from AND to)
            stix_core_relationships = self.opencti.stix_core_relationship.list(
                fromOrToId=entity["x_opencti_id"], getAll=True, filters=access_filter
            )
            for stix_core_relationship in stix_core_relationships:
                objects_to_get.append(
                    stix_core_relationship["to"]
                    if stix_core_relationship["to"]["id"] != entity["x_opencti_id"]
                    else stix_core_relationship["from"]
                )
                relation_object_data = (
                    self.prepare_export(  # ICI -> remove max marking ?
                        entity=self.generate_export(stix_core_relationship),
                        mode="simple",
                        access_filter=access_filter,
                    )
                )
                relation_object_bundle = self.filter_objects(
                    uuids, relation_object_data
                )
                uuids = uuids + [x["id"] for x in relation_object_bundle]
                result = result + relation_object_bundle

            # Get sighting
            stix_sighting_relationships = self.opencti.stix_sighting_relationship.list(
                fromOrToId=entity["x_opencti_id"], getAll=True, filters=access_filter
            )
            for stix_sighting_relationship in stix_sighting_relationships:
                objects_to_get.append(
                    stix_sighting_relationship["to"]
                    if stix_sighting_relationship["to"]["id"] != entity["x_opencti_id"]
                    else stix_sighting_relationship["from"]
                )
                relation_object_data = (
                    self.prepare_export(  # ICI -> remove max marking ?
                        entity=self.generate_export(stix_sighting_relationship),
                        mode="simple",
                        access_filter=access_filter,
                    )
                )
                relation_object_bundle = self.filter_objects(
                    uuids, relation_object_data
                )
                uuids = uuids + [x["id"] for x in relation_object_bundle]
                result = result + relation_object_bundle

            if no_custom_attributes:
                del entity["x_opencti_id"]
            # Get extra objects
            for entity_object in objects_to_get:
                resolve_type = entity_object["entity_type"]
                if "stix-core-relationship" in entity_object["parent_types"]:
                    resolve_type = "stix-core-relationship"
                if "stix-ref-relationship" in entity_object["parent_types"]:
                    resolve_type = "stix-ref-relationship"
                do_read = self.get_reader(resolve_type)
                query_filters = self.prepare_id_filters_export(
                    entity_object["id"], access_filter
                )
                entity_object_data = do_read(filters=query_filters)
                if entity_object_data is not None:
                    stix_entity_object = self.prepare_export(
                        entity=self.generate_export(entity_object_data),
                        mode="simple",
                        access_filter=access_filter,
                    )
                    # Add to result
                    entity_object_bundle = self.filter_objects(
                        uuids, stix_entity_object
                    )
                    uuids = uuids + [x["id"] for x in entity_object_bundle]
                    result = result + entity_object_bundle
            # Get extra reports
            """
            for uuid in uuids:
                if "marking-definition" not in uuid:
                    reports = self.opencti.opencti_stix_object_or_stix_relationship.reports(id=uuid)
                    for report in reports:
                        report_object_data = self.opencti.report.to_stix2(
                            entity=report,
                            mode="simple",
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
            #            )
            #            note_object_bundle = self.filter_objects(
            #                uuids, note_object_data
            #            )
            #            uuids = uuids + [x["id"] for x in note_object_bundle]
            #            result = result + note_object_bundle

            # Refilter all the reports object refs
            final_result = []
            for result_entity in result:
                if result_entity["type"] in [
                    "report",
                    "note",
                    "opinion",
                    "observed-data",
                    "grouping",
                ]:
                    if "object_refs" in result_entity:
                        result_entity["object_refs"] = [
                            k for k in result_entity["object_refs"] if k in uuids
                        ]
                    final_result.append(result_entity)
                else:
                    final_result.append(result_entity)
            return final_result
        else:
            return []

    def get_stix_bundle_or_object_from_entity_id(
        self,
        entity_type: str,
        entity_id: str,
        mode: str = "simple",
        access_filter: Dict = None,
        no_custom_attributes: bool = False,
        only_entity: bool = False,
    ) -> Dict:
        """Get a STIX2 bundle or single object from an entity ID.

        :param entity_type: Type of the entity to export
        :type entity_type: str
        :param entity_id: ID of the entity to export
        :type entity_id: str
        :param mode: Export mode - 'simple' or 'full', defaults to 'simple'
        :type mode: str
        :param access_filter: Access filter for the export, defaults to None
        :type access_filter: Dict, optional
        :param no_custom_attributes: Whether to exclude custom attributes, defaults to False
        :type no_custom_attributes: bool, optional
        :param only_entity: If True, return only the entity object instead of a bundle
        :type only_entity: bool, optional
        :return: STIX2 bundle dictionary or single STIX2 object if only_entity is True
        :rtype: Dict
        """
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }
        do_read = self.get_reader(entity_type)
        entity = do_read(id=entity_id, withFiles=(mode == "full"))
        if entity is None:
            self.opencti.app_logger.error(
                "Cannot export entity (not found)", {"id": entity_id}
            )
            return bundle
        entity_standard_id = entity["standard_id"]
        stix_objects = self.prepare_export(
            entity=self.generate_export(entity, no_custom_attributes),
            mode=mode,
            access_filter=access_filter,
            no_custom_attributes=no_custom_attributes,
        )
        if stix_objects is not None:
            bundle["objects"].extend(stix_objects)
        if only_entity:
            return [e for e in bundle["objects"] if e.get("id") == entity_standard_id][
                0
            ]
        return bundle

    # Please use get_stix_bundle_or_object_from_entity_id instead
    @deprecated("Use get_stix_bundle_or_object_from_entity_id instead")
    def export_entity(
        self,
        entity_type: str,
        entity_id: str,
        mode: str = "simple",
        access_filter: Dict = None,
        no_custom_attributes: bool = False,
        only_entity: bool = False,
    ) -> Dict:
        """Export an entity as a STIX2 bundle.

        .. deprecated::
            Use :meth:`get_stix_bundle_or_object_from_entity_id` instead.

        :param entity_type: Type of the entity to export
        :type entity_type: str
        :param entity_id: ID of the entity to export
        :type entity_id: str
        :param mode: Export mode - 'simple' or 'full', defaults to 'simple'
        :type mode: str
        :param access_filter: Access filter for the export, defaults to None
        :type access_filter: Dict, optional
        :param no_custom_attributes: Whether to exclude custom attributes, defaults to False
        :type no_custom_attributes: bool, optional
        :param only_entity: If True, return only the entity object instead of a bundle
        :type only_entity: bool, optional
        :return: STIX2 bundle dictionary or single STIX2 object
        :rtype: Dict
        """
        return self.get_stix_bundle_or_object_from_entity_id(
            entity_type=entity_type,
            entity_id=entity_id,
            mode=mode,
            access_filter=access_filter,
            no_custom_attributes=no_custom_attributes,
            only_entity=only_entity,
        )

    def export_entities_list(
        self,
        entity_type: str,
        search: Dict = None,
        filters: Dict = None,
        orderBy: str = None,
        orderMode: str = None,
        getAll: bool = True,
        withFiles: bool = False,
    ) -> List[Dict]:
        """List entities for export based on type and filters.

        :param entity_type: Type of entities to list
        :type entity_type: str
        :param search: Search parameters, defaults to None
        :type search: Dict, optional
        :param filters: Filter parameters, defaults to None
        :type filters: Dict, optional
        :param orderBy: Field to order results by, defaults to None
        :type orderBy: str, optional
        :param orderMode: Order direction ('asc' or 'desc'), defaults to None
        :type orderMode: str, optional
        :param getAll: Whether to get all results, defaults to True
        :type getAll: bool, optional
        :param withFiles: Whether to include files in the export, defaults to False
        :type withFiles: bool, optional
        :return: List of entity dictionaries
        :rtype: List[Dict]
        """
        if IdentityTypes.has_value(entity_type):
            entity_type = "Identity"

        if LocationTypes.has_value(entity_type):
            entity_type = "Location"

        if StixCyberObservableTypes.has_value(entity_type):
            entity_type = "Stix-Cyber-Observable"

        if entity_type == "Container":
            entity_type = "Stix-Domain-Object"

        # List
        lister = {
            "Stix-Core-Object": self.opencti.stix_core_object.list,
            "Stix-Domain-Object": self.opencti.stix_domain_object.list,
            "Attack-Pattern": self.opencti.attack_pattern.list,
            "Campaign": self.opencti.campaign.list,
            "Channel": self.opencti.channel.list,
            "Event": self.opencti.event.list,
            "Note": self.opencti.note.list,
            "Observed-Data": self.opencti.observed_data.list,
            "Opinion": self.opencti.opinion.list,
            "Report": self.opencti.report.list,
            "Grouping": self.opencti.grouping.list,
            "Case-Incident": self.opencti.case_incident.list,
            "Feedback": self.opencti.feedback.list,
            "Case-Rfi": self.opencti.case_rfi.list,
            "Case-Rft": self.opencti.case_rft.list,
            "Task": self.opencti.task.list,
            "Course-Of-Action": self.opencti.course_of_action.list,
            "Data-Component": self.opencti.data_component.list,
            "Data-Source": self.opencti.data_source.list,
            "Identity": self.opencti.identity.list,
            "Indicator": self.opencti.indicator.list,
            "Infrastructure": self.opencti.infrastructure.list,
            "Intrusion-Set": self.opencti.intrusion_set.list,
            "Location": self.opencti.location.list,
            "Language": self.opencti.language.list,
            "Malware": self.opencti.malware.list,
            "Malware-Analysis": self.opencti.malware_analysis.list,
            "Threat-Actor": self.opencti.threat_actor_group.list,
            "Threat-Actor-Group": self.opencti.threat_actor_group.list,
            "Threat-Actor-Individual": self.opencti.threat_actor_individual.list,
            "Tool": self.opencti.tool.list,
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

        if getAll and (orderBy is None or orderBy == "_score"):
            orderBy = "created_at"
            if orderMode is None:
                orderMode = "desc"

        # noinspection PyTypeChecker
        return do_list(
            search=search,
            filters=filters,
            orderBy=orderBy,
            orderMode=orderMode,
            getAll=getAll,
            withFiles=withFiles,
        )

    def export_list(
        self,
        entity_type: str,
        search: Dict = None,
        filters: Dict = None,
        order_by: str = None,
        order_mode: str = None,
        mode: str = "simple",
        access_filter: Dict = None,
    ) -> Dict:
        """Export a list of entities as a STIX2 bundle.

        :param entity_type: Type of entities to export
        :type entity_type: str
        :param search: Search parameters, defaults to None
        :type search: Dict, optional
        :param filters: Filter parameters, defaults to None
        :type filters: Dict, optional
        :param order_by: Field to order results by, defaults to None
        :type order_by: str, optional
        :param order_mode: Order direction ('asc' or 'desc'), defaults to None
        :type order_mode: str, optional
        :param mode: Export mode - 'simple' or 'full', defaults to 'simple'
        :type mode: str
        :param access_filter: Access filter for the export, defaults to None
        :type access_filter: Dict, optional
        :return: STIX2 bundle containing all exported entities
        :rtype: Dict
        """
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }
        filter_groups = []
        if filters is not None:
            filter_groups.append(filters)
        if access_filter is not None:
            filter_groups.append(access_filter)
        export_query_filter = {
            "mode": "and",
            "filterGroups": filter_groups,
            "filters": [],
        }
        entities_list = self.export_entities_list(
            entity_type=entity_type,
            search=search,
            filters=export_query_filter,
            orderBy=order_by,
            orderMode=order_mode,
            getAll=True,
            withFiles=(mode == "full"),
        )
        if entities_list is not None:
            uuids = []
            for entity in entities_list:
                entity_bundle = self.prepare_export(
                    entity=self.generate_export(entity),
                    mode=mode,
                    access_filter=access_filter,
                )
                if entity_bundle is not None:
                    entity_bundle_filtered = self.filter_objects(uuids, entity_bundle)
                    for x in entity_bundle_filtered:
                        uuids.append(x["id"])
                    bundle["objects"] = bundle["objects"] + entity_bundle_filtered
        return bundle

    def export_selected(
        self,
        entities_list: List[dict],
        mode: str = "simple",
        access_filter: Dict = None,
    ) -> Dict:
        """Export selected entities as a STIX2 bundle.

        :param entities_list: List of entities to export
        :type entities_list: List[dict]
        :param mode: Export mode ('simple' or 'full'), defaults to 'simple'
        :type mode: str
        :param access_filter: Access filter for the export
        :type access_filter: Dict
        :return: STIX2 bundle containing exported entities
        :rtype: Dict
        """
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }

        uuids = []
        for entity in entities_list:
            entity_bundle = self.prepare_export(
                entity=self.generate_export(entity),
                mode=mode,
                access_filter=access_filter,
            )
            if entity_bundle is not None:
                entity_bundle_filtered = self.filter_objects(uuids, entity_bundle)
                for x in entity_bundle_filtered:
                    uuids.append(x["id"])
                bundle["objects"] = (
                    bundle["objects"] + entity_bundle_filtered
                )  # unsupported operand type(s) for +: 'dict' and 'list'

        return bundle

    def apply_patch_files(self, item):
        """Apply file patches to an item.

        :param item: Item containing file patch operations
        :type item: dict
        """
        field_patch = self.opencti.get_attribute_in_extension(
            "opencti_field_patch", item
        )
        if field_patch is None:
            field_patch = item["opencti_field_patch"]
        field_patch_files = next(
            (op for op in field_patch if op["key"] == "x_opencti_files"), None
        )
        item_id = self.opencti.get_attribute_in_extension("id", item)
        if item_id is None:
            item_id = item["id"]
        do_add_file = self.opencti.stix_domain_object.add_file
        if StixCyberObservableTypes.has_value(item["type"]):
            do_add_file = self.opencti.stix_cyber_observable.add_file
        elif item["type"] == "external-reference":
            do_add_file = self.opencti.external_reference.add_file
        if field_patch_files is not None:
            for file in field_patch_files["value"]:
                if "data" in file:
                    do_add_file(
                        id=item_id,
                        file_name=file["name"],
                        version=file.get("version", None),
                        data=base64.b64decode(file["data"]),
                        fileMarkings=file.get("object_marking_refs", None),
                        mime_type=file.get("mime_type", None),
                        no_trigger_import=file.get("no_trigger_import", False),
                        embedded=file.get("embedded", False),
                    )

    def apply_patch(self, item):
        """Apply field patches to an item.

        :param item: Item containing field patch operations
        :type item: dict
        """
        field_patch = self.opencti.get_attribute_in_extension(
            "opencti_field_patch", item
        )
        if field_patch is None:
            field_patch = item["opencti_field_patch"]
        field_patch_without_files = [
            op for op in field_patch if op["key"] != "x_opencti_files"
        ]
        item_id = self.opencti.get_attribute_in_extension("id", item)
        if item_id is None:
            item_id = item["id"]
        if len(field_patch_without_files) > 0:
            if item["type"] == "relationship":
                self.opencti.stix_core_relationship.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif item["type"] == "sighting":
                self.opencti.stix_sighting_relationship.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif StixCyberObservableTypes.has_value(item["type"]):
                self.opencti.stix_cyber_observable.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif item["type"] == "external-reference":
                self.opencti.external_reference.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif item["type"] == "indicator":
                self.opencti.indicator.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif item["type"] == "notification":
                self.opencti.notification.update_field(
                    id=item_id, input=field_patch_without_files
                )
            elif item["type"] == "user":
                self.opencti.user.update_field(
                    id=item_id, input=field_patch_without_files
                )
            else:
                self.opencti.stix_domain_object.update_field(
                    id=item_id, input=field_patch_without_files
                )
        self.apply_patch_files(item)

    def rule_apply(self, item):
        """Apply a rule to an item.

        :param item: Item to apply the rule to
        :type item: dict
        """
        rule_id = self.opencti.get_attribute_in_extension("opencti_rule", item)
        if rule_id is None:
            rule_id = item["opencti_rule"]
        self.opencti.stix_core_object.rule_apply(element_id=item["id"], rule_id=rule_id)

    def rule_clear(self, item):
        """Clear a rule from an item.

        :param item: Item to clear the rule from
        :type item: dict
        """
        rule_id = self.opencti.get_attribute_in_extension("opencti_rule", item)
        if rule_id is None:
            rule_id = item["opencti_rule"]
        self.opencti.stix_core_object.rule_clear(element_id=item["id"], rule_id=rule_id)

    def rules_rescan(self, item):
        """Rescan rules for an item.

        :param item: Item to rescan rules for
        :type item: dict
        """
        self.opencti.stix_core_object.rules_rescan(element_id=item["id"])

    def organization_share(self, item):
        """Share an item with organizations.

        :param item: Item to share
        :type item: dict
        """
        organization_ids = self.opencti.get_attribute_in_extension(
            "sharing_organization_ids", item
        )
        if organization_ids is None:
            organization_ids = item["sharing_organization_ids"]
        sharing_direct_container = self.opencti.get_attribute_in_extension(
            "sharing_direct_container", item
        )
        if sharing_direct_container is None:
            sharing_direct_container = item["sharing_direct_container"]

        if item["type"] == "relationship":
            self.opencti.stix_core_relationship.organization_share(
                item["id"], organization_ids, sharing_direct_container
            )
        elif item["type"] == "sighting":
            self.opencti.stix_sighting_relationship.organization_share(
                item["id"], organization_ids, sharing_direct_container
            )
        else:
            # Element is considered stix core object
            self.opencti.stix_core_object.organization_share(
                item["id"], organization_ids, sharing_direct_container
            )

    def organization_unshare(self, item):
        """Unshare an item from organizations.

        :param item: Item to unshare
        :type item: dict
        """
        organization_ids = self.opencti.get_attribute_in_extension(
            "sharing_organization_ids", item
        )
        if organization_ids is None:
            organization_ids = item["sharing_organization_ids"]
        sharing_direct_container = self.opencti.get_attribute_in_extension(
            "sharing_direct_container", item
        )
        if sharing_direct_container is None:
            sharing_direct_container = item["sharing_direct_container"]
        if item["type"] == "relationship":
            self.opencti.stix_core_relationship.organization_unshare(
                item["id"], organization_ids, sharing_direct_container
            )
        elif item["type"] == "sighting":
            self.opencti.stix_sighting_relationship.organization_unshare(
                item["id"], organization_ids, sharing_direct_container
            )
        else:
            # Element is considered stix core object
            self.opencti.stix_core_object.organization_unshare(
                item["id"], organization_ids, sharing_direct_container
            )

    def element_add_organizations(self, item):
        """Add organizations to an element.

        :param item: Item to add organizations to
        :type item: dict
        :raises ValueError: If the operation is not compatible with the item type
        """
        organization_ids = self.opencti.get_attribute_in_extension(
            "organization_ids", item
        )
        if organization_ids is None:
            organization_ids = item["organization_ids"]
        if item["type"] == "user":
            for organization_id in organization_ids:
                self.opencti.user.add_organization(
                    id=item["id"], organization_id=organization_id
                )
        else:
            raise ValueError(
                "Add organizations operation not compatible with type",
                {"type": item["type"]},
            )

    def element_remove_organizations(self, item):
        """Remove organizations from an element.

        :param item: Item to remove organizations from
        :type item: dict
        :raises ValueError: If the operation is not compatible with the item type
        """
        organization_ids = self.opencti.get_attribute_in_extension(
            "organization_ids", item
        )
        if organization_ids is None:
            organization_ids = item["organization_ids"]
        if item["type"] == "user":
            for organization_id in organization_ids:
                self.opencti.user.delete_organization(
                    id=item["id"], organization_id=organization_id
                )
        else:
            raise ValueError(
                "Remove organizations operation not compatible with type",
                {"type": item["type"]},
            )

    def element_add_groups(self, item):
        """Add groups to an element.

        :param item: Item to add groups to
        :type item: dict
        :raises ValueError: If the operation is not compatible with the item type
        """
        group_ids = self.opencti.get_attribute_in_extension("group_ids", item)
        if group_ids is None:
            group_ids = item["group_ids"]
        if item["type"] == "user":
            for group_id in group_ids:
                self.opencti.user.add_membership(id=item["id"], group_id=group_id)
        else:
            raise ValueError(
                "Add groups operation not compatible with type", {"type": item["type"]}
            )

    def element_remove_groups(self, item):
        """Remove groups from an element.

        :param item: Item to remove groups from
        :type item: dict
        :raises ValueError: If the operation is not compatible with the item type
        """
        group_ids = self.opencti.get_attribute_in_extension("group_ids", item)
        if group_ids is None:
            group_ids = item["group_ids"]
        if item["type"] == "user":
            for group_id in group_ids:
                self.opencti.user.delete_membership(id=item["id"], group_id=group_id)
        else:
            raise ValueError(
                "Remove groups operation not compatible with type",
                {"type": item["type"]},
            )

    def send_email(self, item):
        """Send an email for an item.

        :param item: Item to send email for
        :type item: dict
        :raises ValueError: If the operation is not supported for the item type
        """
        template_id = self.opencti.get_attribute_in_extension("template_id", item)
        if template_id is None:
            template_id = item["template_id"]
        if item["type"] == "user":
            self.opencti.user.send_mail(id=item["id"], template_id=template_id[0])
        else:
            raise ValueError(
                "Not supported opencti_operation for this type",
                {"type": item["type"]},
            )

    def element_operation_delete(self, item, operation):
        """Delete an element.

        :param item: Item to delete
        :type item: dict
        :param operation: Delete operation type ('delete' or 'delete_force')
        :type operation: str
        :raises ValueError: If the delete operation fails or helper not found
        """
        # If data is stix, just use the generic stix function for deletion
        force_delete = operation == "delete_force"
        if item["type"] == "relationship":
            self.opencti.stix_core_relationship.delete(id=item["id"])
        elif item["type"] == "external-reference":
            self.opencti.external_reference.delete(item["id"])
        elif item["type"] == "sighting":
            self.opencti.stix_sighting_relationship.delete(id=item["id"])
        elif item["type"] in STIX_META_OBJECTS:
            self.opencti.stix.delete(id=item["id"], force_delete=force_delete)
        elif item["type"] in list(STIX_CYBER_OBSERVABLE_MAPPING.keys()):
            self.opencti.stix_cyber_observable.delete(id=item["id"])
        elif item["type"] in STIX_CORE_OBJECTS:
            self.opencti.stix_core_object.delete(id=item["id"])
        else:
            # Element is not knowledge we need to use the right api
            stix_helper = self.get_internal_helper().get(item["type"])
            if stix_helper and hasattr(stix_helper, "delete"):
                stix_helper.delete(id=item["id"], item=item)
            else:
                raise ValueError(
                    "Delete operation or not found stix helper", {"type": item["type"]}
                )

    def element_remove_from_draft(self, item):
        """Remove an element from draft.

        :param item: Item to remove from draft
        :type item: dict
        """
        if item["type"] == "relationship":
            self.opencti.stix_core_relationship.remove_from_draft(id=item["id"])
        elif item["type"] == "sighting":
            self.opencti.stix_sighting_relationship.remove_from_draft(id=item["id"])
        else:
            # Element is considered stix core object
            self.opencti.stix_core_object.remove_from_draft(id=item["id"])

    def apply_opencti_operation(self, item, operation):
        """Apply an OpenCTI operation to an item.

        :param item: Item to apply the operation to
        :type item: dict
        :param operation: Operation to apply (delete, restore, merge, patch, etc.)
        :type operation: str
        :raises ValueError: If the operation is not supported
        """
        if operation == "delete" or operation == "delete_force":
            self.element_operation_delete(item=item, operation=operation)
        elif operation == "revert_draft":
            self.element_remove_from_draft(item=item)
        elif operation == "restore":
            self.opencti.trash.restore(item["id"])
        elif operation == "merge":
            target_id = self.opencti.get_attribute_in_extension("merge_target_id", item)
            if target_id is None:
                target_id = item["merge_target_id"]
            source_ids = self.opencti.get_attribute_in_extension(
                "merge_source_ids", item
            )
            if source_ids is None:
                source_ids = item["merge_source_ids"]
            self.opencti.stix.merge(id=target_id, object_ids=source_ids)
        elif operation == "patch":
            self.apply_patch(item=item)
        elif operation == "pir_flag_element":
            element_id = item["id"]
            pir_input = item["input"]
            self.opencti.pir.pir_flag_element(id=element_id, input=pir_input)
        elif operation == "pir_unflag_element":
            element_id = item["id"]
            pir_input = item["input"]
            self.opencti.pir.pir_unflag_element(id=element_id, input=pir_input)
        elif operation == "rule_apply":
            self.rule_apply(item=item)
        elif operation == "rule_clear":
            self.rule_clear(item=item)
        elif operation == "rules_rescan":
            self.rules_rescan(item=item)
        elif operation == "share":
            self.organization_share(item=item)
        elif operation == "unshare":
            self.organization_unshare(item=item)
        elif operation == "clear_access_restriction":
            self.opencti.stix_core_object.clear_access_restriction(
                element_id=item["id"]
            )
        elif operation == "enrichment":
            connector_ids = self.opencti.get_attribute_in_extension(
                "connector_ids", item
            )
            if connector_ids is None:
                connector_ids = item["connector_ids"]
            self.opencti.stix_core_object.ask_enrichments(
                element_id=item["id"], connector_ids=connector_ids
            )
        elif operation == "add_organizations":
            self.element_add_organizations(item)
        elif operation == "remove_organizations":
            self.element_remove_organizations(item)
        elif operation == "add_groups":
            self.element_add_groups(item)
        elif operation == "remove_groups":
            self.element_remove_groups(item)
        elif operation == "send_email":
            self.send_email(item=item)
        else:
            raise ValueError(
                "Not supported opencti_operation",
                {"operation": operation},
            )

    def import_item(
        self,
        item,
        update: bool = False,
        types: List = None,
        work_id: str = None,
    ):
        """Import a single STIX2 item into OpenCTI.

        :param item: STIX2 item to import
        :type item: dict
        :param update: Whether to update existing data, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: List, optional
        :param work_id: Work ID for tracking import progress, defaults to None
        :type work_id: str, optional
        :return: True on success
        :rtype: bool
        """
        opencti_operation = self.opencti.get_attribute_in_extension(
            "opencti_operation", item
        )
        if opencti_operation is not None:
            self.apply_opencti_operation(item, opencti_operation)
        elif "opencti_operation" in item:
            self.apply_opencti_operation(item, item["opencti_operation"])
        elif item["type"] == "relationship":
            # Import relationship
            self.import_relationship(item, update, types)
        elif item["type"] == "sighting":
            # region Resolve the to
            to_ids = []
            if "x_opencti_where_sighted_refs" in item:
                for where_sighted_ref in item["x_opencti_where_sighted_refs"]:
                    to_ids.append(where_sighted_ref)
            elif "where_sighted_refs" in item:
                for where_sighted_ref in item["where_sighted_refs"]:
                    to_ids.append(where_sighted_ref)
            # endregion
            # region Resolve the from
            from_id = None
            if "x_opencti_sighting_of_ref" in item:
                from_id = item["x_opencti_sighting_of_ref"]
            elif "sighting_of_ref" in item:
                from_id = item["sighting_of_ref"]
            # endregion
            # region create the sightings
            if len(to_ids) > 0:
                if from_id:
                    for to_id in to_ids:
                        self.import_sighting(item, from_id, to_id, update)
                # Import observed_data_refs
                if "observed_data_refs" in item:
                    for observed_data_ref in item["observed_data_refs"]:
                        for to_id in to_ids:
                            self.import_sighting(item, observed_data_ref, to_id, update)
            # endregion
        elif item["type"] == "label":
            stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
            self.opencti.label.create(
                stix_id=item["id"],
                value=item["value"],
                color=item["color"],
                x_opencti_stix_ids=stix_ids,
                update=update,
            )
        elif item["type"] == "vocabulary":
            stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
            self.opencti.vocabulary.create(
                stix_id=item["id"],
                name=item["name"],
                category=item["category"],
                description=(item["description"] if "description" in item else None),
                aliases=item["aliases"] if "aliases" in item else None,
                x_opencti_stix_ids=stix_ids,
                update=update,
            )
        elif item["type"] == "external-reference":
            stix_ids = self.opencti.get_attribute_in_extension("stix_ids", item)
            self.opencti.external_reference.create(
                stix_id=item["id"],
                source_name=(item["source_name"] if "source_name" in item else None),
                url=item["url"] if "url" in item else None,
                external_id=(item["external_id"] if "external_id" in item else None),
                description=(item["description"] if "description" in item else None),
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
            if item["type"] == "marking-definition" or types is None or len(types) == 0:
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
                        self.opencti.get_attribute_in_extension("location_type", item)
                        is not None
                    ):
                        if (
                            self.opencti.get_attribute_in_extension(
                                "location_type", item
                            ).lower()
                            in types
                        ):
                            self.import_object(item, update, types)
        if work_id is not None:
            self.opencti.work.report_expectation(work_id, None)
        bundles_success_counter.add(1)
        return True

    def import_item_with_retries(
        self,
        item,
        update: bool = False,
        types: List = None,
        work_id: str = None,
    ):
        """Import a single STIX2 item with automatic retry on failures.

        Handles various error types including timeouts, lock errors, missing references,
        and bad gateway errors with appropriate retry strategies.

        :param item: STIX2 item to import
        :type item: dict
        :param update: Whether to update existing data, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: List, optional
        :param work_id: Work ID for tracking import progress, defaults to None
        :type work_id: str, optional
        :return: None on success, the failed item on permanent failure
        :rtype: dict or None
        """
        processing_count = 0
        worker_logger = self.opencti.logger_class("worker")
        while processing_count <= MAX_PROCESSING_COUNT:
            try:
                self.opencti.set_retry_number(processing_count)
                self.import_item(item, update, types, work_id)
                return None
            except (RequestException, Timeout):
                bundles_timeout_error_counter.add(1)
                worker_logger.warning("A connection error or timeout occurred")
                # Platform is under heavy load: wait for unlock & retry almost indefinitely.
                sleep_jitter = round(random.uniform(10, 30), 2)
                time.sleep(sleep_jitter)
                processing_count += 1
            except Exception as ex:  # pylint: disable=broad-except
                error = str(ex)
                error_msg = traceback.format_exc()
                in_retry = processing_count < PROCESSING_COUNT
                # Platform is under heavy load, wait for unlock & retry indefinitely.
                if ERROR_TYPE_LOCK in error_msg:
                    bundles_lock_error_counter.add(1)
                    sleep_jitter = round(random.uniform(1, 3), 2)
                    time.sleep(sleep_jitter)
                    processing_count += 1
                # Platform detects a missing reference and have to retry
                elif ERROR_TYPE_MISSING_REFERENCE in error_msg and in_retry:
                    bundles_missing_reference_error_counter.add(1)
                    sleep_jitter = round(random.uniform(1, 3), 2)
                    time.sleep(sleep_jitter)
                    processing_count += 1
                # A bad gateway error occurs
                elif ERROR_TYPE_BAD_GATEWAY in error_msg:
                    worker_logger.error(
                        "Message reprocess for bad gateway",
                        {"count": processing_count},
                    )
                    bundles_bad_gateway_error_counter.add(1)
                    time.sleep(60)
                    processing_count += 1
                # Request timeout error occurs
                elif ERROR_TYPE_TIMEOUT in error_msg:
                    worker_logger.error(
                        "Message reprocess for request timed out",
                        {"count": processing_count},
                    )
                    bundles_timed_out_error_counter.add(1)
                    time.sleep(60)
                    processing_count += 1
                # A draft lock error occurs
                elif ERROR_TYPE_DRAFT_LOCK in error_msg:
                    bundles_technical_error_counter.add(1)
                    if work_id is not None:
                        self.opencti.work.api.set_draft_id("")
                        self.opencti.work.report_expectation(
                            work_id,
                            {
                                "error": error,
                                "source": "Draft in read only",
                            },
                        )
                    return None
                # Platform does not know what to do and raises an error:
                # That also works for missing reference with too much execution
                else:
                    bundles_technical_error_counter.add(1)
                    worker_logger.error(
                        "Unrecognized error during bundle import", {"error": error}
                    )
                    if work_id is not None:
                        item_str = json.dumps(item)
                        self.opencti.work.report_expectation(
                            work_id,
                            {
                                "error": error,
                                "source": (
                                    item_str
                                    if len(item_str) < 50000
                                    else "Bundle too large"
                                ),
                            },
                        )
                    return None

        max_retry_error_message = "Max number of retries reached, please see error logs of workers for more details. Bundle will be sent to dead letter queue."
        worker_logger.error(max_retry_error_message)
        if work_id is not None:
            item_str = json.dumps(item)
            self.opencti.work.report_expectation(
                work_id,
                {
                    "error": max_retry_error_message,
                    "source": (
                        item_str if len(item_str) < 50000 else "Bundle too large"
                    ),
                },
            )
        return item

    def import_bundle(
        self,
        stix_bundle: Dict,
        update: bool = False,
        types: List = None,
        work_id: str = None,
        objects_max_refs: int = 0,
    ) -> Tuple[list, list]:
        """Import a complete STIX2 bundle into OpenCTI.

        :param stix_bundle: STIX2 bundle dictionary to import
        :type stix_bundle: Dict
        :param update: Whether to update existing data, defaults to False
        :type update: bool, optional
        :param types: List of STIX2 types to filter, defaults to None
        :type types: List, optional
        :param work_id: Work ID for tracking import progress, defaults to None
        :type work_id: str, optional
        :param objects_max_refs: Maximum number of object references allowed; objects exceeding
            this limit will be rejected. Set to 0 to disable the limit.
        :type objects_max_refs: int, optional
        :return: Tuple of (list of successfully imported elements, list of failed/too-large elements)
        :rtype: Tuple[list, list]
        :raises ValueError: If the bundle is not properly formatted or empty
        """
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

        stix2_splitter = OpenCTIStix2Splitter()
        _, incompatible_elements, bundles = (
            stix2_splitter.split_bundle_with_expectations(
                stix_bundle, False, event_version
            )
        )

        # Report every element ignored during bundle splitting
        if work_id is not None:
            for incompatible_element in incompatible_elements:
                self.opencti.work.report_expectation(
                    work_id,
                    {
                        "error": "Incompatible element in bundle",
                        "source": "Element "
                        + incompatible_element["id"]
                        + " is incompatible and couldn't be processed",
                    },
                )

        # Import every element in a specific order
        imported_elements = []
        too_large_elements_bundles = []
        for bundle in bundles:
            for item in bundle["objects"]:
                # If item is considered too large, meaning that it has a number of refs higher than inputted objects_max_refs, do not import it
                nb_refs = OpenCTIStix2Utils.compute_object_refs_number(item)
                if 0 < objects_max_refs <= nb_refs:
                    self.opencti.work.report_expectation(
                        work_id,
                        {
                            "error": "Too large element in bundle",
                            "source": "Element "
                            + item["id"]
                            + " is too large and couldn't be processed",
                        },
                    )
                    too_large_elements_bundles.append(item)
                else:
                    failed_item = self.import_item_with_retries(
                        item, update, types, work_id
                    )
                    if failed_item is not None:
                        too_large_elements_bundles.append(item)
                    else:
                        imported_elements.append(
                            {"id": item["id"], "type": item["type"]}
                        )

        return imported_elements, too_large_elements_bundles

    @staticmethod
    def put_attribute_in_extension(
        stix_object, extension_id, key, value, multiple=False
    ) -> any:
        """Add or update an attribute in a STIX object's extension.

        :param stix_object: STIX object to modify
        :type stix_object: dict
        :param extension_id: ID of the extension to add the attribute to
        :type extension_id: str
        :param key: Attribute key name
        :type key: str
        :param value: Attribute value to set
        :type value: any
        :param multiple: If True, append value to a list; if False, replace the value
        :type multiple: bool
        :return: Modified STIX object
        :rtype: dict
        """
        if ("x_opencti_" + key) in stix_object:
            del stix_object["x_opencti_" + key]
        if ("x_mitre_" + key) in stix_object:
            del stix_object["x_mitre_" + key]
        if "extensions" not in stix_object:
            stix_object["extensions"] = {}
        if extension_id not in stix_object["extensions"]:
            stix_object["extensions"][extension_id] = {}
        if key in stix_object["extensions"][extension_id]:
            if multiple:
                stix_object["extensions"][extension_id][key].append(value)
            else:
                stix_object["extensions"][extension_id][key] = value
        else:
            if multiple:
                stix_object["extensions"][extension_id][key] = [value]
            else:
                stix_object["extensions"][extension_id][key] = value
        return stix_object
