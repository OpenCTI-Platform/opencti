import json
import uuid
from typing import Tuple

from typing_extensions import deprecated

from pycti.utils.opencti_stix2_identifier import (
    external_reference_generate_id,
    kill_chain_phase_generate_id,
)
from pycti.utils.opencti_stix2_utils import (
    STIX_CYBER_OBSERVABLE_MAPPING,
    SUPPORTED_INTERNAL_OBJECTS,
    SUPPORTED_STIX_ENTITY_OBJECTS,
)

OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

supported_types = frozenset(
    SUPPORTED_STIX_ENTITY_OBJECTS  # entities
    + SUPPORTED_INTERNAL_OBJECTS  # internals
    + list(STIX_CYBER_OBSERVABLE_MAPPING.keys())  # observables
    + ["relationship", "sighting"]  # relationships
    + ["pir"]
)


def is_id_supported(key):
    """Check if a STIX ID type is supported for processing.

    :param key: STIX ID or identifier to check
    :type key: str
    :return: True if the ID type is supported, False otherwise
    :rtype: bool
    """
    id_type, separator, _ = key.partition("--")
    if separator:
        return id_type in supported_types
    # If not a stix id, don't try to filter
    return True


class OpenCTIStix2Splitter:
    """STIX2 bundle splitter for OpenCTI.

    Splits large STIX2 bundles into smaller chunks for processing,
    handling dependencies between objects and deduplicating references.
    """

    def __init__(self, external_reference_id_generator=None):
        """Initialize the STIX2 bundle splitter.

        Sets up internal caches for tracking processed elements,
        references, and incompatible items.
        """
        self.cache_index = {}
        self.cache_refs = {}
        self.external_reference_ids = {}
        self._external_reference_id_generator = (
            external_reference_id_generator or external_reference_generate_id
        )
        self.elements = []
        self.incompatible_items = []

    def _get_external_reference_id(self, reference):
        url = reference.get("url")
        source_name = reference.get("source_name")
        external_id = reference.get("external_id")
        cache_key = (url, source_name, external_id)
        if not (
            (url is None or isinstance(url, str))
            and (source_name is None or isinstance(source_name, str))
            and (external_id is None or isinstance(external_id, str))
        ):
            return self._external_reference_id_generator(
                url=url,
                source_name=source_name,
                external_id=external_id,
            )
        if cache_key not in self.external_reference_ids:
            self.external_reference_ids[cache_key] = (
                self._external_reference_id_generator(
                    url=url,
                    source_name=source_name,
                    external_id=external_id,
                )
            )
        return self.external_reference_ids[cache_key]

    def get_internal_ids_in_extension(self, item):
        """Get internal IDs from OpenCTI extensions in a STIX object.

        :param item: the STIX object to extract IDs from
        :type item: dict
        :return: list of internal IDs found in extensions
        :rtype: list
        """
        ids = []
        if item.get("x_opencti_id"):
            ids.append(item["x_opencti_id"])
        if (
            item.get("extensions")
            and item["extensions"].get(OPENCTI_EXTENSION)
            and item["extensions"].get(OPENCTI_EXTENSION).get("id")
        ):
            ids.append(item["extensions"][OPENCTI_EXTENSION]["id"])
        return ids

    def enlist_element(
        self, item_id, raw_data, cleanup_inconsistent_bundle, parent_acc
    ):
        """Enlist an element and its dependencies for processing.

        :param item_id: the ID of the item to enlist
        :type item_id: str
        :param raw_data: the raw data dictionary of all items
        :type raw_data: dict
        :param cleanup_inconsistent_bundle: whether to cleanup inconsistent references
        :type cleanup_inconsistent_bundle: bool
        :param parent_acc: accumulator of parent IDs to prevent circular references
        :type parent_acc: set
        :return: number of dependencies enlisted
        :rtype: int
        """
        nb_deps = 1
        if item_id not in raw_data:
            return 0

        existing_item = self.cache_index.get(item_id)
        if existing_item is not None:
            return existing_item["nb_deps"]

        item = raw_data[item_id]
        if self.cache_refs.get(item_id) is None:
            self.cache_refs[item_id] = set()
        for key in tuple(item):
            value = item[key]
            # Recursive enlist for every refs
            if key.endswith("_refs") and value is not None:
                to_keep = []
                to_keep_ids = set()
                for element_ref in value:
                    # We need to check if this ref is not already a reference
                    is_missing_ref = raw_data.get(element_ref) is None
                    must_be_cleaned = is_missing_ref and cleanup_inconsistent_bundle
                    not_dependency_ref = (
                        self.cache_refs.get(element_ref) is None
                        or item_id not in self.cache_refs[element_ref]
                    )
                    # Prevent any self reference
                    if (
                        is_id_supported(element_ref)
                        and not must_be_cleaned
                        and element_ref not in parent_acc
                        and element_ref != item_id
                        and not_dependency_ref
                    ):
                        self.cache_refs[item_id].add(element_ref)
                        parent_acc.add(element_ref)
                        nb_deps += self.enlist_element(
                            element_ref,
                            raw_data,
                            cleanup_inconsistent_bundle,
                            parent_acc,
                        )
                        parent_acc.remove(element_ref)
                        if element_ref not in to_keep_ids:
                            to_keep_ids.add(element_ref)
                            to_keep.append(element_ref)
                    item[key] = to_keep
            elif key.endswith("_ref"):
                is_missing_ref = raw_data.get(value) is None
                must_be_cleaned = is_missing_ref and cleanup_inconsistent_bundle
                not_dependency_ref = (
                    self.cache_refs.get(value) is None
                    or item_id not in self.cache_refs[value]
                )
                # Prevent any self reference
                if (
                    value is not None
                    and not must_be_cleaned
                    and value not in parent_acc
                    and is_id_supported(value)
                    and value != item_id
                    and not_dependency_ref
                ):
                    self.cache_refs[item_id].add(value)
                    parent_acc.add(value)
                    nb_deps += self.enlist_element(
                        value,
                        raw_data,
                        cleanup_inconsistent_bundle,
                        parent_acc,
                    )
                    parent_acc.remove(value)
                else:
                    item[key] = None
            # Case for embedded elements (deduplicating and cleanup)
            elif key == "external_references" and value is not None:
                # specific case of splitting external references
                # reference_ids = []
                deduplicated_references = []
                deduplicated_references_cache = {}
                references = value
                for reference in references:
                    reference_id = self._get_external_reference_id(reference)
                    if (
                        reference_id is not None
                        and deduplicated_references_cache.get(reference_id) is None
                    ):
                        deduplicated_references_cache[reference_id] = reference_id
                        deduplicated_references.append(reference)
                        # - Needed for a future move of splitting the elements
                        # reference["id"] = reference_id
                        # reference["type"] = "External-Reference"
                        # raw_data[reference_id] = reference
                        # if reference_id not in reference_ids:
                        #     reference_ids.append(reference_id)
                        # nb_deps += self.enlist_element(reference_id, raw_data)
                item[key] = deduplicated_references
            elif key == "kill_chain_phases" and value is not None:
                # specific case of splitting kill_chain phases
                # kill_chain_ids = []
                deduplicated_kill_chain = []
                deduplicated_kill_chain_cache = {}
                kill_chains = value
                for kill_chain in kill_chains:
                    kill_chain_id = kill_chain_phase_generate_id(
                        kill_chain_name=kill_chain.get("kill_chain_name"),
                        phase_name=kill_chain.get("phase_name"),
                    )
                    if (
                        kill_chain_id is not None
                        and deduplicated_kill_chain_cache.get(kill_chain_id) is None
                    ):
                        deduplicated_kill_chain_cache[kill_chain_id] = kill_chain_id
                        deduplicated_kill_chain.append(kill_chain)
                        # - Needed for a future move of splitting the elements
                        # kill_chain["id"] = kill_chain_id
                        # kill_chain["type"] = "Kill-Chain-Phase"
                        # raw_data[kill_chain_id] = kill_chain
                        # if kill_chain_id not in kill_chain_ids:
                        #     kill_chain_ids.append(kill_chain_id)
                        # nb_deps += self.enlist_element(kill_chain_id, raw_data)
                item[key] = deduplicated_kill_chain

        # Get the final dep counting and add in cache
        item["nb_deps"] = nb_deps
        # Put in cache
        if self.cache_index.get(item_id) is None:
            # enlist only if compatible
            if item["type"] == "relationship":
                is_compatible = (
                    item["source_ref"] is not None and item["target_ref"] is not None
                )
            elif item["type"] == "sighting":
                is_compatible = (
                    item.get("sighting_of_ref") is not None
                    and len(item.get("where_sighted_refs", [])) > 0
                )
            else:
                is_compatible = is_id_supported(item_id)

            if is_compatible:
                self.elements.append(item)
            else:
                self.incompatible_items.append(item)
            self.cache_index[item_id] = item
            for internal_id in self.get_internal_ids_in_extension(item):
                self.cache_index[internal_id] = item

        return nb_deps

    def split_bundle_with_expectations(
        self,
        bundle,
        use_json=True,
        event_version=None,
        cleanup_inconsistent_bundle=False,
        max_bundle_objects=1,
        max_bundle_bytes=None,
    ) -> Tuple[int, list, list]:
        """Split a valid STIX2 bundle into a list of bundles.

        :param bundle: the STIX2 bundle to split
        :type bundle: str or dict
        :param use_json: whether the bundle is JSON string (True) or dict (False)
        :type use_json: bool
        :param event_version: (optional) event version to include in bundles
        :type event_version: str or None
        :param cleanup_inconsistent_bundle: whether to cleanup inconsistent references
        :type cleanup_inconsistent_bundle: bool
        :param max_bundle_objects: maximum terminal same-dependency-level objects
            per bundle; earlier dependency levels remain singleton bundles so
            multiple queue consumers cannot start a dependent level before its
            prerequisites have drained
        :type max_bundle_objects: int
        :param max_bundle_bytes: maximum serialized bytes per bundle when more than
            one object can be grouped; a single oversized object is emitted as-is
        :type max_bundle_bytes: int or None
        :return: tuple of (number of expectations, incompatible items, list of bundles)
        :rtype: Tuple[int, list, list]
        """
        if (
            isinstance(max_bundle_objects, bool)
            or not isinstance(max_bundle_objects, int)
            or max_bundle_objects <= 0
        ):
            raise ValueError("max_bundle_objects must be a positive integer")
        if max_bundle_bytes is not None and (
            isinstance(max_bundle_bytes, bool)
            or not isinstance(max_bundle_bytes, int)
            or max_bundle_bytes <= 0
        ):
            raise ValueError("max_bundle_bytes must be a positive integer")

        if use_json:
            try:
                bundle_data = json.loads(bundle)
            except json.JSONDecodeError as e:
                raise Exception(f"File data is not a valid JSON: {e}")
        else:
            bundle_data = bundle

        if "objects" not in bundle_data:
            raise Exception("File data is not a valid bundle")
        if "id" not in bundle_data:
            bundle_data["id"] = "bundle--" + str(uuid.uuid4())

        raw_data = {}

        # Build flat list of elements
        for item in bundle_data["objects"]:
            raw_data[item["id"]] = item
            for internal_id in self.get_internal_ids_in_extension(item):
                raw_data[internal_id] = item
        for item in bundle_data["objects"]:
            self.enlist_element(
                item["id"], raw_data, cleanup_inconsistent_bundle, set()
            )

        # Build the bundles
        bundles = []

        def by_dep_size(elem):
            """Get the dependency count for sorting elements.

            :param elem: Element dictionary containing nb_deps
            :type elem: dict
            :return: Number of dependencies
            :rtype: int
            """
            return elem["nb_deps"]

        self.elements.sort(key=by_dep_size)

        number_expectations = 0
        chunk_items = []
        chunk_dep_size = None
        chunk_max_bundle_objects = 1
        terminal_dep_size = self.elements[-1]["nb_deps"] if self.elements else None

        def append_chunk(bundle_seq, items):
            if max_bundle_bytes is None:
                bundles.append(
                    self.stix2_create_bundle(
                        bundle_data["id"],
                        bundle_seq,
                        items,
                        use_json,
                        event_version,
                    )
                )
                return

            serialized_bundle = self.stix2_create_bundle(
                bundle_data["id"], bundle_seq, items, True, event_version
            )
            # json.dumps() keeps ensure_ascii=True, so string length is byte length.
            if len(items) == 1 or len(serialized_bundle) <= max_bundle_bytes:
                bundles.append(
                    serialized_bundle
                    if use_json
                    else self.stix2_create_bundle(
                        bundle_data["id"],
                        bundle_seq,
                        items,
                        False,
                        event_version,
                    )
                )
                return

            empty_bundle_size = len(
                self.stix2_create_bundle(
                    bundle_data["id"], bundle_seq, [], True, event_version
                )
            )
            bounded_items = []
            bounded_serialized_bytes = empty_bundle_size
            for item in items:
                item_serialized_bytes = len(json.dumps(item))
                projected_size = (
                    bounded_serialized_bytes
                    + (2 if bounded_items else 0)
                    + item_serialized_bytes
                )
                if bounded_items and projected_size > max_bundle_bytes:
                    bundles.append(
                        self.stix2_create_bundle(
                            bundle_data["id"],
                            bundle_seq,
                            bounded_items,
                            use_json,
                            event_version,
                        )
                    )
                    bounded_items = []
                    bounded_serialized_bytes = empty_bundle_size
                bounded_items.append(item)
                if len(bounded_items) > 1:
                    bounded_serialized_bytes += 2
                bounded_serialized_bytes += item_serialized_bytes
            if bounded_items:
                bundles.append(
                    self.stix2_create_bundle(
                        bundle_data["id"],
                        bundle_seq,
                        bounded_items,
                        use_json,
                        event_version,
                    )
                )

        for element in self.elements:
            number_expectations += 1
            element_max_bundle_objects = (
                max_bundle_objects if element["nb_deps"] == terminal_dep_size else 1
            )
            if chunk_items and (
                element["nb_deps"] != chunk_dep_size
                or len(chunk_items) >= chunk_max_bundle_objects
            ):
                append_chunk(chunk_dep_size, chunk_items)
                chunk_items = []
            if not chunk_items:
                chunk_dep_size = element["nb_deps"]
                chunk_max_bundle_objects = element_max_bundle_objects
            chunk_items.append(element)

        if chunk_items:
            append_chunk(chunk_dep_size, chunk_items)

        return (
            number_expectations,
            self.incompatible_items,
            bundles,
        )

    @deprecated("Use split_bundle_with_expectations instead")
    def split_bundle(self, bundle, use_json=True, event_version=None) -> list:
        """Split a valid STIX2 bundle into a list of bundles.

        .. deprecated::
            Use :meth:`split_bundle_with_expectations` instead.

        :param bundle: the STIX2 bundle to split
        :type bundle: str or dict
        :param use_json: whether the bundle is JSON string (True) or dict (False)
        :type use_json: bool
        :param event_version: (optional) event version to include in bundles
        :type event_version: str or None
        :return: list of STIX2 bundles
        :rtype: list
        """
        _, _, bundles = self.split_bundle_with_expectations(
            bundle, use_json, event_version
        )
        return bundles

    @staticmethod
    def stix2_create_bundle(bundle_id, bundle_seq, items, use_json, event_version=None):
        """Create a STIX2 bundle with items.

        :param bundle_id: the bundle ID
        :type bundle_id: str
        :param bundle_seq: the bundle sequence number
        :type bundle_seq: int
        :param items: valid STIX2 items
        :type items: list
        :param use_json: whether to return JSON string (True) or dict (False)
        :type use_json: bool
        :param event_version: (optional) event version to include
        :type event_version: str or None
        :return: STIX2 bundle as JSON string or dict
        :rtype: str or dict
        """

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "x_opencti_seq": bundle_seq,
            "objects": items,
        }
        if event_version is not None:
            bundle["x_opencti_event_version"] = event_version
        return json.dumps(bundle) if use_json else bundle
