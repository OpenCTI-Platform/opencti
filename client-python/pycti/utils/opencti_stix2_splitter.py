import copy
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
    STIX_EXT_OCTI_TIMELINE,
    SUPPORTED_INTERNAL_OBJECTS,
    SUPPORTED_STIX_ENTITY_OBJECTS,
    TIMELINE_REQUIRED_IDS,
)

OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

supported_types = (
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
    if "--" in key:
        id_type = key.split("--")[0]
        return id_type in supported_types
    # If not a stix id, don't try to filter
    return True


class OpenCTIStix2Splitter:
    """STIX2 bundle splitter for OpenCTI.

    Splits large STIX2 bundles into smaller chunks for processing,
    handling dependencies between objects and deduplicating references.
    """

    def __init__(self):
        """Initialize the STIX2 bundle splitter.

        Sets up internal caches for tracking processed elements,
        references, and incompatible items.
        """
        self.cache_index = {}
        self.cache_refs = {}
        self.elements = []
        self.incompatible_items = []
        # Per incident or case, the elements of its timeline imported after it
        self.timeline_deferred_refs = {}

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

    @staticmethod
    def get_timeline_extension_refs(item):
        """Get the refs nested in the timeline extension of an incident or a case.

        The elements, authors and markings of the analyst contributions are
        dependencies of the container that carries them.

        :param item: the STIX object to extract the refs from
        :type item: dict
        :return: list of the distinct refs, in their order of appearance
        :rtype: list
        """
        extension = (item.get("extensions") or {}).get(STIX_EXT_OCTI_TIMELINE)
        if not isinstance(extension, dict):
            return []
        refs = []
        for event in extension.get("events") or []:
            if not isinstance(event, dict):
                continue
            for key in ("element_ref", "created_by_ref"):
                if isinstance(event.get(key), str):
                    refs.append(event[key])
            for marking_ref in event.get("object_marking_refs") or []:
                if isinstance(marking_ref, str):
                    refs.append(marking_ref)
        for annotation in extension.get("annotations") or []:
            if isinstance(annotation, dict) and isinstance(
                annotation.get("element_ref"), str
            ):
                refs.append(annotation["element_ref"])
        return list(dict.fromkeys(refs))

    def refers_to(self, start_id, target_id, raw_data):
        """Tell whether an object of the bundle refers to another one.

        The reference may be direct or go through the objects it refers to, by
        their refs or by the refs of their timeline extension.

        :param start_id: the ID of the object to start from
        :type start_id: str
        :param target_id: the ID of the object to look for
        :type target_id: str
        :param raw_data: the raw data dictionary of all items
        :type raw_data: dict
        :return: True if target_id is reachable from start_id
        :rtype: bool
        """
        visited = set()
        to_visit = [start_id]
        while to_visit:
            current_id = to_visit.pop()
            if current_id == target_id:
                return True
            if current_id in visited:
                continue
            visited.add(current_id)
            current = raw_data.get(current_id)
            if not isinstance(current, dict):
                continue
            for key, value in current.items():
                if key.endswith("_ref") and isinstance(value, str):
                    to_visit.append(value)
                elif key.endswith("_refs") and isinstance(value, list):
                    to_visit.extend(ref for ref in value if isinstance(ref, str))
            to_visit.extend(self.get_timeline_extension_refs(current))
        return False

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
        :type parent_acc: list
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
            self.cache_refs[item_id] = []
        for key in list(item.keys()):
            value = item[key]
            # Recursive enlist for every refs
            if key.endswith("_refs") and item[key] is not None:
                to_keep = []
                for element_ref in item[key]:
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
                        self.cache_refs[item_id].append(element_ref)
                        nb_deps += self.enlist_element(
                            element_ref,
                            raw_data,
                            cleanup_inconsistent_bundle,
                            parent_acc + [element_ref],
                        )
                        if element_ref not in to_keep:
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
                    self.cache_refs[item_id].append(value)
                    nb_deps += self.enlist_element(
                        value,
                        raw_data,
                        cleanup_inconsistent_bundle,
                        parent_acc + [value],
                    )
                else:
                    item[key] = None
            # Case for embedded elements (deduplicating and cleanup)
            elif key == "external_references" and item[key] is not None:
                # specific case of splitting external references
                # reference_ids = []
                deduplicated_references = []
                deduplicated_references_cache = {}
                references = item[key]
                for reference in references:
                    reference_id = external_reference_generate_id(
                        url=reference.get("url"),
                        source_name=reference.get("source_name"),
                        external_id=reference.get("external_id"),
                    )
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
            elif key == "kill_chain_phases" and item[key] is not None:
                # specific case of splitting kill_chain phases
                # kill_chain_ids = []
                deduplicated_kill_chain = []
                deduplicated_kill_chain_cache = {}
                kill_chains = item[key]
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

        # The refs nested in a timeline extension are imported before the container,
        # so that its analyst contributions resolve their elements, authors and markings.
        # The extension itself is kept as is: a ref missing from the bundle is skipped on import.
        # An element that refers back to the container (a note about the case) is not waited
        # for: the cycle would be broken by removing that reference from the element. It is
        # imported after the container, and the container is sent again after it.
        for nested_ref in self.get_timeline_extension_refs(item):
            if (
                raw_data.get(nested_ref) is None
                or not is_id_supported(nested_ref)
                or nested_ref == item_id
                or nested_ref in self.cache_refs[item_id]
            ):
                continue
            if (
                nested_ref in parent_acc
                or item_id in (self.cache_refs.get(nested_ref) or [])
                or self.refers_to(nested_ref, item_id, raw_data)
            ):
                deferred = self.timeline_deferred_refs.setdefault(item_id, [])
                if nested_ref not in deferred:
                    deferred.append(nested_ref)
            else:
                self.cache_refs[item_id].append(nested_ref)
                nb_deps += self.enlist_element(
                    nested_ref,
                    raw_data,
                    cleanup_inconsistent_bundle,
                    parent_acc + [nested_ref],
                )

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
        :return: tuple of (number of expectations, incompatible items, list of bundles)
        :rtype: Tuple[int, list, list]
        """
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
            self.enlist_element(item["id"], raw_data, cleanup_inconsistent_bundle, [])

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

        # A container whose timeline names elements imported after it is sent again after
        # them, so that its timeline extension is imported once they exist
        compatible_ids = {element["id"] for element in self.elements}
        for container_id, deferred_refs in self.timeline_deferred_refs.items():
            container = self.cache_index.get(container_id)
            required_refs = [
                ref
                for ref in deferred_refs
                if self.cache_index.get(ref) is not None
                and self.cache_index[ref]["id"] in compatible_ids
            ]
            if (
                container is None
                or container["id"] not in compatible_ids
                or len(required_refs) == 0
            ):
                continue
            resent_container = copy.deepcopy(container)
            resent_container[TIMELINE_REQUIRED_IDS] = required_refs
            resent_container["nb_deps"] = 1 + max(
                [container["nb_deps"]]
                + [self.cache_index[ref]["nb_deps"] for ref in required_refs]
            )
            # The first copy creates the container without its timeline: the milestones are
            # imported once, by the copy sent after the elements they point to
            first_container = {
                **container,
                "extensions": {
                    key: value
                    for key, value in (container.get("extensions") or {}).items()
                    if key != STIX_EXT_OCTI_TIMELINE
                },
            }
            self.elements = [
                first_container if element is container else element
                for element in self.elements
            ]
            self.elements.append(resent_container)

        self.elements.sort(key=by_dep_size)

        elements_with_deps = list(
            map(lambda e: {"nb_deps": e["nb_deps"], "elements": [e]}, self.elements)
        )

        number_expectations = 0
        for entity in elements_with_deps:
            number_expectations += len(entity["elements"])
            bundles.append(
                self.stix2_create_bundle(
                    bundle_data["id"],
                    entity["nb_deps"],
                    entity["elements"],
                    use_json,
                    event_version,
                )
            )

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
