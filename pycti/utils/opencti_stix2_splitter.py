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
    SUPPORTED_STIX_ENTITY_OBJECTS,
)

OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

supported_types = (
    SUPPORTED_STIX_ENTITY_OBJECTS  # entities
    + list(STIX_CYBER_OBSERVABLE_MAPPING.keys())  # observables
    + ["relationship", "sighting"]  # relationships
)


def is_id_supported(key):
    if "--" in key:
        id_type = key.split("--")[0]
        return id_type in supported_types
    # If not a stix id, don't try to filter
    return True


class OpenCTIStix2Splitter:
    def __init__(self):
        self.cache_index = {}
        self.cache_refs = {}
        self.elements = []

    def get_internal_ids_in_extension(self, item):
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
            if key.endswith("_refs"):
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
            elif key == "external_references":
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
            elif key == "kill_chain_phases":
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
                    item["sighting_of_ref"] is not None
                    and len(item["where_sighted_refs"]) > 0
                )
            else:
                is_compatible = is_id_supported(item_id)
            if is_compatible:
                self.elements.append(item)
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
    ) -> Tuple[int, list]:
        """splits a valid stix2 bundle into a list of bundles"""
        if use_json:
            try:
                bundle_data = json.loads(bundle)
            except:
                raise Exception("File data is not a valid JSON")
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
            return elem["nb_deps"]

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

        return number_expectations, bundles

    @deprecated("Use split_bundle_with_expectations instead")
    def split_bundle(self, bundle, use_json=True, event_version=None) -> list:
        expectations, bundles = self.split_bundle_with_expectations(
            bundle, use_json, event_version
        )
        return bundles

    @staticmethod
    def stix2_create_bundle(bundle_id, bundle_seq, items, use_json, event_version=None):
        """create a stix2 bundle with items

        :param items: valid stix2 items
        :type items:
        :param use_json: use JSON?
        :type use_json:
        :return: JSON of the stix2 bundle
        :rtype:
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
