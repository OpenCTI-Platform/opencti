import json
import uuid


class OpenCTIStix2Splitter:
    def __init__(self):
        self.cache_index = {}
        self.cache_added = []
        self.entities = []
        self.relationships = []

    def enlist_entity_element(self, item_id, raw_data):
        nb_deps = 0
        item = raw_data[item_id]
        is_marking = item["id"].startswith('marking-definition--')
        if "created_by_ref" in item and is_marking is False and self.cache_index.get(item["created_by_ref"]) is None:
            nb_deps += 1
            self.enlist_entity_element(item["created_by_ref"], raw_data)

        if "object_refs" in item:
            for object_ref in item["object_refs"]:
                nb_deps += 1
                if self.cache_index.get(object_ref) is None:
                    self.enlist_entity_element(object_ref, raw_data)

        if "object_marking_refs" in item:
            for object_marking_ref in item["object_marking_refs"]:
                nb_deps += 1
                if self.cache_index.get(object_marking_ref) is None:
                    self.enlist_entity_element(object_marking_ref, raw_data)

        item["nb_deps"] = nb_deps
        self.entities.append(item)
        self.cache_index[item_id] = item  # Put in cache

    def enlist_relation_element(self, item_id, raw_data):
        nb_deps = 0
        item = raw_data[item_id]
        source = item["source_ref"]
        target = item["target_ref"]
        if source.startswith('relationship--'):
            nb_deps += 1
            if self.cache_index.get(source) is None:
                self.enlist_entity_element(target, raw_data)
        if target.startswith('relationship--'):
            nb_deps += 1
            if self.cache_index.get(target) is None:
                self.enlist_entity_element(target, raw_data)
        item["nb_deps"] = nb_deps
        self.relationships.append(item)
        self.cache_index[item_id] = item  # Put in cache

    def split_bundle(self, bundle) -> list:
        """splits a valid stix2 bundle into a list of bundles

        :param bundle: valid stix2 bundle
        :type bundle:
        :raises Exception: if data is not valid JSON
        :return: returns a list of bundles
        :rtype: list
        """
        try:
            bundle_data = json.loads(bundle)
        except:
            raise Exception("File data is not a valid JSON")

        raw_data = {}
        for item in bundle_data["objects"]:
            raw_data[item["id"]] = item

        for item in bundle_data["objects"]:
            is_entity = item["type"] != "relationship"
            if is_entity:
                self.enlist_entity_element(item["id"], raw_data)

        for item in bundle_data["objects"]:
            is_relation = item["type"] == "relationship"
            if is_relation:
                self.enlist_relation_element(item["id"], raw_data)

        bundles = []
        for entity in self.entities:
            bundles.append(self.stix2_create_bundle([entity]))
        for relationship in self.relationships:
            bundles.append(self.stix2_create_bundle([relationship]))
        return bundles

    # @deprecated
    def split_stix2_bundle(self, bundle) -> list:
        """splits a valid stix2 bundle into a list of bundles

        :param bundle: valid stix2 bundle
        :type bundle:
        :raises Exception: if data is not valid JSON
        :return: returns a list of bundles
        :rtype: list
        """
        try:
            bundle_data = json.loads(bundle)
        except:
            raise Exception("File data is not a valid JSON")

        # validation = validate_parsed_json(bundle_data)
        # if not validation.is_valid:
        #     raise ValueError('The bundle is not a valid STIX2 JSON:' + bundle)

        # Index all objects by id
        for item in bundle_data["objects"]:
            self.cache_index[item["id"]] = item

        bundles = []
        # Reports must be handled because of object_refs
        for item in bundle_data["objects"]:
            if item["type"] == "report":
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_report_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Relationships not added in previous reports
        for item in bundle_data["objects"]:
            if item["type"] == "relationship" and item["id"] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_relationship_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Entities not added in previous reports and relationships
        for item in bundle_data["objects"]:
            if item["type"] != "relationship" and item["id"] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(
                    self.stix2_get_entity_objects(item)
                )
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send["id"])
                bundles.append(self.stix2_create_bundle(items_to_send))

        return bundles

    @staticmethod
    def stix2_deduplicate_objects(items) -> list:
        """deduplicate stix2 items

        :param items: valid stix2 items
        :type items:
        :return: de-duplicated list of items
        :rtype: list
        """

        ids = []
        final_items = []
        for item in items:
            if item["id"] not in ids:
                final_items.append(item)
                ids.append(item["id"])
        return final_items

    def stix2_get_report_objects(self, report) -> list:
        """get a list of items for a stix2 report object

        :param report: valid stix2 report object
        :type report:
        :return: list of items for a stix2 report object
        :rtype: list
        """

        items = [report]
        # Add all object refs
        for object_ref in report["object_refs"]:
            items.append(self.cache_index[object_ref])
        for item in items:
            if item["type"] == "relationship":
                items = items + self.stix2_get_relationship_objects(item)
            else:
                items = items + self.stix2_get_entity_objects(item)
        return items

    @staticmethod
    def stix2_create_bundle(items):
        """create a stix2 bundle with items

        :param items: valid stix2 items
        :type items:
        :return: JSON of the stix2 bundle
        :rtype:
        """

        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.0",
            "objects": items,
        }
        return json.dumps(bundle)

    def stix2_get_relationship_objects(self, relationship) -> list:
        """get a list of relations for a stix2 relationship object

        :param relationship: valid stix2 relationship
        :type relationship:
        :return: list of relations objects
        :rtype: list
        """

        items = [relationship]
        # Get source ref
        if relationship["source_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["source_ref"]])

        # Get target ref
        if relationship["target_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["target_ref"]])

        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(relationship)
        # Add created by ref
        if embedded_objects["created_by_ref"] is not None:
            items.append(embedded_objects["created_by_ref"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items

    def stix2_get_embedded_objects(self, item) -> dict:
        """gets created and marking refs for a stix2 item

        :param item: valid stix2 item
        :type item:
        :return: returns a dict of created_by_ref of object_marking_refs
        :rtype: dict
        """
        # Marking definitions
        object_marking_refs = []
        if "object_marking_refs" in item:
            for object_marking_ref in item["object_marking_refs"]:
                if object_marking_ref in self.cache_index:
                    object_marking_refs.append(self.cache_index[object_marking_ref])
        # Created by ref
        created_by_ref = None
        if "created_by_ref" in item and item["created_by_ref"] in self.cache_index:
            created_by_ref = self.cache_index[item["created_by_ref"]]

        return {
            "object_marking_refs": object_marking_refs,
            "created_by_ref": created_by_ref,
        }

    def stix2_get_entity_objects(self, entity) -> list:
        """process a stix2 entity

        :param entity: valid stix2 entity
        :type entity:
        :return: entity objects as list
        :rtype: list
        """

        items = [entity]
        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(entity)
        # Add created by ref
        if embedded_objects["created_by_ref"] is not None:
            items.append(embedded_objects["created_by_ref"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items