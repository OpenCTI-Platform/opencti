import json
import uuid


class OpenCTIStix2Splitter:
    def __init__(self):
        self.cache_index = {}
        self.cache_added = []
        self.entities = []
        self.relationships = []

    def enlist_entity_element(self, item_id, raw_data):
        if item_id not in raw_data:
            return
        nb_deps = 0
        item = raw_data[item_id]
        is_marking = item["id"].startswith("marking-definition--")
        if (
            "created_by_ref" in item
            and is_marking is False
            and self.cache_index.get(item["created_by_ref"]) is None
        ):
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
        if item_id not in raw_data:
            return
        nb_deps = 0
        item = raw_data[item_id]
        source = item["source_ref"]
        target = item["target_ref"]
        if source.startswith("relationship--"):
            nb_deps += 1
            if self.cache_index.get(source) is None:
                self.enlist_entity_element(target, raw_data)
        if target.startswith("relationship--"):
            nb_deps += 1
            if self.cache_index.get(target) is None:
                self.enlist_entity_element(target, raw_data)
        item["nb_deps"] = nb_deps
        self.relationships.append(item)
        self.cache_index[item_id] = item  # Put in cache

    def split_bundle(self, bundle, use_json=True) -> list:
        """splits a valid stix2 bundle into a list of bundles

        :param bundle: valid stix2 bundle
        :type bundle:
        :param use_json: is JSON?
        :type use_json:
        :raises Exception: if data is not valid JSON
        :return: returns a list of bundles
        :rtype: list
        """
        if use_json:
            try:
                bundle_data = json.loads(bundle)
            except:
                raise Exception("File data is not a valid JSON")
        else:
            bundle_data = bundle
            if "objects" not in bundle_data:
                raise Exception("File data is not a valid bundle")

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
            bundles.append(self.stix2_create_bundle([entity], use_json))
        for relationship in self.relationships:
            bundles.append(self.stix2_create_bundle([relationship], use_json))
        return bundles

    @staticmethod
    def stix2_create_bundle(items, use_json):
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
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "objects": items,
        }
        return json.dumps(bundle) if use_json else bundle
