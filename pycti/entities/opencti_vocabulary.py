import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class Vocabulary:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            name
            category {
                key
                fields {
                    key
                }
            }
        """

    @staticmethod
    def generate_id(name, category):
        name = name.lower().strip()
        data = {"name": name, "category": category}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "vocabulary--" + id

    @staticmethod
    def generate_id_from_data(data):
        return Vocabulary.generate_id(data["name"], data["category"])

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        self.opencti.app_logger.info(
            "Listing Vocabularies with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                    query Vocabularies($filters: FilterGroup) {
                        vocabularies(filters: $filters) {
                            edges {
                                node {
                                    """
            + self.properties
            + """
                        }
                    }
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "filters": filters,
            },
        )
        return self.opencti.process_multiple(result["data"]["vocabularies"])

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.app_logger.info("Reading vocabulary", {"id": id})
            query = (
                """
                        query Vocabulary($id: String!) {
                            vocabulary(id: $id) {
                                """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["vocabulary"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_vocabulary] Missing parameters: id or filters"
            )
            return None

    def handle_vocab(self, vocab, cache, field):
        if "vocab_" + vocab in cache:
            vocab_data = cache["vocab_" + vocab]
        else:
            vocab_data = self.read_or_create_unchecked(
                name=vocab,
                required=field["required"],
                category=cache["category_" + field["key"]],
            )
        if vocab_data is not None:
            cache["vocab_" + vocab] = vocab_data
        return vocab_data

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        category = kwargs.get("category", None)
        description = kwargs.get("description", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        aliases = kwargs.get("aliases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if name is not None and category is not None:
            self.opencti.app_logger.info(
                "Creating or Getting aliased Vocabulary", {"name": name}
            )
            query = (
                """
                        mutation VocabularyAdd($input: VocabularyAddInput!) {
                            vocabularyAdd(input: $input) {
                                """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "stix_id": stix_id,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "name": name,
                        "description": description,
                        "category": category,
                        "created": created,
                        "modified": modified,
                        "aliases": aliases,
                        "update": update,
                    }
                },
            )
            return result["data"]["vocabularyAdd"]
        else:
            self.opencti.app_logger.error(
                "[opencti_vocabulary] Missing parameters: name or category",
            )

    def read_or_create_unchecked(self, **kwargs):
        value = kwargs.get("name", None)
        vocab = self.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [value]}],
                "filterGroups": [],
            }
        )
        if vocab is None:
            try:
                return self.create(**kwargs)
            except ValueError:
                return None
        return vocab

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Vocabulary", {"id": id})
            query = """
                        mutation VocabularyEdit($id: ID!, $input: [EditInput!]!) {
                            vocabularyFieldPatch(id: $id, input: $input) { 
                                id
                                standard_id
                                entity_type
                            }
                        }
                    """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "input": input,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["vocabularyFieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_vocabulary] Missing parameters: id and key and value"
            )
            return None
