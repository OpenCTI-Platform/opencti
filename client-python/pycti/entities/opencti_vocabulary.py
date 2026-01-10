import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class Vocabulary:
    """Main Vocabulary class for OpenCTI

    Manages vocabularies and controlled vocabularies in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

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
        """Generate a STIX ID for a Vocabulary.

        :param name: the name of the Vocabulary
        :type name: str
        :param category: the category of the Vocabulary
        :type category: str
        :return: STIX ID for the Vocabulary
        :rtype: str
        """
        name = name.lower().strip()
        data = {"name": name, "category": category}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "vocabulary--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from Vocabulary data.

        :param data: Dictionary containing 'name' and 'category' keys
        :type data: dict
        :return: STIX ID for the Vocabulary
        :rtype: str
        """
        return Vocabulary.generate_id(data["name"], data["category"])

    def list(self, **kwargs):
        """List Vocabulary objects.

        :param filters: the filters to apply
        :type filters: dict
        :return: List of Vocabulary objects
        :rtype: list
        """
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
        """Read a Vocabulary object.

        :param id: the id of the Vocabulary
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :return: Vocabulary object
        :rtype: dict or None
        """
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

    def read_or_create_unchecked_with_cache(self, vocab, cache, field):
        """Read or create a Vocabulary using a cache for optimization.

        :param vocab: the vocabulary name
        :type vocab: str
        :param cache: the cache dictionary
        :type cache: dict
        :param field: the field configuration containing 'required' and 'key'
        :type field: dict
        :return: Vocabulary object or None
        :rtype: dict or None
        """
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
        """Create a Vocabulary object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param name: the name of the Vocabulary (required)
        :type name: str
        :param category: the category of the Vocabulary (required)
        :type category: str
        :param description: (optional) description
        :type description: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param aliases: (optional) list of aliases
        :type aliases: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :return: Vocabulary object
        :rtype: dict or None
        """
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
            return None

    def read_or_create_unchecked(self, **kwargs):
        """Read or create a Vocabulary.

        If the user has no rights to create the vocabulary, return None.

        :param name: the vocabulary name
        :type name: str
        :param required: whether the vocabulary is required
        :type required: bool
        :param category: the category of the vocabulary
        :type category: str
        :return: The available or created Vocabulary object
        :rtype: dict or None
        """
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
        """Update a Vocabulary object field.

        :param id: the Vocabulary id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: The updated Vocabulary object
        :rtype: dict or None
        """
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
