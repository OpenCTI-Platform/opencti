# coding: utf-8

import json
import uuid
import warnings
from typing import Union

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities.opencti_threat_actor_group import ThreatActorGroup
from pycti.entities.opencti_threat_actor_individual import ThreatActorIndividual


class ThreatActor:
    """Main ThreatActor class for OpenCTI

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the ThreatActor instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.threat_actor_group = ThreatActorGroup(opencti)
        self.threat_actor_individual = ThreatActorIndividual(opencti)
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    identity_class
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        id
                        value
                        color
                    }
                }
                ... on Organization {
                    x_opencti_organization_type
                    x_opencti_reliability
                }
                ... on Individual {
                    x_opencti_firstname
                    x_opencti_lastname
                }
            }
            objectOrganization {
                id
                standard_id
                name
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                created
                modified
                x_opencti_order
                x_opencti_color
            }
            objectLabel {
                id
                value
                color
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                        importFiles {
                            edges {
                                node {
                                    id
                                    name
                                    size
                                    metaData {
                                        mimetype
                                        version
                                    }
                                }
                            }
                        }
                    }
                }
            }
            revoked
            confidence
            created
            modified
            name
            description
            aliases
            threat_actor_types
            first_seen
            last_seen
            roles
            goals
            sophistication
            resource_level
            primary_motivation
            secondary_motivations
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                        metaData {
                            mimetype
                            version
                        }
                    }
                }
            }
        """

    @staticmethod
    def generate_id(name, opencti_type):
        """Generate a STIX ID for a Threat Actor.

        :param name: the name of the Threat Actor
        :type name: str
        :param opencti_type: the type of the Threat Actor (e.g., 'Threat-Actor-Group')
        :type opencti_type: str
        :return: STIX ID for the Threat Actor
        :rtype: str
        """
        data = {"name": name.lower().strip(), "opencti_type": opencti_type}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "threat-actor--" + id

    def generate_id_from_data(self, data):
        """Generate a STIX ID from Threat Actor data.

        :param data: Dictionary containing 'name' and optionally 'x_opencti_type' keys
        :type data: dict
        :return: STIX ID for the Threat Actor
        :rtype: str
        """
        data_type = "Threat-Actor-Group"
        if "x_opencti_type" in data:
            data_type = data["x_opencti_type"]
        elif self.opencti.get_attribute_in_extension("type", data) is not None:
            data_type = self.opencti.get_attribute_in_extension("type", data)
        return ThreatActor.generate_id(data["name"], data_type)

    def list(self, **kwargs) -> dict:
        """List Threat-Actor objects.

        :param filters: the filters to apply
        :type filters: dict
        :param search: the search keyword
        :type search: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :param orderBy: field to order results by
        :type orderBy: str
        :param orderMode: ordering mode (asc/desc)
        :type orderMode: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param getAll: whether to retrieve all results
        :type getAll: bool
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :return: List of Threat-Actor objects
        :rtype: list
        """

        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.app_logger.info(
            "Listing Threat-Actors with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query ThreatActors($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: ThreatActorsOrdering, $orderMode: OrderingMode) {
                    threatActors(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                        edges {
                            node {
                                """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["threatActors"])
            final_data = final_data + data
            while result["data"]["threatActors"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["threatActors"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug("Listing threatActors", {"after": after})
                result = self.opencti.query(
                    query,
                    {
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["threatActors"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["threatActors"], with_pagination
            )

    def read(self, **kwargs) -> Union[dict, None]:
        """Read a Threat-Actor object.

        :param id: the id of the Threat-Actor
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: Threat-Actor object
        :rtype: dict or None
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Threat-Actor", {"id": id})
            query = (
                """
                    query ThreatActor($id: String!) {
                        threatActor(id: $id) {
                            """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else self.properties
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["threatActor"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_threat_actor] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Threat-Actor-Group object (deprecated).

        .. deprecated::
            Use :meth:`threat_actor_group.create` or :meth:`threat_actor_individual.create` instead.
        """
        warnings.warn(
            "ThreatActor.create() is deprecated, use threat_actor_group.create() "
            "or threat_actor_individual.create() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.threat_actor_group.create(**kwargs)

    def import_from_stix2(self, **kwargs):
        """Import a Threat-Actor object from a STIX2 object.

        :param stixObject: the STIX2 Threat-Actor object
        :type stixObject: dict
        :return: Threat-Actor object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        if "x_opencti_type" in stix_object:
            type = stix_object["x_opencti_type"].lower()
        elif self.opencti.get_attribute_in_extension("type", stix_object) is not None:
            type = self.opencti.get_attribute_in_extension("type", stix_object).lower()
        elif (
            "resource_level" in stix_object
            and stix_object["resource_level"].lower() == "individual"
        ):
            type = "threat-actor-individual"
        else:
            type = "threat-actor-group"

        if type == "threat-actor-individual":
            return self.threat_actor_individual.import_from_stix2(**kwargs)
        else:
            return self.threat_actor_group.import_from_stix2(**kwargs)
