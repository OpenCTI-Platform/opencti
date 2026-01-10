# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class Location:
    """Main Location class for OpenCTI

    Manages geographic locations (countries, cities, regions) in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the Location instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            status {
                id
                template {
                  id
                  name
                  color
                }
            }
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
            objectOrganization {
                id
                standard_id
                name
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
                    }
                }
            }
            revoked
            confidence
            created
            modified
            name
            description
            latitude
            longitude
            precision
            x_opencti_aliases
        """
        self.properties_with_files = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            status {
                id
                template {
                  id
                  name
                  color
                }
            }
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
            objectOrganization {
                id
                standard_id
                name
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
            latitude
            longitude
            precision
            x_opencti_aliases
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
    def generate_id(name, x_opencti_location_type, latitude=None, longitude=None):
        """Generate a STIX ID for a Location.

        :param name: The name of the location
        :type name: str
        :param x_opencti_location_type: The type of location (Country, City, Region, Position)
        :type x_opencti_location_type: str
        :param latitude: Optional latitude coordinate
        :type latitude: float or None
        :param longitude: Optional longitude coordinate
        :type longitude: float or None
        :return: STIX ID for the location
        :rtype: str
        """
        if x_opencti_location_type == "Position":
            if latitude is not None and longitude is None:
                data = {"latitude": latitude}
            elif latitude is None and longitude is not None:
                data = {"longitude": longitude}
            elif latitude is not None and longitude is not None:
                data = {"latitude": latitude, "longitude": longitude}
            else:
                data = {"name": name.lower().strip()}
        else:
            data = {
                "name": name.lower().strip(),
                "x_opencti_location_type": x_opencti_location_type,
            }
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "location--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from location data.

        :param data: Dictionary containing 'name', 'x_opencti_location_type', and optionally 'latitude'/'longitude'
        :type data: dict
        :return: STIX ID for the location
        :rtype: str
        """
        return Location.generate_id(
            data.get("name"),
            data.get("x_opencti_location_type"),
            data.get("latitude"),
            data.get("longitude"),
        )

    def list(self, **kwargs):
        """List Location objects.

        :param types: the list of location types to filter by
        :type types: list
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
        :type customAttributes: list
        :param getAll: whether to retrieve all results
        :type getAll: bool
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: List of Location objects
        :rtype: list
        """
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)

        self.opencti.app_logger.info(
            "Listing Locations with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query Locations($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: LocationsOrdering, $orderMode: OrderingMode) {
                locations(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
            )
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
                "types": types,
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
            data = self.opencti.process_multiple(result["data"]["locations"])
            final_data = final_data + data
            while result["data"]["locations"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["locations"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug("Listing Locations", {"after": after})
                result = self.opencti.query(
                    query,
                    {
                        "types": types,
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["locations"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["locations"], with_pagination
            )

    def read(self, **kwargs):
        """Read a Location object.

        :param id: the id of the Location
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: list
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: Location object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Location", {"id": id})
            query = (
                """
                query Location($id: String!) {
                    location(id: $id) {
                        """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["location"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_location] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Location object.

        :param type: the type of location (Country, City, Region, Position)
        :type type: str
        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param revoked: (optional) whether the location is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: datetime
        :param modified: (optional) modification date
        :type modified: datetime
        :param name: the name of the Location (required)
        :type name: str
        :param description: (optional) description
        :type description: str
        :param latitude: (optional) latitude coordinate
        :type latitude: float
        :param longitude: (optional) longitude coordinate
        :type longitude: float
        :param precision: (optional) precision in meters
        :type precision: float
        :param x_opencti_aliases: (optional) list of aliases
        :type x_opencti_aliases: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: datetime
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Location object
        :rtype: dict or None
        """
        type = kwargs.get("type", None)
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        latitude = kwargs.get("latitude", None)
        longitude = kwargs.get("longitude", None)
        precision = kwargs.get("precision", None)
        x_opencti_aliases = kwargs.get("x_opencti_aliases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Location", {"name": name})
            query = """
                mutation LocationAdd($input: LocationAddInput!) {
                    locationAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "type": type,
                        "stix_id": stix_id,
                        "createdBy": created_by,
                        "objectMarking": object_marking,
                        "objectLabel": object_label,
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "name": name,
                        "description": description,
                        "latitude": latitude,
                        "longitude": longitude,
                        "precision": precision,
                        "x_opencti_aliases": x_opencti_aliases,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                        "files": files,
                        "filesMarkings": files_markings,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["locationAdd"])
        else:
            self.opencti.app_logger.error("[opencti_location] Missing parameters: name")
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Location object from a STIX2 object.

        :param stixObject: the Stix-Object Location
        :type stixObject: dict
        :param extras: extra dict
        :type extras: dict
        :param update: set the update flag on import
        :type update: bool
        :return: Location object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if "name" in stix_object:
            name = stix_object["name"]
        elif "city" in stix_object:
            name = stix_object["city"]
        elif "country" in stix_object:
            name = stix_object["country"]
        elif "region" in stix_object:
            name = stix_object["region"]
        else:
            self.opencti.app_logger.error("[opencti_location] Missing name")
            return None
        if "x_opencti_location_type" in stix_object:
            type = stix_object["x_opencti_location_type"]
        elif self.opencti.get_attribute_in_extension("type", stix_object) is not None:
            type = self.opencti.get_attribute_in_extension("type", stix_object)
        else:
            if "city" in stix_object:
                type = "City"
            elif "country" in stix_object:
                type = "Country"
            elif "region" in stix_object:
                type = "Region"
            else:
                type = "Position"
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_aliases" not in stix_object:
                stix_object["x_opencti_aliases"] = (
                    self.opencti.get_attribute_in_extension("aliases", stix_object)
                )
            if "x_opencti_stix_ids" not in stix_object:
                stix_object["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_object)
                )
            if "x_opencti_workflow_id" not in stix_object:
                stix_object["x_opencti_workflow_id"] = (
                    self.opencti.get_attribute_in_extension("workflow_id", stix_object)
                )
            if "x_opencti_modified_at" not in stix_object:
                stix_object["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension("modified_at", stix_object)
                )

            return self.create(
                type=type,
                stix_id=stix_object["id"],
                createdBy=(
                    extras["created_by_id"] if "created_by_id" in extras else None
                ),
                objectMarking=(
                    extras["object_marking_ids"]
                    if "object_marking_ids" in extras
                    else None
                ),
                objectLabel=(
                    extras["object_label_ids"] if "object_label_ids" in extras else None
                ),
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
                ),
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                name=name,
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
                latitude=stix_object["latitude"] if "latitude" in stix_object else None,
                longitude=(
                    stix_object["longitude"] if "longitude" in stix_object else None
                ),
                precision=(
                    stix_object["precision"] if "precision" in stix_object else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                x_opencti_aliases=self.opencti.stix2.pick_aliases(stix_object),
                x_opencti_workflow_id=(
                    stix_object["x_opencti_workflow_id"]
                    if "x_opencti_workflow_id" in stix_object
                    else None
                ),
                x_opencti_modified_at=(
                    stix_object["x_opencti_modified_at"]
                    if "x_opencti_modified_at" in stix_object
                    else None
                ),
                update=update,
                files=extras.get("files"),
                filesMarkings=extras.get("filesMarkings"),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_location] Missing parameters: stixObject"
            )
            return None
