# coding: utf-8

import json


class IntrusionSet:
    def __init__(self, opencti):
        self.opencti = opencti
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
                    name
                    aliases
                    description
                    created
                    modified
                    objectLabel {
                        edges {
                            node {
                                id
                                value
                                color
                            }
                        }
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
                edges {
                    node {
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
                }
            }
            objectLabel {
                edges {
                    node {
                        id
                        value
                        color
                    }
                }
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
            aliases
            first_seen
            last_seen
            goals
            resource_level
            primary_motivation
            secondary_motivations      
        """

    """
        List Intrusion-Set objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Intrusion-Set objects
    """

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info", "Listing Intrusion-Sets with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query IntrusionSets($filters: [IntrusionSetsFiltering], $search: String, $first: Int, $after: ID, $orderBy: IntrusionSetsOrdering, $orderMode: OrderingMode) {
                intrusionSets(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(
            result["data"]["intrusionSets"], with_pagination
        )

    """
        Read a Intrusion-Set object
        
        :param id: the id of the Intrusion-Set
        :param filters: the filters to apply if no id provided
        :return Intrusion-Set object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Intrusion-Set {" + id + "}.")
            query = (
                """
                query IntrusionSet($id: String!) {
                    intrusionSet(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["intrusionSet"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_intrusion_set] Missing parameters: id or filters"
            )
            return None

    """
        Create a Intrusion-Set object

        :param name: the name of the Intrusion Set
        :return Intrusion-Set object
    """

    def create_raw(self, **kwargs):
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
        description = kwargs.get("description", "")
        aliases = kwargs.get("aliases", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        goals = kwargs.get("goals", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Intrusion-Set {" + name + "}.")
            query = """
                mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
                    intrusionSetAdd(input: $input) {
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
                        "aliases": aliases,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "goals": goals,
                        "resource_level": resource_level,
                        "primary_motivation": primary_motivation,
                        "secondary_motivations": secondary_motivations,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["intrusionSetAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_intrusion_set] Missing parameters: name and description",
            )

    """
        Create a Intrusion-Set object only if it not exists, update it on request

        :param name: the name of the Intrusion Set
        :return Intrusion-Set object
    """

    def create(self, **kwargs):
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
        description = kwargs.get("description", "")
        aliases = kwargs.get("aliases", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        goals = kwargs.get("goals", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            standard_id
            entity_type
            parent_types
            createdBy {
                ... on Identity {
                    id
                }
            }       
            ... on IntrusionSet {
                name
                description
                aliases    
                first_seen
                last_seen
                goals
                resource_level
                primary_motivation
                secondary_motivations
            }
        """
        object_result = self.opencti.stix_domain_object.get_by_stix_id_or_name(
            types=["Intrusion-Set"],
            stix_id=stix_id,
            name=name,
            customAttributes=custom_attributes,
        )
        if object_result is not None:
            if update or object_result["createdById"] == created_by:
                # name
                if object_result["name"] != name:
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="name", value=name
                    )
                    object_result["name"] = name
                # description
                if (
                    self.opencti.not_empty(description)
                    and object_result["description"] != description
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="description", value=description
                    )
                    object_result["description"] = description
                # aliases
                if (
                    self.opencti.not_empty(aliases)
                    and object_result["aliases"] != aliases
                ):
                    if "aliases" in object_result:
                        new_aliases = object_result["aliases"] + list(
                            set(aliases) - set(object_result["aliases"])
                        )
                    else:
                        new_aliases = aliases
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="aliases", value=new_aliases
                    )
                    object_result["aliases"] = new_aliases
                # first_seen
                if first_seen is not None and object_result["first_seen"] != first_seen:
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="first_seen", value=first_seen
                    )
                    object_result["first_seen"] = first_seen
                # last_seen
                if last_seen is not None and object_result["last_seen"] != last_seen:
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="last_seen", value=last_seen
                    )
                    object_result["last_seen"] = last_seen
                # goals
                if self.opencti.not_empty(goals) and object_result["goals"] != goals:
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="goals", value=goals
                    )
                    object_result["goals"] = goals
                # resource_level
                if (
                    self.opencti.not_empty(resource_level)
                    and object_result["resource_level"] != resource_level
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="resource_level",
                        value=resource_level,
                    )
                    object_result["resource_level"] = resource_level
                # primary_motivation
                if (
                    self.opencti.not_empty(primary_motivation)
                    and object_result["primary_motivation"] != primary_motivation
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="primary_motivation",
                        value=primary_motivation,
                    )
                    object_result["primary_motivation"] = primary_motivation
                # secondary_motivations
                if (
                    self.opencti.not_empty(secondary_motivations)
                    and object_result["secondary_motivations"] != secondary_motivations
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="secondary_motivations",
                        value=secondary_motivations,
                    )
                    object_result["secondary_motivations"] = secondary_motivations
            return object_result
        else:
            return self.create_raw(
                stix_id=stix_id,
                createdBy=created_by,
                objectMarking=object_marking,
                objectLabel=object_label,
                externalReferences=external_references,
                revoked=revoked,
                confidence=confidence,
                lang=lang,
                created=created,
                modified=modified,
                name=name,
                description=description,
                aliases=aliases,
                first_seen=first_seen,
                last_seen=last_seen,
                goals=goals,
                resource_level=resource_level,
                primary_motivation=primary_motivation,
                secondary_motivations=secondary_motivations,
            )

    """
        Import an Intrusion-Set object from a STIX2 object

        :param stixObject: the Stix-Object Intrusion-Set
        :return Intrusion-Set object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            return self.create(
                stix_id=stix_object["id"],
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else None,
                objectLabel=extras["object_label_ids"]
                if "object_label_ids" in extras
                else [],
                externalReferences=extras["external_references_ids"]
                if "external_references_ids" in extras
                else [],
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=stix_object["confidence"]
                if "confidence" in stix_object
                else None,
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                alias=self.opencti.stix2.pick_aliases(stix_object),
                first_seen=stix_object["first_seen"]
                if "first_seen" in stix_object
                else None,
                last_seen=stix_object["last_seen"]
                if "last_seen" in stix_object
                else None,
                goals=stix_object["goals"] if "goals" in stix_object else None,
                resource_level=stix_object["resource_level"]
                if "resource_level" in stix_object
                else None,
                primary_motivation=stix_object["primary_motivation"]
                if "primary_motivation" in stix_object
                else None,
                secondary_motivations=stix_object["secondary_motivations"]
                if "secondary_motivations" in stix_object
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )
