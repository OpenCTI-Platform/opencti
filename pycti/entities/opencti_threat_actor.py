# coding: utf-8

import json

from typing import Union


class ThreatActor:
    """Main ThreatActor class for OpenCTI

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    """

    def __init__(self, opencti):
        """Create an instance of ThreatActor
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
            threat_actor_types
            first_seen
            last_seen
            roles
            goals
            sophistication
            resource_level
            primary_motivation
            secondary_motivations      
            personal_motivations
        """

    def list(self, **kwargs) -> dict:
        """List Threat-Actor objects

        The list method accepts the following \**kwargs:

        :param list filters: (optional) the filters to apply
        :param str search: (optional) a search keyword to apply for the listing
        :param int first: (optional) return the first n rows from the `after` ID
                            or the beginning if not set
        :param str after: (optional) OpenCTI object ID of the first row for pagination
        :param str orderBy: (optional) the field to order the response on
        :param bool orderMode: (optional) either "`asc`" or "`desc`"
        :param bool getAll: (optional) switch to return all entries (be careful to use this without any other filters)
        :param bool withPagination: (optional) switch to use pagination
        """

        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info", "Listing Threat-Actors with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query ThreatActors($filters: [ThreatActorsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ThreatActorsOrdering, $orderMode: OrderingMode) {
                threatActors(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + self.properties
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
            result["data"]["threatActors"], with_pagination
        )

    def read(self, **kwargs) -> Union[dict, None]:
        """Read a Threat-Actor object

        read can be either used with a known OpenCTI entity `id` or by using a
        valid filter to search and return a single Threat-Actor entity or None.

        The list method accepts the following \**kwargs.

        Note: either `id` or `filters` is required.

        :param str id: the id of the Threat-Actor
        :param list filters: the filters to apply if no id provided
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Threat-Actor {" + id + "}.")
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
            self.opencti.log(
                "error", "[opencti_threat_actor] Missing parameters: id or filters"
            )
            return None

    def _create_raw(self, **kwargs):
        """Create a Threat-Actor object
        """

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
        threat_actor_types = kwargs.get("threat_actor_types", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        roles = kwargs.get("roles", None)
        goals = kwargs.get("goals", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)
        personal_motivations = kwargs.get("personal_motivations", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Threat-Actor {" + name + "}.")
            query = """
                mutation ThreatActorAdd($input: ThreatActorAddInput) {
                    threatActorAdd(input: $input) {
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
                        "threat_actor_types": threat_actor_types,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "roles": roles,
                        "goals": goals,
                        "sophistication": sophistication,
                        "resource_level": resource_level,
                        "primary_motivation": primary_motivation,
                        "secondary_motivations": secondary_motivations,
                        "personal_motivations": personal_motivations,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["threatActorAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_threat_actor] Missing parameters: name and description",
            )

    def create(self, **kwargs):
        """Create a Threat-Actor object

        The Threat-Actor entity will only be created if it doesn't exists
        By setting `update` to `True` it acts like an upsert and updates
        fields of an existing Threat-Actor entity.

        The create method accepts the following \**kwargs.

        Note: `name` and `description` or `stix_id` is required.

        :param str stix_id: stix2 id reference for the Threat-Actor entity
        :param str createdBy: (optional) id of the organization that created the knowledge
        :param list objectMarking: (optional) list of OpenCTI markin definition ids
        :param list objectLabel: (optional) list of OpenCTI label ids
        :param list externalReferences: (optional) list of OpenCTI external references ids
        :param bool revoked: is this entity revoked
        :param int confidence: confidence level
        :param str lang: language
        :param str created: (optional) date in OpenCTI date format
        :param str modified: (optional) date in OpenCTI date format
        :param str name: name of the threat actor
        :param str description: description of the threat actor
        :param list aliases: (optional) list of alias names for the Threat-Actor
        :param list threat_actor_types: (optional) list of threat actor types
        :param str first_seen: (optional) date in OpenCTI date format
        :param str last_seen: (optional) date in OpenCTI date format
        :param list roles: (optional) list of roles
        :param list goals: (optional) list of goals
        :param str sophistication: (optional) describe the actors sophistication in text
        :param str resource_level: (optional) describe the actors resource_level in text
        :param str primary_motivation: (optional) describe the actors primary_motivation in text
        :param list secondary_motivations: (optional) describe the actors secondary_motivations in list of string
        :param list personal_motivations: (optional) describe the actors personal_motivations in list of strings
        :param bool update: (optional) choose to updated an existing Threat-Actor entity, default `False`
        """

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
        threat_actor_types = kwargs.get("threat_actor_types", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        roles = kwargs.get("roles", None)
        goals = kwargs.get("goals", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)
        personal_motivations = kwargs.get("personal_motivations", None)
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
            ... on ThreatActor {
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
                personal_motivations
            }
        """
        object_result = self.opencti.stix_domain_object.get_by_stix_id_or_name(
            types=["Threat-Actor"],
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
                # sophistication
                if (
                    self.opencti.not_empty(sophistication)
                    and object_result["sophistication"] != sophistication
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="sophistication",
                        value=sophistication,
                    )
                    object_result["sophistication"] = sophistication
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
                # personal_motivations
                if (
                    self.opencti.not_empty(personal_motivations)
                    and object_result["personal_motivations"] != personal_motivations
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="personal_motivations",
                        value=personal_motivations,
                    )
                    object_result["personal_motivations"] = personal_motivations
            return object_result
        else:
            return self._create_raw(
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
                threat_actor_types=threat_actor_types,
                first_seen=first_seen,
                last_seen=last_seen,
                roles=roles,
                goals=goals,
                sophistication=sophistication,
                resource_level=resource_level,
                primary_motivation=primary_motivation,
                secondary_motivations=secondary_motivations,
                personal_motivations=personal_motivations,
            )

    """
        Import an Threat-Actor object from a STIX2 object

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
                threat_actor_types=stix_object["threat_actor_types"]
                if "threat_actor_types" in stix_object
                else None,
                first_seen=stix_object["first_seen"]
                if "first_seen" in stix_object
                else None,
                last_seen=stix_object["last_seen"]
                if "last_seen" in stix_object
                else None,
                roles=stix_object["roles"] if "roles" in stix_object else None,
                goals=stix_object["goals"] if "goals" in stix_object else None,
                sophistication=stix_object["sophistication"]
                if "sophistication" in stix_object
                else None,
                resource_level=stix_object["resource_level"]
                if "resource_level" in stix_object
                else None,
                primary_motivation=stix_object["primary_motivation"]
                if "primary_motivation" in stix_object
                else None,
                secondary_motivations=stix_object["secondary_motivations"]
                if "secondary_motivations" in stix_object
                else None,
                personal_motivations=stix_object["personal_motivations"]
                if "personal_motivations" in stix_object
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )
