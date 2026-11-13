# coding: utf-8

import json

from pycti.utils.opencti_procedure_utils import MITRE_ATTACK_KILL_CHAIN
from pycti.utils.opencti_stix2_utils import build_custom_field_values_input

# Relationship type stored by the platform -> procedure property exported from it
_RELATIONSHIP_EXPORT_PROPERTIES = (
    ("implements-technique", "x_technique_refs"),
    ("exploits", "x_vulnerability_refs"),
)

_RELATIONSHIP_TARGET_PROPERTIES = """
    id
    to {
        ... on BasicObject {
            id
        }
        ... on StixObject {
            standard_id
        }
    }
"""


class Procedure:
    """Main Procedure class for OpenCTI

    Manages procedures (STIX ``x-opencti-procedure``) in the OpenCTI platform.
    A procedure id is a random ``x-opencti-procedure--<uuid4>``, never derived
    from its properties: two procedures with identical properties are two
    entities.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the Procedure instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            customFieldValues {
                field_id
                field_name
                int_value
                float_value
                string_value
                boolean_value
                date_value
                select_value
                select_values
            }
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
            creators {
                id
                name
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
                    }
                }
            }
            revoked
            confidence
            created
            modified
            name
            description
            x_procedure_type
            x_mitre_platforms
            first_observed
            last_observed
            x_execution_start
            x_execution_end
            x_fingerprint
            killChainPhases {
                id
                standard_id
                entity_type
                kill_chain_name
                phase_name
                x_opencti_order
                created
                modified
            }
            procedureObservables {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        observable_value
                    }
                }
            }
            procedureCommand {
                id
                standard_id
                entity_type
                observable_value
            }
            procedureSources {
                id
                standard_id
                entity_type
                name
            }
        """

    @staticmethod
    def generate_id_from_data(data):
        """Return the STIX ID of a procedure.

        Procedure ids are never derived from properties, so the id of the
        data is returned as is.

        :param data: Dictionary containing the 'id' key
        :type data: dict
        :return: STIX ID of the procedure
        :rtype: str
        """
        return data["id"]

    def list(self, **kwargs):
        """List Procedure objects.

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
        :return: List of Procedure objects
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
            "Listing Procedures with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query Procedures($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: ProceduresOrdering, $orderMode: OrderingMode) {
                procedures(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        variables = {
            "filters": filters,
            "search": search,
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
        }
        result = self.opencti.query(query, variables)

        if get_all:
            final_data = self.opencti.process_multiple(result["data"]["procedures"])
            while result["data"]["procedures"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["procedures"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug("Listing Procedures", {"after": after})
                result = self.opencti.query(query, {**variables, "after": after})
                final_data = final_data + self.opencti.process_multiple(
                    result["data"]["procedures"]
                )
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["procedures"], with_pagination
            )

    def read(self, **kwargs):
        """Read a Procedure object.

        :param id: the id of the Procedure
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: Procedure object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Procedure", {"id": id})
            query = (
                """
                query Procedure($id: String!) {
                    procedure(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["procedure"])
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_procedure] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Procedure object.

        :param stix_id: (optional) the STIX ID, kept as the standard id
        :type stix_id: str
        :param name: the name of the Procedure (required)
        :type name: str
        :param description: (optional) description
        :type description: str
        :param x_procedure_type: (optional) procedure type (procedure_type_ov)
        :type x_procedure_type: str
        :param x_mitre_platforms: (optional) platforms (platforms_ov)
        :type x_mitre_platforms: list
        :param first_observed: (optional) first observed date
        :type first_observed: str
        :param last_observed: (optional) last observed date
        :type last_observed: str
        :param x_execution_start: (optional) execution start date
        :type x_execution_start: str
        :param x_execution_end: (optional) execution end date
        :type x_execution_end: str
        :param x_fingerprint: (optional) fingerprint, computed by the platform if missing
        :type x_fingerprint: str
        :param killChainPhases: (optional) kill chain phase IDs
        :type killChainPhases: list
        :param procedureObservables: (optional) observable IDs
        :type procedureObservables: list
        :param procedureCommand: (optional) process observable ID of the command
        :type procedureCommand: str
        :param procedureSources: (optional) identity IDs of the sources
        :type procedureSources: list
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param revoked: (optional) whether the procedure is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param x_opencti_stix_ids: (optional) additional STIX IDs
        :type x_opencti_stix_ids: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: str
        :param update: (optional) whether to update an existing procedure
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :param custom_field_values: (optional) list of custom field name/value inputs
        :type custom_field_values: list
        :return: Procedure object
        :rtype: dict or None
        """
        name = kwargs.get("name", None)
        if name is None:
            self.opencti.app_logger.error(
                "[opencti_procedure] Missing parameters: name"
            )
            return None

        custom_field_values = build_custom_field_values_input(
            kwargs.get("custom_field_values", None),
            kwargs.get("custom_properties", None),
            self.opencti.app_logger,
        )
        self.opencti.app_logger.info("Creating Procedure", {"name": name})
        query = """
            mutation ProcedureAdd($input: ProcedureAddInput!) {
                procedureAdd(input: $input) {
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
                    "stix_id": kwargs.get("stix_id", None),
                    "customFieldValues": custom_field_values,
                    "createdBy": kwargs.get("createdBy", None),
                    "objectMarking": kwargs.get("objectMarking", None),
                    "objectLabel": kwargs.get("objectLabel", None),
                    "objectOrganization": kwargs.get("objectOrganization", None),
                    "externalReferences": kwargs.get("externalReferences", None),
                    "revoked": kwargs.get("revoked", None),
                    "confidence": kwargs.get("confidence", None),
                    "lang": kwargs.get("lang", None),
                    "created": kwargs.get("created", None),
                    "modified": kwargs.get("modified", None),
                    "name": name,
                    "description": kwargs.get("description", None),
                    "x_procedure_type": kwargs.get("x_procedure_type", None),
                    "x_mitre_platforms": kwargs.get("x_mitre_platforms", None),
                    "first_observed": kwargs.get("first_observed", None),
                    "last_observed": kwargs.get("last_observed", None),
                    "x_execution_start": kwargs.get("x_execution_start", None),
                    "x_execution_end": kwargs.get("x_execution_end", None),
                    "x_fingerprint": kwargs.get("x_fingerprint", None),
                    "killChainPhases": kwargs.get("killChainPhases", None),
                    "procedureObservables": kwargs.get("procedureObservables", None),
                    "procedureCommand": kwargs.get("procedureCommand", None),
                    "procedureSources": kwargs.get("procedureSources", None),
                    "x_opencti_stix_ids": kwargs.get("x_opencti_stix_ids", None),
                    "x_opencti_workflow_id": kwargs.get("x_opencti_workflow_id", None),
                    "x_opencti_modified_at": kwargs.get("x_opencti_modified_at", None),
                    "update": kwargs.get("update", False),
                    "files": kwargs.get("files", None),
                    "filesMarkings": kwargs.get("filesMarkings", None),
                    "noTriggerImport": kwargs.get("noTriggerImport", None),
                    "embedded": kwargs.get("embedded", None),
                    "upsertOperations": kwargs.get("upsert_operations", None),
                }
            },
        )
        return self.opencti.process_multiple_fields(result["data"]["procedureAdd"])

    def import_from_stix2(self, **kwargs):
        """Import a Procedure from a STIX2 ``x-opencti-procedure`` object.

        The bundle is expected to be normalized first (see
        :py:func:`~pycti.utils.opencti_procedure_utils.normalize_procedure_bundle`):
        techniques, vulnerabilities, tactics and report sources are then
        relationships, kill chain phases and report containment, not
        properties of the procedure.

        :param stixObject: the STIX2 Procedure object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Procedure object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is None:
            self.opencti.app_logger.error(
                "[opencti_procedure] Missing parameters: stixObject"
            )
            return None

        # Search in extensions
        extension_attributes = {
            "x_opencti_stix_ids": "stix_ids",
            "x_opencti_granted_refs": "granted_refs",
            "x_opencti_workflow_id": "workflow_id",
            "x_opencti_modified_at": "modified_at",
            "opencti_upsert_operations": "opencti_upsert_operations",
        }
        for key, extension_key in extension_attributes.items():
            if key not in stix_object:
                stix_object[key] = self.opencti.get_attribute_in_extension(
                    extension_key, stix_object
                )

        return self.create(
            custom_field_values=extras.get("custom_field_values", None),
            stix_id=stix_object["id"],
            name=stix_object["name"],
            description=(
                self.opencti.stix2.convert_markdown(stix_object["description"])
                if "description" in stix_object
                else None
            ),
            x_procedure_type=stix_object.get("x_procedure_type", None),
            x_mitre_platforms=stix_object.get("platforms", None),
            first_observed=stix_object.get("first_observed", None),
            last_observed=stix_object.get("last_observed", None),
            x_execution_start=stix_object.get("x_execution_start", None),
            x_execution_end=stix_object.get("x_execution_end", None),
            x_fingerprint=stix_object.get("x_fingerprint", None),
            killChainPhases=extras.get("kill_chain_phases_ids", None),
            procedureObservables=stix_object.get("x_observable_refs", None),
            procedureCommand=stix_object.get("x_command_ref", None),
            procedureSources=stix_object.get("x_source_refs", None),
            createdBy=extras.get("created_by_id", None),
            objectMarking=extras.get("object_marking_ids", None),
            objectLabel=extras.get("object_label_ids", None),
            objectOrganization=stix_object.get("x_opencti_granted_refs", None),
            externalReferences=extras.get("external_references_ids", None),
            revoked=stix_object.get("revoked", None),
            confidence=stix_object.get("confidence", None),
            lang=stix_object.get("lang", None),
            created=stix_object.get("created", None),
            modified=stix_object.get("modified", None),
            x_opencti_stix_ids=stix_object.get("x_opencti_stix_ids", None),
            x_opencti_workflow_id=stix_object.get("x_opencti_workflow_id", None),
            x_opencti_modified_at=stix_object.get("x_opencti_modified_at", None),
            update=update,
            files=extras.get("files"),
            filesMarkings=extras.get("filesMarkings"),
            noTriggerImport=extras.get("noTriggerImport", None),
            embedded=extras.get("embedded", None),
            upsert_operations=stix_object.get("opencti_upsert_operations", None),
        )

    def _list_relationship_target_ids(
        self, entity_id, relationship_type, access_filter=None
    ):
        """Standard ids of the targets of the relationships of a procedure.

        Targets the user cannot read are skipped. Order is kept, duplicates removed.
        """
        relationships = self.opencti.stix_core_relationship.list(
            fromId=entity_id,
            relationship_type=relationship_type,
            filters=access_filter,
            customAttributes=_RELATIONSHIP_TARGET_PROPERTIES,
            getAll=True,
        )
        target_ids = []
        for relationship in relationships:
            target_id = (relationship.get("to") or {}).get("standard_id")
            if target_id is not None and target_id not in target_ids:
                target_ids.append(target_id)
        return target_ids

    def _list_report_ids(self, entity_id, access_filter=None):
        """Standard ids of the reports that contain a procedure."""
        contains_procedure = {
            "mode": "and",
            "filters": [{"key": "objects", "values": [entity_id]}],
            "filterGroups": [],
        }
        if access_filter is not None:
            contains_procedure = {
                "mode": "and",
                "filters": [],
                "filterGroups": [contains_procedure, access_filter],
            }
        reports = self.opencti.report.list(
            filters=contains_procedure,
            customAttributes="id standard_id",
            getAll=True,
        )
        return [report["standard_id"] for report in reports]

    def to_stix_export(self, entity_id, access_filter=None):
        """Export a procedure with the links the platform stores once.

        The platform ``toStix`` output has no technique, vulnerability, tactic
        or report property: they are ``implements-technique`` and ``exploits``
        relationships, ``mitre-attack`` kill chain phases and report
        containment. They are expanded here into ``x_technique_refs``,
        ``x_vulnerability_refs``, ``tactics`` and report entries of
        ``x_source_refs``. Kill chain phases of other chains stay in
        ``kill_chain_phases`` only. An empty expansion is not exported.

        :param entity_id: the internal id of the Procedure
        :type entity_id: str
        :param access_filter: (optional) export access filter, applied to the
            relationship and report lookups so that restricted objects are not
            referenced
        :type access_filter: dict
        :return: STIX ``x-opencti-procedure`` object
        :rtype: dict
        :raises ValueError: if the platform returns no payload
        """
        stix = self.opencti.stix_core_object.to_stix(id=entity_id)
        if stix is None:
            raise ValueError(
                f"Backend STIX conversion returned no payload for Procedure {entity_id!r}"
            )
        for relationship_type, stix_property in _RELATIONSHIP_EXPORT_PROPERTIES:
            target_ids = self._list_relationship_target_ids(
                entity_id, relationship_type, access_filter
            )
            if len(target_ids) > 0:
                stix[stix_property] = target_ids
        tactics = []
        for phase in stix.get("kill_chain_phases") or []:
            if (
                phase.get("kill_chain_name") == MITRE_ATTACK_KILL_CHAIN
                and phase.get("phase_name") is not None
                and phase["phase_name"] not in tactics
            ):
                tactics.append(phase["phase_name"])
        if len(tactics) > 0:
            stix["tactics"] = tactics
        source_refs = list(stix.get("x_source_refs") or [])
        for report_id in self._list_report_ids(entity_id, access_filter):
            if report_id not in source_refs:
                source_refs.append(report_id)
        if len(source_refs) > 0:
            stix["x_source_refs"] = source_refs
        return stix
