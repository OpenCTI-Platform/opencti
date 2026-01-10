# coding: utf-8

import json

from pycti.utils.opencti_stix2_identifier import kill_chain_phase_generate_id


class KillChainPhase:
    """Main KillChainPhase class for OpenCTI

    Manages kill chain phases (ATT&CK tactics) in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the KillChainPhase instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            kill_chain_name
            phase_name
            x_opencti_order
            created
            modified
            created_at
            updated_at
        """

    @staticmethod
    def generate_id(phase_name, kill_chain_name):
        """Generate a STIX ID for a Kill Chain Phase.

        :param phase_name: The phase name
        :type phase_name: str
        :param kill_chain_name: The kill chain name
        :type kill_chain_name: str
        :return: STIX ID for the kill chain phase
        :rtype: str
        """
        return kill_chain_phase_generate_id(
            phase_name=phase_name, kill_chain_name=kill_chain_name
        )

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from kill chain phase data.

        :param data: Dictionary containing 'phase_name' and 'kill_chain_name' keys
        :type data: dict
        :return: STIX ID for the kill chain phase
        :rtype: str
        """
        return KillChainPhase.generate_id(data["phase_name"], data["kill_chain_name"])

    def list(self, **kwargs):
        """List Kill-Chain-Phase objects.

        :param filters: the filters to apply
        :type filters: dict
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
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :return: List of Kill-Chain-Phase objects
        :rtype: list
        """
        filters = kwargs.get("filters", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.app_logger.info(
            "Listing Kill-Chain-Phase with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query KillChainPhases($filters: FilterGroup, $first: Int, $after: ID, $orderBy: KillChainPhasesOrdering, $orderMode: OrderingMode) {
                killChainPhases(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["killChainPhases"], with_pagination
        )

    def read(self, **kwargs):
        """Read a Kill-Chain-Phase object.

        :param id: the id of the Kill-Chain-Phase
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :return: Kill-Chain-Phase object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Kill-Chain-Phase", {"id": id})
            query = (
                """
                query KillChainPhase($id: String!) {
                    killChainPhase(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["killChainPhase"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_kill_chain_phase] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Kill-Chain-Phase object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param created: (optional) creation date
        :type created: datetime
        :param modified: (optional) modification date
        :type modified: datetime
        :param kill_chain_name: the kill chain name (required)
        :type kill_chain_name: str
        :param phase_name: the phase name (required)
        :type phase_name: str
        :param x_opencti_order: (optional) order (default: 0)
        :type x_opencti_order: int
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :return: Kill-Chain-Phase object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        kill_chain_name = kwargs.get("kill_chain_name", None)
        phase_name = kwargs.get("phase_name", None)
        x_opencti_order = kwargs.get("x_opencti_order", 0)
        update = kwargs.get("update", False)

        if kill_chain_name is not None and phase_name is not None:
            self.opencti.app_logger.info(
                "Creating Kill-Chain-Phase", {"name": phase_name}
            )
            query = (
                """
                mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) {
                    killChainPhaseAdd(input: $input) {
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
                        "created": created,
                        "modified": modified,
                        "kill_chain_name": kill_chain_name,
                        "phase_name": phase_name,
                        "x_opencti_order": x_opencti_order,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["killChainPhaseAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_kill_chain_phase] Missing parameters: kill_chain_name and phase_name",
            )
            return None

    def update_field(self, **kwargs):
        """Update a Kill Chain Phase object field.

        :param id: the Kill Chain Phase id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: The updated Kill Chain Phase object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Kill chain", {"id": id})
            query = """
                    mutation KillChainPhaseEdit($id: ID!, $input: [EditInput]!) {
                        killChainPhaseEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
                                standard_id
                                entity_type
                            }
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
                result["data"]["killChainPhaseEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_kill_chain] Missing parameters: id and key and value"
            )
            return None

    def delete(self, **kwargs):
        """Delete a Kill-Chain-Phase object.

        :param id: the id of the Kill-Chain-Phase to delete
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Kill-Chain-Phase", {"id": id})
            query = """
                 mutation KillChainPhaseEdit($id: ID!) {
                     killChainPhaseEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_kill_chain_phase] Missing parameters: id"
            )
            return None
