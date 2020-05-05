# coding: utf-8

import json


class KillChainPhase:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            entity_type
            stix_id_key
            kill_chain_name
            phase_name
            phase_order
            created
            modified
            created_at
            updated_at
        """

    """
        List Kill-Chain-Phase objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Kill-Chain-Phase objects
    """

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info", "Listing Kill-Chain-Phase with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query KillChainPhases($filters: [KillChainPhasesFiltering], $first: Int, $after: ID, $orderBy: KillChainPhasesOrdering, $orderMode: OrderingMode) {
                killChainPhases(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["killChainPhases"], with_pagination
        )

    """
        Read a Kill-Chain-Phase object

        :param id: the id of the Kill-Chain-Phase
        :param filters: the filters to apply if no id provided
        :return Kill-Chain-Phase object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading Kill-Chain-Phase {" + id + "}.")
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
            self.opencti.log(
                "error", "[opencti_kill_chain_phase] Missing parameters: id or filters"
            )
            return None

    """
        Create a Kill-Chain-Phase object

        :param name: the name of the Kill-Chain-Phase
        :return Kill-Chain-Phase object
    """

    def create_raw(self, **kwargs):
        kill_chain_name = kwargs.get("kill_chain_name", None)
        phase_name = kwargs.get("phase_name", None)
        phase_order = kwargs.get("phase_order", 0)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

        if kill_chain_name is not None and phase_name is not None:
            self.opencti.log("info", "Creating Kill-Chain-Phase {" + phase_name + "}.")
            query = (
                """
                mutation KillChainPhaseAdd($input: KillChainPhaseAddInput) {
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
                        "kill_chain_name": kill_chain_name,
                        "phase_name": phase_name,
                        "phase_order": phase_order,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["killChainPhaseAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_kill_chain_phase] Missing parameters: kill_chain_name and phase_name",
            )

    """
        Create a Kill-Chain-Phase object only if it not exists, update it on request

        :param name: the name of the Kill-Chain-Phase
        :return Kill-Chain-Phase object
    """

    def create(self, **kwargs):
        kill_chain_name = kwargs.get("kill_chain_name", None)
        phase_name = kwargs.get("phase_name", None)
        phase_order = kwargs.get("phase_order", 0)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

        kill_chain_phase_result = self.read(
            filters=[{"key": "phase_name", "values": [phase_name]}]
        )
        if kill_chain_phase_result is not None:
            return kill_chain_phase_result
        else:
            return self.create_raw(
                kill_chain_name=kill_chain_name,
                phase_name=phase_name,
                phase_order=phase_order,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
            )
