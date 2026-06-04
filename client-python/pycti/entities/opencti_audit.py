from typing import Dict, List, Optional


class Audit:
    """Main Audit class for OpenCTI

    Reads audits in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the Audit instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """

        """

        self.properties = """
            id
            entity_type
            event_scope
            event_status
            timestamp
            user_id
            raw_data
            context_uri
            user_metadata
        """

    def list(self, **kwargs) -> List[Dict]:
        """List Audit objects.

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
        :return: List of Task objects
        :rtype: list
        """
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", "timestamp")
        order_mode = kwargs.get("orderMode", "asc")
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        if get_all:
            first = 100

        self.opencti.admin_logger.info(
            "Fetching audit with filters", {"filters": filters}
        )
        query = (
            """
            query AuditList($first: Int, $after: ID, $orderBy: LogsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
                audits(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
                    edges {
                        node {
                    """
            + (self.properties if custom_attributes is None else custom_attributes)
            + """
                        }
                    }

                    pageInfo {
                        startCursor, endCursor, hasNextPage, hasPreviousPage
                        globalCount
                    }
                }
            }
            """
        )
        result = self.opencti.query(
            query,
            {
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
                "filters": filters,
                "search": search,
            },
        )

        if get_all:
            self.opencti.admin_logger.info("Getting all data.")
            final_data = []
            data = self.opencti.process_multiple(result["data"]["audits"])
            final_data = final_data + data
            page = 1
            while result["data"]["audits"]["pageInfo"]["hasNextPage"]:
                self.opencti.admin_logger.info("Getting next page of data: " + str(page))
                after = result["data"]["audits"]["pageInfo"]["endCursor"]
                result = self.opencti.query(
                    query,
                    {
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                        "filters": filters,
                        "search": search,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["audits"])
                final_data = final_data + data
                page = page + 1
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["audits"], with_pagination
            )

    def read(self, **kwargs) -> Optional[Dict]:
        """Reads audit details from the platform.

        :param id: ID of the audit to fetch
        :type id: str, optional
        :param customAttributes: Custom attributes to include instead of the
            defaults
        :type customAttribues: str, optional
        :param filters: Filters to apply to find a single user
        :type filters: dict, optional
        :param search: Search term to use to find a single user
        :type search: str, optional
        :return: Representation of the audit as a Python dictionary.
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        custom_attributes = kwargs.get("customAttributes", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        if id is not None:
            self.opencti.admin_logger.info("Fetching audit with ID", {"id": id})
            query = (
                """
                query AuditRead($id: String!) {
                    audit(id: $id) {
                        """
                + (self.properties if custom_attributes is None else custom_attributes)
                + """
                    }
                }
                """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["audit"])
        elif filters is not None or search is not None:
            results = self.list(
                filters=filters,
                search=search,
                customAttributes=custom_attributes,
            )
            return results[0] if results else None
        else:
            self.opencti.admin_logger.error(
                "[opencti_audit] Missing parameters: id, search, or filters"
            )
            return None