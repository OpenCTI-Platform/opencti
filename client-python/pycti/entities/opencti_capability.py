from typing import Dict, List


class Capability:
    """Represents a role capability on the OpenCTI platform

    See the properties attribute to understand which properties are fetched by
    default from the graphql queries.
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            name
            description
            attribute_order
            created_at
            updated_at
        """

    def list(self, **kwargs) -> List[Dict]:
        """Lists all capabilities available on the platform

        :param customAttributes: Custom attributes to retrieve from the GraphQL
            query.
        :type customAttributes: str, optional
        :return: List of capabilities
        :rtype: List[Dict]
        """
        custom_attributes = kwargs.get("customAttributes")
        self.opencti.admin_logger.info("Listing capabilities")
        query = (
            """
            query CapabilityList {
                capabilities {
                    edges {
                        node {
                            """
            + (self.properties if custom_attributes is None else custom_attributes)
            + """
                        }
                    }
                }
            }
            """
        )
        result = self.opencti.query(query)
        return self.opencti.process_multiple(result["data"]["capabilities"])
