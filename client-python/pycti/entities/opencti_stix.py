class Stix:
    """Main Stix class for OpenCTI

    Provides generic STIX object operations in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        self.opencti = opencti

    def delete(self, **kwargs):
        """Delete a Stix element.

        :param id: the Stix element id
        :type id: str
        :param force_delete: force deletion (default: True)
        :type force_delete: bool
        :return: None
        """
        id = kwargs.get("id", None)
        force_delete = kwargs.get("force_delete", True)
        if id is not None:
            self.opencti.app_logger.info("Deleting Stix element", {"id": id})
            query = """
                 mutation StixEdit($id: ID!, $forceDelete: Boolean) {
                     stixEdit(id: $id) {
                         delete(forceDelete: $forceDelete)
                     }
                 }
             """
            self.opencti.query(query, {"id": id, "forceDelete": force_delete})
        else:
            self.opencti.app_logger.error("[opencti_stix] Missing parameters: id")
            return None

    def merge(self, **kwargs):
        """Merge STIX objects into one.

        :param id: the target Stix-Object id
        :type id: str
        :param object_ids: list of source STIX object IDs to merge into target
        :type object_ids: list
        :return: The merged Stix-Object object
        :rtype: dict or None
        """
        id = kwargs.get("id")
        stix_objects_ids = kwargs.get("object_ids")
        if id is not None and stix_objects_ids is not None:
            self.opencti.app_logger.info(
                "Merging Stix object", {"id": id, "sources": ",".join(stix_objects_ids)}
            )
            query = """
                        mutation StixEdit($id: ID!, $stixObjectsIds: [String]!) {
                            stixEdit(id: $id) {
                                merge(stixObjectsIds: $stixObjectsIds) {
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
                    "stixObjectsIds": stix_objects_ids,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixEdit"]["merge"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix] Missing parameters: id and object_ids"
            )
            return None
