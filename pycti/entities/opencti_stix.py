class Stix:
    def __init__(self, opencti):
        self.opencti = opencti

    """
        Delete a Stix element

        :param id: the Stix element id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Stix element", {"id": id})
            query = """
                 mutation StixEdit($id: ID!) {
                     stixEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error("[opencti_stix] Missing parameters: id")
            return None

    """
            Merge a Stix-Object object field
    
            :param id: the Stix-Object id
            :param key: the key of the field
            :param value: the value of the field
            :return The updated Stix-Object object
        """

    def merge(self, **kwargs):
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
