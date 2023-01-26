# coding: utf-8

from pycti.entities import LOGGER


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
            LOGGER.info("Deleting Stix element {%s}.", id)
            query = """
                 mutation StixEdit($id: ID!) {
                     stixEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            LOGGER.error("[opencti_stix] Missing parameters: id")
            return None

    """
            Merge a Stix-Object object field
    
            :param id: the Stix-Object id
            :param key: the key of the field
            :param value: the value of the field
            :return The updated Stix-Object object
        """

    def merge(self, **kwargs):
        id = kwargs.get("id", None)
        stix_objects_ids = kwargs.get("object_ids", None)
        if id is not None and stix_objects_ids is not None:
            self.opencti.log(
                "info",
                "Merging Stix object {"
                + id
                + "} with {"
                + ",".join(stix_objects_ids)
                + "}.",
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
            self.opencti.log(
                "error",
                "[opencti_stix] Missing parameters: id and object_ids",
            )
            return None
