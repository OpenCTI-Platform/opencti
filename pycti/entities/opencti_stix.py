# coding: utf-8


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
            self.opencti.log("info", "Deleting Stix element {" + id + "}.")
            query = """
                 mutation StixEdit($id: ID!) {
                     stixEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log("error", "[opencti_stix] Missing parameters: id")
            return None
