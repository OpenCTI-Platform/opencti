class OpenCTIApiPublicDashboard:
    """OpenCTIApiPublicDashboard"""

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            query = """
                mutation PublicDashboardDelete($id: ID!) {
                    publicDashboardDelete(id: $id)
                }
               """
            self.api.query(
                query,
                {
                    "id": id,
                },
            )
        else:
            self.opencti.app_logger.error(
                "[stix_public_dashboard] Cant delete public dashboard, missing parameters: id"
            )
            return None
