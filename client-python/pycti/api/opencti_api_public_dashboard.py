class OpenCTIApiPublicDashboard:
    """OpenCTI Public Dashboard API class.

    Manages public dashboard operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        """Delete a public dashboard.

        :param id: the public dashboard id
        :type id: str
        :return: None
        """
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
            self.api.app_logger.error(
                "[opencti_public_dashboard] Cannot delete public dashboard, missing parameters: id"
            )
            return None
