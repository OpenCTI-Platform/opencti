class OpenCTIApiPublicDashboard:
    """OpenCTI Public Dashboard API class.

    Manages public dashboard operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        """Initialize the OpenCTIApiPublicDashboard instance.

        :param api: OpenCTI API client instance
        :type api: OpenCTIApiClient
        """
        self.api = api

    def delete(self, **kwargs):
        """Delete a public dashboard.

        :param id: the public dashboard id
        :type id: str
        :return: None
        :rtype: None
        """
        dashboard_id = kwargs.get("id", None)
        if dashboard_id is not None:
            query = """
                mutation PublicDashboardDelete($id: ID!) {
                    publicDashboardDelete(id: $id)
                }
               """
            self.api.query(
                query,
                {
                    "id": dashboard_id,
                },
            )
        else:
            self.api.app_logger.error(
                "[opencti_public_dashboard] Cannot delete public dashboard, missing parameter: id"
            )
            return None
