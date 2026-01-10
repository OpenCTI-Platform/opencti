class OpenCTIApiWorkspace:
    """OpenCTI Workspace API class.

    Manages workspace operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        """Delete a workspace.

        :param id: the workspace id
        :type id: str
        :return: None
        :rtype: None
        """
        workspace_id = kwargs.get("id", None)
        if workspace_id is None:
            self.api.admin_logger.error(
                "[opencti_workspace] Cannot delete workspace, missing parameter: id"
            )
            return None
        query = """
            mutation WorkspaceDelete($id: ID!) {
                workspaceDelete(id: $id)
            }
           """
        self.api.query(
            query,
            {
                "id": workspace_id,
            },
        )
