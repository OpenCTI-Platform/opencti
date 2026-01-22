class OpenCTIApiDraft:
    """OpenCTI Draft API class.

    Manages draft workspace operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        """Initialize the OpenCTIApiDraft instance.

        :param api: OpenCTI API client instance
        :type api: OpenCTIApiClient
        """
        self.api = api

    def delete(self, **kwargs):
        """Delete a draft workspace.

        :param id: the draft workspace id
        :type id: str
        :return: None
        :rtype: None
        """
        draft_id = kwargs.get("id", None)
        if draft_id is None:
            self.api.app_logger.error(
                "[opencti_draft] Cannot delete draft workspace, missing parameter: id"
            )
            return None
        query = """
            mutation DraftWorkspaceDelete($id: ID!) {
                draftWorkspaceDelete(id: $id)
            }
           """
        self.api.query(
            query,
            {
                "id": draft_id,
            },
        )
