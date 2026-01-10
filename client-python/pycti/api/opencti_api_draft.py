class OpenCTIApiDraft:
    """OpenCTI Draft API class.

    Manages draft workspace operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        """Delete a draft workspace.

        :param id: the draft workspace id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        query = """
            mutation DraftWorkspaceDelete($id: ID!) {
                draftWorkspaceDelete(id: $id)
            }
           """
        self.api.query(
            query,
            {
                "id": id,
            },
        )
