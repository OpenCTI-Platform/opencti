class OpenCTIApiDraft:
    """OpenCTIApiDraft"""

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
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
