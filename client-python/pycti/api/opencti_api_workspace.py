class OpenCTIApiWorkspace:
    """OpenCTIApiWorkspace"""

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is None:
            self.api.admin_logger.error(
                "[opencti_workspace] Cant delete workspace, missing parameter: id"
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
                "id": id,
            },
        )
