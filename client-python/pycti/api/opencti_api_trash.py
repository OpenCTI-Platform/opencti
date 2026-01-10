class OpenCTIApiTrash:
    """OpenCTI Trash API class.

    Manages trash/delete operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        """Initialize the OpenCTIApiTrash instance.

        :param api: OpenCTI API client instance
        :type api: OpenCTIApiClient
        """
        self.api = api

    def restore(self, operation_id: str):
        """Restore a deleted item from trash.

        :param operation_id: the delete operation id
        :type operation_id: str
        :return: None
        :rtype: None
        """
        query = """
            mutation DeleteOperationRestore($id: ID!) {
                deleteOperationRestore(id: $id)
            }
           """
        self.api.query(
            query,
            {
                "id": operation_id,
            },
        )

    def delete(self, **kwargs):
        """Delete a trash item given its ID.

        :param id: ID for the delete operation on the platform
        :type id: str
        :return: None
        :rtype: None
        """
        delete_operation_id = kwargs.get("id", None)
        if delete_operation_id is None:
            self.api.admin_logger.error(
                "[opencti_trash] Cannot confirm delete, missing parameter: id"
            )
            return None
        query = """
            mutation DeleteOperationConfirm($id: ID!) {
                deleteOperationConfirm(id: $id)
            }
        """
        self.api.query(
            query,
            {
                "id": delete_operation_id,
            },
        )
