class OpenCTIApiInternalFile:
    """OpenCTI Internal File API class.

    Manages internal file operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        """Delete an internal file.

        :param item: the item containing file information
        :type item: dict
        :return: None
        """
        item = kwargs.get("item", None)
        file_name = self.api.get_attribute_in_extension("id", item)
        if file_name is not None:
            query = """
                mutation InternalFileDelete($fileName: String) {
                    deleteImport(fileName: $fileName)
                }
               """
            self.api.query(
                query,
                {
                    "fileName": file_name,
                },
            )
        else:
            self.api.app_logger.error(
                "[opencti_internal_file] Cannot delete internal file, missing parameters: fileName"
            )
            return None
