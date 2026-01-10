class OpenCTIApiNotification:
    """OpenCTI Notification API class.

    Manages notification operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        """Delete a notification.

        :param id: the notification id
        :type id: str
        :return: None
        """
        notification_id = kwargs.get("id", None)
        self.api.app_logger.info(
            "Deleting notification", {"notification_id": notification_id}
        )
        query = """
            mutation notificationDelete($id: ID!) {
                notificationDelete(id: $id)
            }
           """
        self.api.query(query, {"id": notification_id})

    def update_field(self, **kwargs):
        """Update a notification field.

        :param id: the notification id
        :type id: str
        :param input: the input fields to update
        :type input: list
        :return: None
        """
        notification_id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        for input_value in input:
            if input_value["key"] == "is_read":
                is_read_value = bool(input_value["value"][0])
                self.mark_as_read(notification_id, is_read_value)

    def mark_as_read(self, notification_id: str, read: bool):
        """Mark a notification as read or unread.

        :param notification_id: the notification id
        :type notification_id: str
        :param read: whether to mark as read (True) or unread (False)
        :type read: bool
        :return: None
        """
        self.api.app_logger.info(
            "Marking notification as read",
            {"notification_id": notification_id, "read": read},
        )
        query = """
                mutation notificationMarkRead($id: ID!, $read: Boolean!) {
                    notificationMarkRead(id: $id, read: $read) {
                        id
                    }
                }
               """
        self.api.query(query, {"id": notification_id, "read": read})
