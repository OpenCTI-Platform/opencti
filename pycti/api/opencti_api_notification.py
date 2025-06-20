class OpenCTIApiNotification:
    """OpenCTIApiJob"""

    def __init__(self, api):
        self.api = api

    def delete(self, **kwargs):
        notification_id = kwargs.get("id", None)
        self.api.app_logger.info(
            "Deleting notifcation", {"notification_id": notification_id}
        )
        query = """
            mutation notificationDelete($id: ID!) {
                notificationDelete(id: $id)
            }
           """
        self.api.query(query, {"id": notification_id})

    def update_field(self, **kwargs):
        notification_id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        for input_value in input:
            if input_value["key"] == "is_read":
                is_read_value = bool(input_value["value"][0])
                self.mark_as_read(notification_id, is_read_value)

    def mark_as_read(self, notification_id: str, read: bool):
        self.api.app_logger.info(
            "Marking notifcation as read",
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
