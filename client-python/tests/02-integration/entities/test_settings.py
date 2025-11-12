from tests.cases.entities import SettingsTest


def test_settings_messages(api_client):
    settings_test = SettingsTest(api_client)
    settings_test.setup()
    try:
        result = settings_test.own_class().read(include_messages=True)
        id = result["id"]
        num_messages = len(result["platform_messages"])

        # Add message
        test_message_data = {
            "message": "This is a test message",
            "activated": True,
            "dismissible": True,
        }
        result = settings_test.own_class().edit_message(id=id, input=test_message_data)
        assert len(result["platform_messages"]) == num_messages + 1

        test_message = result["platform_messages"][-1]
        assert test_message["message"] == test_message_data["message"]

        # Update message
        result = settings_test.own_class().edit_message(
            id=id,
            input={
                "id": test_message["id"],
                "message": "This is an updated test message",
                "activated": True,
                "dismissible": False,
            },
        )
        assert len(result["platform_messages"]) == num_messages + 1

        updated_message = result["platform_messages"][-1]
        assert updated_message["id"] == test_message["id"]
        assert updated_message["message"] == "This is an updated test message"

        # Delete message
        result = settings_test.own_class().delete_message(
            id=id, input=test_message["id"]
        )
        assert len(result["platform_messages"]) == num_messages
        assert test_message["id"] not in result["platform_messages_ids"]
    finally:
        settings_test.teardown()
