from typing import Dict, Optional


class Settings:
    """Represents the Settings object in OpenCTI

    These are the properties which are viewable in the customization and
    security policies views on OpenCTI platform. This also includes all
    messages on the platform.

    See the properties attribute to understand which properties are fetched by
    default on graphql queries.
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            platform_organization {
                id, name, description
            }
            platform_title
            platform_favicon
            platform_email
            platform_url
            platform_language
            platform_cluster {
                instances_number
            }
            platform_modules {
                id, enable, warning
            }
            platform_providers {
                name, type, strategy, provider
            }
            platform_user_statuses {
                status, message
            }
            platform_theme
            platform_theme_dark_background
            platform_theme_dark_paper
            platform_theme_dark_nav
            platform_theme_dark_primary
            platform_theme_dark_secondary
            platform_theme_dark_accent
            platform_theme_dark_logo
            platform_theme_dark_logo_collapsed
            platform_theme_dark_logo_login
            platform_theme_light_background
            platform_theme_light_paper
            platform_theme_light_nav
            platform_theme_light_primary
            platform_theme_light_secondary
            platform_theme_light_accent
            platform_theme_light_logo
            platform_theme_light_logo_collapsed
            platform_theme_light_logo_login
            platform_map_tile_server_dark
            platform_map_tile_server_light
            platform_openbas_url
            platform_openbas_disable_display
            platform_openerm_url
            platform_openmtd_url
            platform_ai_enabled
            platform_ai_type
            platform_ai_model
            platform_ai_has_token
            platform_login_message
            platform_consent_message
            platform_consent_confirm_text
            platform_banner_text
            platform_banner_level
            platform_session_idle_timeout
            platform_session_timeout
            platform_whitemark
            platform_demo
            platform_reference_attachment
            platform_feature_flags {
                id, enable, warning
            }
            platform_critical_alerts {
                message, type
                details {
                    groups {
                        id, name, description
                    }
                }
            }
            platform_trash_enabled
            platform_protected_sensitive_config {
                enabled
                markings {
                    enabled, protected_ids
                }
                groups {
                    enabled, protected_ids
                }
                roles {
                    enabled, protected_ids
                }
                rules {
                    enabled, protected_ids
                }
                ce_ee_toggle {
                    enabled, protected_ids
                }
                file_indexing {
                    enabled, protected_ids
                }
                platform_organization {
                    enabled, protected_ids
                }
            }
            created_at
            updated_at
            platform_enterprise_edition {
                license_enterprise
                license_by_configuration
                license_customer
                license_validated
                license_valid_cert
                license_expired
                license_expiration_prevention
                license_start_date
                license_expiration_date
                license_platform
                license_type
                license_platform_match
                license_creator
                license_global
            }
            analytics_google_analytics_v4
            activity_listeners {
                id, name, entity_type
            }
        """
        self.messages_properties = """
            entity_type
            platform_messages {
                id, message, activated, dismissible, updated_at, color
                recipients {
                    id, name, entity_type
                }
            }
            messages_administration {
                id, message, activated, dismissible, updated_at, color
                recipients {
                    id, name, entity_type
                }
            }
        """
        self.password_policy_properties = """
            otp_mandatory
            password_policy_min_length
            password_policy_max_length
            password_policy_min_symbols
            password_policy_min_numbers
            password_policy_min_words
            password_policy_min_lowercase
            password_policy_min_uppercase
        """

        self.editable_properties = (
            """
            id
            platform_organization {
                id
            }
            platform_title
            platform_favicon
            platform_email
            platform_language
            platform_theme
            platform_theme_dark_background
            platform_theme_dark_paper
            platform_theme_dark_nav
            platform_theme_dark_primary
            platform_theme_dark_secondary
            platform_theme_dark_accent
            platform_theme_dark_logo
            platform_theme_dark_logo_collapsed
            platform_theme_dark_logo_login
            platform_theme_light_background
            platform_theme_light_paper
            platform_theme_light_nav
            platform_theme_light_primary
            platform_theme_light_secondary
            platform_theme_light_accent
            platform_theme_light_logo
            platform_theme_light_logo_collapsed
            platform_theme_light_logo_login
            platform_login_message
            platform_consent_message
            platform_consent_confirm_text
            platform_banner_text
            platform_banner_level
            platform_whitemark
            analytics_google_analytics_v4
        """
            + self.password_policy_properties
        )

    def read(self, **kwargs) -> Dict:
        """Reads settings from the platform

        :param customAttributes: Custom attribues to return from query
        :type customAttributes: str, optional
        :param include_password_policy: Defaults to False. Whether to include
            password policy properties in response.
        :type include_password_policy: bool, optional
        :param include_messages: Defaults to False. Whether to include messages
            in query response.
        :type include_messages: bool, optional
        :return: Representation of the platform settings
        :rtype: Dict
        """
        custom_attributes = kwargs.get("customAttributes", None)
        include_password_policy = kwargs.get("include_password_policy", False)
        include_messages = kwargs.get("include_messages", False)

        self.opencti.admin_logger.info("Reading platform settings")
        query = (
            """
            query PlatformSettings {
                settings {
                    """
            + (self.properties if custom_attributes is None else custom_attributes)
            + (self.password_policy_properties if include_password_policy else "")
            + (self.messages_properties if include_messages else "")
            + """
                }
            }
            """
        )
        result = self.opencti.query(query)
        return self.opencti.process_multiple_fields(result["data"]["settings"])

    def update_field(self, **kwargs) -> Optional[Dict]:
        """Update settings using input to fieldPatch

        :param id: ID of the settings object to update
        :type id: str
        :param input: List of EditInput objects
        :type input: List[Dict]
        :param customAttributes: Custom attribues to return from query
        :type customAttributes: str, optional
        :param include_password_policy: Defaults to False. Whether to include
            password policy properties in response.
        :type include_password_policy: bool, optional
        :param include_messages: Defaults to False. Whether to include messages
            in query response.
        :type include_messages: bool, optional
        :return: Representation of the platform settings
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        custom_attributes = kwargs.get("customAttributes", None)
        include_password_policy = kwargs.get("include_password_policy", False)
        include_messages = kwargs.get("include_messages", False)

        if id is None or input is None:
            self.opencti.admin_logger.error(
                "[opencti_settings] Missing parameters: id and input"
            )
            return None

        self.opencti.admin_logger.info(
            "Updating settings with input", {"id": id, "input": input}
        )
        query = (
            """
            mutation SettingsUpdateField($id: ID!, $input: [EditInput]!) {
                settingsEdit(id: $id) {
                    fieldPatch(input: $input) {
                        """
            + (self.properties if custom_attributes is None else custom_attributes)
            + (self.password_policy_properties if include_password_policy else "")
            + (self.messages_properties if include_messages else "")
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"id": id, "input": input})
        return self.opencti.process_multiple_fields(
            result["data"]["settingsEdit"]["fieldPatch"]
        )

    def edit_message(self, **kwargs) -> Optional[Dict]:
        """Edit or add a message to the platform

        To add a message, don't include an ID in the input object. To edit a
        message an ID must be provided.

        :param id: ID of the settings object on the platform
        :type id: str
        :param input: SettingsMessageInput object
        :type input: Dict
        :return: Settings ID and message objects
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is None or input is None:
            self.opencti.admin_logger.error(
                "[opencti_settings] Missing parameters: id and input"
            )
            return None
        self.opencti.admin_logger.info("Editing message", {"id": id, "input": input})

        query = (
            """
            mutation SettingsEditMessage($id: ID!, $input: SettingsMessageInput!) {
                settingsEdit(id: $id) {
                    editMessage(input: $input) {
                        id
                        """
            + self.messages_properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"id": id, "input": input})
        return self.opencti.process_multiple_fields(
            result["data"]["settingsEdit"]["editMessage"]
        )

    def delete_message(self, **kwargs) -> Optional[Dict]:
        """Delete a message from the platform

        :param id: ID of the settings object on the platform
        :type id: str
        :param input: ID of the message to delete
        :type input: str
        :return: Settings ID and message objects
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is None:
            self.opencti.admin_logger.info("[opencti_settings] Missing parameters: id")
            return None

        query = (
            """
            mutation SettingsEditDeleteMessage($id: ID!, $input: String!) {
                settingsEdit(id: $id) {
                    deleteMessage(input: $input) {
                        id
                        """
            + self.messages_properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"id": id, "input": input})
        return self.opencti.process_multiple_fields(
            result["data"]["settingsEdit"]["deleteMessage"]
        )

    def process_multiple_fields(self, data):
        if "platform_messages" in data:
            data["platform_messages"] = self.opencti.process_multiple(
                data["platform_messages"]
            )
            data["platform_messages_ids"] = self.opencti.process_multiple_ids(
                data["platform_messages"]
            )
        if "messages_administration" in data:
            data["messages_administration"] = self.opencti.process_multiple(
                data["messages_administration"]
            )
            data["messages_administration_ids"] = self.opencti.process_multiple_ids(
                data["messages_administration"]
            )
        return data
