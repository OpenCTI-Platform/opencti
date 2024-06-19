import deprecation


class StixCyberObservableDeprecatedMixin:
    """
    deprecated [>=6.2 & <6.5]`
    Promote a Stix-Observable to an Indicator

    :param id: the Stix-Observable id
    :return the observable
    """

    @deprecation.deprecated(
        deprecated_in="6.2",
        removed_in="6.5",
        details="Use promote_to_indicator_v2 instead.",
    )
    def promote_to_indicator(self, **kwargs):
        id = kwargs.get("id", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info(
                "Promoting Stix-Observable",
                {
                    "id": id,
                    "withFiles": with_files,
                    "customAttributes": custom_attributes,
                },
            )
            query = (
                """
                        mutation StixCyberObservableEdit($id: ID!) {
                            stixCyberObservableEdit(id: $id) {
                                promote {
                                    """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                            }
                        }
                    }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableEdit"]["promote"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable_promote] Missing parameters: id"
            )
            return None
