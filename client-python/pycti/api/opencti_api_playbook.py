class OpenCTIApiPlaybook:
    """OpenCTI Playbook API class.

    Manages playbook operations.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def playbook_step_execution(self, playbook: dict, bundle: str):
        """Execute a playbook step.

        :param playbook: the playbook configuration dict containing execution_id, event_id,
            execution_start, playbook_id, data_instance_id, step_id, previous_step_id,
            and previous_bundle
        :type playbook: dict
        :param bundle: the STIX bundle to process
        :type bundle: str
        :return: None
        :rtype: None
        """
        self.api.app_logger.info(
            "Executing playbook step",
            {
                "playbook_id": playbook["playbook_id"],
                "step_id": playbook["step_id"],
                "data_instance_id": playbook["data_instance_id"],
            },
        )
        query = """
            mutation PlaybookStepExecution($execution_id: ID!, $event_id: ID!, $execution_start: DateTime!, $data_instance_id: ID!, $playbook_id: ID!, $previous_step_id: ID!, $step_id: ID!, $previous_bundle: String!, $bundle: String!) {
                playbookStepExecution(execution_id: $execution_id, event_id: $event_id, execution_start: $execution_start, data_instance_id: $data_instance_id, playbook_id: $playbook_id, previous_step_id: $previous_step_id, step_id: $step_id, previous_bundle: $previous_bundle, bundle: $bundle)
            }
           """
        self.api.query(
            query,
            {
                "execution_id": playbook["execution_id"],
                "event_id": playbook["event_id"],
                "execution_start": playbook["execution_start"],
                "playbook_id": playbook["playbook_id"],
                "data_instance_id": playbook["data_instance_id"],
                "step_id": playbook["step_id"],
                "previous_step_id": playbook["previous_step_id"],
                "previous_bundle": playbook["previous_bundle"],
                "bundle": bundle,
            },
        )

    def delete(self, **kwargs):
        """Delete a playbook.

        :param id: the playbook id
        :type id: str
        :return: None
        :rtype: None
        """
        playbook_id = kwargs.get("id", None)
        if playbook_id is not None:
            query = """
                mutation PlaybookDelete($id: ID!) {
                    playbookDelete(id: $id)
                }
               """
            self.api.query(
                query,
                {
                    "id": playbook_id,
                },
            )
        else:
            self.api.app_logger.error(
                "[opencti_playbook] Cannot delete playbook, missing parameter: id"
            )
            return None
