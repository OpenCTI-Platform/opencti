class OpenCTIApiPlaybook:
    """OpenCTIApiPlaybook"""

    def __init__(self, api):
        self.api = api

    def playbook_step_execution(self, playbook: dict, bundle: str):
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
