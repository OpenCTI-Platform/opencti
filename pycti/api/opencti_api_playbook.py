import json

from pycti.api import LOGGER


class OpenCTIApiPlaybook:
    """OpenCTIApiPlaybook"""

    def __init__(self, api):
        self.api = api

    def playbook_step_execution(self, playbook: dict, bundle: str):
        LOGGER.info("Executing playbook step %s", playbook["playbook_id"])
        query = """
            mutation PlaybookStepExecution($instance_id: ID!, $playbook_id: ID!, $previous_step_id: ID!, $step_id: ID!, $previous_bundle: String!, $bundle: String!) {
                playbookStepExecution(instance_id: $instance_id, playbook_id: $playbook_id, previous_step_id: $previous_step_id, step_id: $step_id, previous_bundle: $previous_bundle, bundle: $bundle)
            }
           """
        self.api.query(
            query,
            {
                "playbook_id": playbook["playbook_id"],
                "instance_id": playbook["instance_id"],
                "step_id": playbook["step_id"],
                "previous_step_id": playbook["previous_step_id"],
                "previous_bundle": json.dumps(playbook["previous_bundle"]),
                "bundle": bundle,
            },
        )
