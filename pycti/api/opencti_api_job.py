import logging

from typing import List


class OpenCTIApiJob:
    """OpenCTIApiJob
    """

    def __init__(self, api):
        self.api = api

    def update_job(self, job_id: str, status: str, messages: List[str]) -> str:
        """update a job with the API

        :param job_id: job id
        :type job_id: str
        :param status: job status
        :type status: str
        :param messages: job messages
        :type messages: list
        :return: the id for the updateJob
        :rtype: str
        """

        logging.info("Reporting job " + job_id + " with status " + status + "...")
        query = """
            mutation UpdateJob($id: ID!, $status: Status!, $messages: [String]) {
                updateJob(jobId: $id, status: $status, messages: $messages) {
                    internal_id_key
                }
            }
           """
        result = self.api.query(
            query, {"id": job_id, "status": status, "messages": messages}
        )
        return result["data"]["updateJob"]["internal_id_key"]

    def initiate_job(self, work_id: str) -> str:
        """initiate a job with the API

        :param work_id: id for the job
        :type work_id: str
        :return: the id for the initiateJob
        :rtype: str
        """

        logging.info("Creating new job on work " + work_id)
        query = """
            mutation InitiateJob($id: ID!) {
                initiateJob(workId: $id) {
                    internal_id_key
                }
            }
           """
        result = self.api.query(query, {"id": work_id})
        return result["data"]["initiateJob"]["internal_id_key"]
