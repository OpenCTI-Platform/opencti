import logging


class OpenCTIApiJob:

    def __init__(self, api):
        self.api = api

    def update_job(self, job_id: str, status: str, messages: [str]):
        logging.info('Reporting job ' + job_id + ' with status ' + status + '...')
        query = """
            mutation UpdateJob($id: ID!, $status: Status!, $messages: [String]) {
                updateJob(jobId: $id, status: $status, messages: $messages) {
                    internal_id_key
                }
            }
           """
        result = self.api.query(query, {'id': job_id, 'status': status, 'messages': messages})
        return result['data']['updateJob']['internal_id_key']

    def initiate_job(self, work_id: str):
        logging.info('Creating new job on work ' + work_id)
        query = """
            mutation InitiateJob($id: ID!) {
                initiateJob(workId: $id) {
                    internal_id_key
                }
            }
           """
        result = self.api.query(query, {'id': work_id})
        return result['data']['initiateJob']['internal_id_key']
