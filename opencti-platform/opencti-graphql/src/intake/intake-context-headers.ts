// The headers of a worker's ingestion request (pycti OpenCTIApiClient set_*_header)
export const INTAKE_HEADERS = {
  work: 'opencti-work-id',
  draft: 'opencti-draft-id',
  event: 'opencti-event-id',
  previousStandard: 'previous-standard',
  synchronized: 'synchronized-upsert',
  applicant: 'opencti-applicant-id',
  playbook: 'opencti-playbook-id',
  retry: 'opencti-retry-number',
} as const;
