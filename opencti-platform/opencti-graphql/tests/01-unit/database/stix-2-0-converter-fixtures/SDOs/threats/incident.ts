import type { StoreEntity } from '../../../../../../src/types/store';

export const INCIDENT_INSTANCE = {
  id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  standard_id: 'incident--4e110b9d-8c95-581e-8618-4be501bcbe06',
  entity_type: 'Incident',
  name: 'Incident Stix 2.0',
  description: 'description',
  incident_type: 'alert',
  first_seen: '2025-07-24T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  severity: 'medium',
  source: 'secret',
  objective: 'destruction',
  revoked: false,
  created: '2025-07-30T16:26:06.212Z',
  modified: '2025-07-30T18:52:14.947Z',
  confidence: 100,
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  objectOrganization: [
    {
      standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
      entity_type: 'Organization',
      name: 'ANSSI',
    },
  ],
  objectAssignee: [
    {
      internal_id: '51c085a6-612a-463b-9575-27513bf85d99',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'Marie',
    },
  ],
  objectLabel: [{ value: 'covid-19' }],
  createdBy: { standard_id: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29' },
  objectParticipant: [
    {
      internal_id: '51c085a6-612a-463b-9575-27513bf85d99',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'Marie',
    },
  ],
} as unknown as StoreEntity;

export const EXPECTED_INCIDENT = {
  id: 'incident--4e110b9d-8c95-581e-8618-4be501bcbe06',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-07-30T16:26:06.212Z',
  modified: '2025-07-30T18:52:14.947Z',
  name: 'Incident Stix 2.0',
  description: 'description',
  first_seen: '2025-07-24T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  objective: 'destruction',
  incident_type: 'alert',
  severity: 'medium',
  source: 'secret',
  labels: [
    'covid-19',
  ],
  x_opencti_id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  x_opencti_type: 'Incident',
  type: 'incident',
  x_opencti_files: [],
  created_by_ref: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  x_opencti_granted_refs: [
    'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  ],
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
  ],
  external_references: [],
};
