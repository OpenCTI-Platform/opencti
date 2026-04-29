import type { StoreEntityCaseIncident } from '../../../../../../src/modules/case/case-incident/case-incident-types';

export const INCIDENT_RESPONSE_INSTANCE = {
  id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  standard_id: 'case-incident--0ed8c294-d99f-5155-a54b-7cc3044174c3',
  entity_type: 'Case-Incident',
  name: 'IR STIX 2.0',
  severity: 'medium',
  priority: 'P2',
  description: 'description',
  content: '<p>some content</p>',
  confidence: 100,
  created: '2025-06-26T16:06:02.000Z',
  modified: '2025-06-26T16:06:52.288Z',
  revoked: false,
  response_types: ['data-leak'],
  x_opencti_files: [
    {
      id: 'import/Case-Incident/4c849ab0-81f2-457c-b837-bea76f4d4d15/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T16:06:52.222Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  objectParticipant: [
    {
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'marie',
    },
  ],
  objectLabel: [{ value: 'ryuk' }],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objectAssignee: [
    {
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'marie',
    },
  ],
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
} as unknown as StoreEntityCaseIncident;

export const EXPECTED_IR = {
  id: 'x-opencti-case-incident--0ed8c294-d99f-5155-a54b-7cc3044174c3',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T16:06:02.000Z',
  modified: '2025-06-26T16:06:52.288Z',
  name: 'IR STIX 2.0',
  description: 'description',
  severity: 'medium',
  priority: 'P2',
  object_refs: [],
  response_types: [
    'data-leak',
  ],
  labels: [
    'ryuk',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  x_opencti_type: 'Case-Incident',
  type: 'x-opencti-case-incident',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Incident/4c849ab0-81f2-457c-b837-bea76f4d4d15/ipv4_example.json',
      version: '2025-06-26T16:06:52.222Z',
    },
  ],
  x_opencti_granted_refs: [],
};
