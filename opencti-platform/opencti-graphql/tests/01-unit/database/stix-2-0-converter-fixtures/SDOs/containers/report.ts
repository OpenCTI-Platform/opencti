import type { StoreEntity } from '../../../../../../src/types/store';

export const REPORT_INSTANCE = {
  id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  standard_id: 'report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f',
  entity_type: 'Report',
  name: 'Report STIX 2.0',
  description: 'description',
  content: '<p>some content for my report about &nbsp;Disco Team Threat Actor Group</p>',
  published: '2025-06-26T14:32:10.000Z',
  report_types: ['internal-report'],
  x_opencti_reliability: 'A - Completely reliable',
  confidence: 100,
  created: '2025-06-26T14:32:10.000Z',
  modified: '2025-06-26T14:36:51.467Z',
  revoked: false,
  x_opencti_workflow_id: 'b29268cc-bb75-4f28-96c9-4cb48e549dff',
  x_opencti_files: [
    {
      id: 'import/Report/0c38a734-3150-468f-bf38-8dc1f937a1b3/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T14:33:39.655Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  content_mapping: 'eyJkaXNjbyB0ZWFtIHRocmVhdCBhY3RvciBncm91cCI6InRocmVhdC1hY2N0b3ItLWZkNmIwZTZmLTk2ZTAtNTY4ZC1iYTI0LThhMTQwZDA0MjhjZCJ9',
  createdBy: { standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6' },
  objects: [
    { standard_id: 'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd' },
    { standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' },
  ],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objectLabel: [{ value: 'report' }],
} as unknown as StoreEntity;

export const EXPECTED_REPORT = {
  id: 'report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f',
  spec_version: '2.0',
  revoked: false,
  x_opencti_reliability: 'A - Completely reliable',
  confidence: 100,
  created: '2025-06-26T14:32:10.000Z',
  modified: '2025-06-26T14:36:51.467Z',
  name: 'Report STIX 2.0',
  description: 'description',
  report_types: [
    'internal-report',
  ],
  published: '2025-06-26T14:32:10.000Z',
  x_opencti_workflow_id: 'b29268cc-bb75-4f28-96c9-4cb48e549dff',
  labels: [
    'report',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  x_opencti_type: 'Report',
  type: 'report',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Report/0c38a734-3150-468f-bf38-8dc1f937a1b3/ipv4_example.json',
      version: '2025-06-26T14:33:39.655Z',
    },
  ],
  x_opencti_granted_refs: [],
};
