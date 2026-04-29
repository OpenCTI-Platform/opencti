import type { StoreEntity } from '../../../../../../src/types/store';

export const OBSERVED_DATA_INSTANCE = {
  id: '9653626d-54c7-433b-beca-ee1dee226125',
  standard_id: 'observed-data--a9ed3299-df09-5bc6-bd5f-0831d75114ae',
  entity_type: 'Observed-Data',
  first_observed: '2025-06-18T22:00:00.000Z',
  last_observed: '2025-06-27T22:00:00.000Z',
  number_observed: 1,
  confidence: 94,
  created: '2025-06-26T15:23:30.704Z',
  modified: '2025-06-26T15:29:37.100Z',
  revoked: false,
  x_opencti_files: [
    {
      id: 'import/Observed-Data/9653626d-54c7-433b-beca-ee1dee226125/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T15:23:30.705Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  objects: [
    { standard_id: 'campaign--737733a0-2cb5-5981-9814-53c0e3fbd9e9' },
    { standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' },
  ],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  createdBy: { standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6' },
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objectLabel: [{ value: 'campaign' }],
} as unknown as StoreEntity;

export const EXPECTED_OBSERVED_DATA = {
  id: 'observed-data--a9ed3299-df09-5bc6-bd5f-0831d75114ae',
  spec_version: '2.0',
  revoked: false,
  confidence: 94,
  created: '2025-06-26T15:23:30.704Z',
  modified: '2025-06-26T15:29:37.100Z',
  first_observed: '2025-06-18T22:00:00.000Z',
  last_observed: '2025-06-27T22:00:00.000Z',
  number_observed: 1,
  labels: [
    'campaign',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: '9653626d-54c7-433b-beca-ee1dee226125',
  x_opencti_type: 'Observed-Data',
  type: 'observed-data',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'campaign--737733a0-2cb5-5981-9814-53c0e3fbd9e9',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Observed-Data/9653626d-54c7-433b-beca-ee1dee226125/ipv4_example.json',
      version: '2025-06-26T15:23:30.705Z',
    },
  ],
  x_opencti_granted_refs: [],
};
