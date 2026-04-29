import type { StoreEntityGrouping } from '../../../../../../src/modules/grouping/grouping-types';

export const GROUPING_INSTANCE = {
  id: '2076a71c-a480-424f-8058-cb5c798e4360',
  standard_id: 'grouping--3f78a876-9216-5111-92d8-6871301f6e9e',
  entity_type: 'Grouping',
  name: 'grouping STIX 2.0',
  description: 'description',
  content: '<p>some content : Paradise Ransomware</p>',
  context: 'malware-analysis',
  confidence: 100,
  created: '2025-06-26T14:59:43.780Z',
  modified: '2025-06-26T15:14:12.529Z',
  revoked: false,
  x_opencti_files: [
    {
      id: 'import/Grouping/2076a71c-a480-424f-8058-cb5c798e4360/file_example (2).json',
      name: 'file_example (2).json',
      version: '2025-06-26T14:59:43.780Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  content_mapping: 'eyJhcmFkaXNlIHJhbnNvbXdhcmUiOiJtYWx3YXJlLS0yMWM0NWRiZS01NGVjLTViYjctYjhjZC05ZjI3Y2M1MTg3MTQifQ',
  objectLabel: [{ value: 'ryuk' }],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  createdBy: { standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6' },
  objects: [
    { standard_id: 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714' },
    { standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
} as unknown as StoreEntityGrouping;

export const EXPECTED_GROUPING = {
  id: 'grouping--3f78a876-9216-5111-92d8-6871301f6e9e',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T14:59:43.780Z',
  modified: '2025-06-26T15:14:12.529Z',
  name: 'grouping STIX 2.0',
  description: 'description',
  context: 'malware-analysis',
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
  x_opencti_id: '2076a71c-a480-424f-8058-cb5c798e4360',
  x_opencti_type: 'Grouping',
  type: 'grouping',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'file_example (2).json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Grouping/2076a71c-a480-424f-8058-cb5c798e4360/file_example (2).json',
      version: '2025-06-26T14:59:43.780Z',
    },
  ],
  x_opencti_granted_refs: [],
};
