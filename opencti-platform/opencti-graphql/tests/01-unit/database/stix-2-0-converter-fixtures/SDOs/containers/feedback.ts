import type { StoreEntityFeedback } from '../../../../../../src/modules/case/feedback/feedback-types';

export const FEEDBACK_INSTANCE = {
  id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  standard_id: 'feedback--ce07ddc6-2377-576b-ace5-a4de6996e789',
  entity_type: 'Feedback',
  name: 'Feedback from admin@opencti.io',
  description: 'Feedback STIX 2.0',
  confidence: 93,
  rating: 3,
  created: '2025-06-26T15:58:16.208Z',
  modified: '2025-06-26T16:04:50.126Z',
  revoked: false,
  x_opencti_files: [
    {
      id: 'import/Feedback/5a194bd5-1fe1-4618-bfa0-48b15eb590b4/file_example (2).json',
      name: 'file_example (2).json',
      version: '2025-06-26T15:58:16.639Z',
      mime_type: 'application/json',
      file_markings: [],
    },
  ],
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  objects: [{ standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' }],
  objectLabel: [{ value: 'ryuk' }],
  externalReferences: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096',
    },
  ],
} as unknown as StoreEntityFeedback;

export const EXPECTED_FEEDBACK = {
  id: 'x-opencti-feedback--ce07ddc6-2377-576b-ace5-a4de6996e789',
  spec_version: '2.0',
  revoked: false,
  confidence: 93,
  created: '2025-06-26T15:58:16.208Z',
  modified: '2025-06-26T16:04:50.126Z',
  name: 'Feedback from admin@opencti.io',
  description: 'Feedback STIX 2.0',
  rating: 3,
  labels: [
    'ryuk',
  ],
  external_references: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096',
    },
  ],
  x_opencti_id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  x_opencti_type: 'Feedback',
  type: 'x-opencti-feedback',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_refs: [
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'file_example (2).json',
      object_marking_refs: [],
      uri: '/storage/get/import/Feedback/5a194bd5-1fe1-4618-bfa0-48b15eb590b4/file_example (2).json',
      version: '2025-06-26T15:58:16.639Z',
    },
  ],
  object_marking_refs: [],
  x_opencti_granted_refs: [],
};
