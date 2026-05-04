import type { StoreEntity } from '../../../../../../src/types/store';

export const NOTE_INSTANCE = {
  id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
  standard_id: 'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8',
  entity_type: 'Note',
  attribute_abstract: 'this is a new note',
  content: 'with description:',
  note_types: ['analysis'],
  likelihood: 50,
  confidence: 100,
  created: '2025-06-26T15:32:23.000Z',
  modified: '2025-06-26T15:33:21.426Z',
  revoked: false,
  x_opencti_files: [
    {
      id: 'import/Note/b9aca079-0a66-4efd-a481-71b1ce745a3a/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T15:32:54.229Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  objects: [
    { standard_id: 'domain-name--c9d852bc-ec1b-57c8-b013-32f0f402f7a8' },
  ],
  objectLabel: [{ value: 'note' }],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
} as unknown as StoreEntity;

export const EXPECTED_NOTE = {
  id: 'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T15:32:23.000Z',
  modified: '2025-06-26T15:33:21.426Z',
  content: 'with description:',
  note_types: [
    'analysis',
  ],
  likelihood: 50,
  labels: [
    'note',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
  x_opencti_type: 'Note',
  type: 'note',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'domain-name--c9d852bc-ec1b-57c8-b013-32f0f402f7a8',
  ],
  abstract: 'this is a new note',
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Note/b9aca079-0a66-4efd-a481-71b1ce745a3a/ipv4_example.json',
      version: '2025-06-26T15:32:54.229Z',
    },
  ],
  x_opencti_granted_refs: [],
};
