import type { StoreEntity } from '../../../../../../src/types/store';

export const OPINION_INSTANCE = {
  id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  standard_id: 'opinion--0fe325be-7171-5696-a922-c9d15685c495',
  entity_type: 'Opinion',
  opinion: 'agree',
  explanation: 'my opinion',
  confidence: 75,
  created: '2025-06-26T15:36:22.864Z',
  modified: '2025-06-26T15:37:27.254Z',
  revoked: false,
  externalReferences: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096',
    },
  ],
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  objects: [{ standard_id: 'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8' }],
  objectOrganization: [
    {
      standard_id: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
      entity_type: 'Organization',
      name: 'Filigran',
    },
  ],
  objectLabel: [{ value: 'opinion' }],
} as unknown as StoreEntity;

export const EXPECTED_OPINION = {
  id: 'opinion--0fe325be-7171-5696-a922-c9d15685c495',
  spec_version: '2.0',
  revoked: false,
  confidence: 75,
  created: '2025-06-26T15:36:22.864Z',
  modified: '2025-06-26T15:37:27.254Z',
  explanation: 'my opinion',
  opinion: 'agree',
  labels: [
    'opinion',
  ],
  external_references: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096',
    },
  ],
  x_opencti_id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  x_opencti_type: 'Opinion',
  type: 'opinion',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_refs: [
    'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8',
  ],
  x_opencti_granted_refs: [
    'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  ],
  x_opencti_files: [],
  object_marking_refs: [],
};
