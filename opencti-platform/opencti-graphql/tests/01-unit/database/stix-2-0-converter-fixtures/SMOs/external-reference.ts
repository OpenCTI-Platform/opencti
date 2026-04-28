import type { StoreEntity } from '../../../../../src/types/store';

export const EXTERNAL_REFERENCE_INSTANCE = {
  id: '24cf37f3-e6fa-4b79-a1cb-3d5a588c99dc',
  entity_type: 'External-Reference',
  standard_id: 'external-reference--c124ce2d-15d8-555f-9023-6afe519ac3df',
  source_name: '20th January – Threat Intelligence Report',
  description: 'bug nino 20th January – Threat Intelligence Report. Retrieved 2025-01-20T15:03:57.000Z.',
  url: 'https://research.checkpoint.com/2025/20th-january-threat-intelligence-report/',
} as unknown as StoreEntity;

export const EXPECTED_EXTERNAL_REFERENCE = {
  id: 'external-reference--c124ce2d-15d8-555f-9023-6afe519ac3df',
  type: 'external-reference',
  spec_version: '2.0',
  source_name: '20th January – Threat Intelligence Report',
  description: 'bug nino 20th January – Threat Intelligence Report. Retrieved 2025-01-20T15:03:57.000Z.',
  url: 'https://research.checkpoint.com/2025/20th-january-threat-intelligence-report/',
  hashes: {},
  x_opencti_id: '24cf37f3-e6fa-4b79-a1cb-3d5a588c99dc',
  x_opencti_type: 'External-Reference',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
};
