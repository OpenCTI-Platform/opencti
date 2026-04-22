import type { StoreCyberObservable } from '../../../../../src/types/store';

export const URL_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000022',
  standard_id: 'url--20000000-0000-4000-8000-000000000022',
  entity_type: 'Url',
  defanged: false,
  value: 'https://example.com/malware',
  x_opencti_score: 80,
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
} as unknown as StoreCyberObservable;

export const EXPECTED_URL = {
  id: 'url--20000000-0000-4000-8000-000000000022',
  type: 'url',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000022',
  x_opencti_type: 'Url',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  x_opencti_score: 80,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'https://example.com/malware',
  score: 80,
};

