import type { StoreCyberObservable } from '../../../../../src/types/store';

export const DOMAIN_NAME_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000021',
  standard_id: 'domain-name--20000000-0000-4000-8000-000000000021',
  entity_type: 'Domain-Name',
  defanged: false,
  value: 'example.com',
  x_opencti_score: 50,
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
} as unknown as StoreCyberObservable;

export const EXPECTED_DOMAIN_NAME = {
  id: 'domain-name--20000000-0000-4000-8000-000000000021',
  type: 'domain-name',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000021',
  x_opencti_type: 'Domain-Name',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  x_opencti_external_references: [],
  value: 'example.com',
  resolves_to_refs: [],
};

