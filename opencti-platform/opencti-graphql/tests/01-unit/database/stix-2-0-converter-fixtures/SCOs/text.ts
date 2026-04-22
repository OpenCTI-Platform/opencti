import type { StoreCyberObservable } from '../../../../../src/types/store';

export const TEXT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000054',
  standard_id: 'text--20000000-0000-4000-8000-000000000054',
  entity_type: 'Text',
  defanged: false,
  value: 'v=spf1 redirect=spf.hostens.com',
  objectMarking: [{ standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9' }],
} as unknown as StoreCyberObservable;

export const EXPECTED_TEXT = {
  id: 'text--20000000-0000-4000-8000-000000000054',
  type: 'text',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000054',
  x_opencti_type: 'Text',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: ['marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'v=spf1 redirect=spf.hostens.com',
  labels: [],
  external_references: [],
};

