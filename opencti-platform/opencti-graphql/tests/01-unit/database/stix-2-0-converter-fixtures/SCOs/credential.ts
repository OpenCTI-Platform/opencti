import type { StoreCyberObservable } from '../../../../../src/types/store';

export const CREDENTIAL_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000053',
  standard_id: 'credential--20000000-0000-4000-8000-000000000053',
  entity_type: 'Credential',
  defanged: false,
  value: 'test password',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_CREDENTIAL = {
  id: 'credential--20000000-0000-4000-8000-000000000053',
  type: 'credential',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000053',
  x_opencti_type: 'Credential',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'test password',
  labels: [],
  score: 50,
  external_references: [],
};

