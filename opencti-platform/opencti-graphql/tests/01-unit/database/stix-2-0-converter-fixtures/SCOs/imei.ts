import type { StoreCyberObservable } from '../../../../../src/types/store';

export const IMEI_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000060',
  standard_id: 'imei--20000000-0000-4000-8000-000000000060',
  entity_type: 'IMEI',
  defanged: false,
  value: '111111111111111',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_IMEI = {
  id: 'imei--20000000-0000-4000-8000-000000000060',
  type: 'imei',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000060',
  x_opencti_type: 'IMEI',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '111111111111111',
  labels: [],
  score: 50,
  external_references: [],
};

