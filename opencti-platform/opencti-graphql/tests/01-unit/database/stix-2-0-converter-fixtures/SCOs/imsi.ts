import type { StoreCyberObservable } from '../../../../../src/types/store';

export const IMSI_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000064',
  standard_id: 'imsi--20000000-0000-4000-8000-000000000064',
  entity_type: 'IMSI',
  defanged: false,
  value: '310260000000000',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_IMSI = {
  id: 'imsi--20000000-0000-4000-8000-000000000064',
  type: 'imsi',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000064',
  x_opencti_type: 'IMSI',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '310260000000000',
  labels: [],
  external_references: [],
};

