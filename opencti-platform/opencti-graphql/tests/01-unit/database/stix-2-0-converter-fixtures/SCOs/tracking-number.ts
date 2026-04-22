import type { StoreCyberObservable } from '../../../../../src/types/store';

export const TRACKING_NUMBER_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000056',
  standard_id: 'tracking-number--20000000-0000-4000-8000-000000000056',
  entity_type: 'Tracking-Number',
  defanged: false,
  value: '5555',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_TRACKING_NUMBER = {
  id: 'tracking-number--20000000-0000-4000-8000-000000000056',
  type: 'tracking-number',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000056',
  x_opencti_type: 'Tracking-Number',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '5555',
  labels: [],
  external_references: [],
};

