import type { StoreCyberObservable } from '../../../../../src/types/store';

export const ICCID_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000063',
  standard_id: 'iccid--20000000-0000-4000-8000-000000000063',
  entity_type: 'ICCID',
  defanged: false,
  value: '8901260882902170891',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_ICCID = {
  id: 'iccid--20000000-0000-4000-8000-000000000063',
  type: 'iccid',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000063',
  x_opencti_type: 'ICCID',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '8901260882902170891',
  labels: [],
  external_references: [],
};

