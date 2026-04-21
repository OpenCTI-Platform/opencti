import type { StoreCyberObservable } from '../../../../../src/types/store';

export const MUTEX_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000032',
  standard_id: 'mutex--20000000-0000-4000-8000-000000000032',
  entity_type: 'Mutex',
  defanged: false,
  name: 'Global\\MalwareMutex',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_MUTEX = {
  id: 'mutex--20000000-0000-4000-8000-000000000032',
  type: 'mutex',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000032',
  x_opencti_type: 'Mutex',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  name: 'Global\\MalwareMutex',
};

