import type { StoreCyberObservable } from '../../../../../src/types/store';

export const AUTONOMOUS_SYSTEM_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000025',
  standard_id: 'autonomous-system--20000000-0000-4000-8000-000000000025',
  entity_type: 'Autonomous-System',
  defanged: false,
  number: 15169,
  name: 'GOOGLE',
  rir: 'ARIN',
  x_opencti_score: 30,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_AUTONOMOUS_SYSTEM = {
  id: 'autonomous-system--20000000-0000-4000-8000-000000000025',
  type: 'autonomous-system',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000025',
  x_opencti_type: 'Autonomous-System',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 30,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  number: 15169,
  name: 'GOOGLE',
  rir: 'ARIN',
};

