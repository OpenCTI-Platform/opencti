import type { StoreCyberObservable } from '../../../../../src/types/store';

export const USER_AGENT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000055',
  standard_id: 'user-agent--20000000-0000-4000-8000-000000000055',
  entity_type: 'User-Agent',
  defanged: false,
  value: 'Mozilla/5.0',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_USER_AGENT = {
  id: 'user-agent--20000000-0000-4000-8000-000000000055',
  type: 'user-agent',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000055',
  x_opencti_type: 'User-Agent',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'Mozilla/5.0',
  labels: [],
  score: 50,
  external_references: [],
};

