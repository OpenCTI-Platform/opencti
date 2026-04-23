import type { StoreCyberObservable } from '../../../../../src/types/store';

export const SSH_KEY_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000058',
  standard_id: 'ssh-key--20000000-0000-4000-8000-000000000058',
  entity_type: 'SSH-Key',
  defanged: false,
  fingerprint_sha256: '698e5b54741866540fee17b77d4a1da0',
  comment: 'test key',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_SSH_KEY = {
  id: 'ssh-key--20000000-0000-4000-8000-000000000058',
  type: 'ssh-key',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000058',
  x_opencti_type: 'SSH-Key',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  fingerprint_sha256: '698e5b54741866540fee17b77d4a1da0',
  comment: 'test key',
  external_references: [],
};

