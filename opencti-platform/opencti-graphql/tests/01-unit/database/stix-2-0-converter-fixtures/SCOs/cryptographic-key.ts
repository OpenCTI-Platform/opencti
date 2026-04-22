import type { StoreCyberObservable } from '../../../../../src/types/store';

export const CRYPTOGRAPHIC_KEY_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000059',
  standard_id: 'cryptographic-key--20000000-0000-4000-8000-000000000059',
  entity_type: 'Cryptographic-Key',
  defanged: false,
  value: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_CRYPTOGRAPHIC_KEY = {
  id: 'cryptographic-key--20000000-0000-4000-8000-000000000059',
  type: 'cryptographic-key',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000059',
  x_opencti_type: 'Cryptographic-Key',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
  labels: [],
  external_references: [],
};

