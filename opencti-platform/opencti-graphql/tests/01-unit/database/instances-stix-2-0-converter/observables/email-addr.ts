import type { StoreCyberObservable } from '../../../../../src/types/store';

export const EMAIL_ADDR_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000023',
  standard_id: 'email-addr--20000000-0000-4000-8000-000000000023',
  entity_type: 'Email-Addr',
  defanged: false,
  value: 'phish@evil.com',
  display_name: 'Phisher',
  x_opencti_score: 60,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_EMAIL_ADDR = {
  id: 'email-addr--20000000-0000-4000-8000-000000000023',
  type: 'email-addr',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000023',
  x_opencti_type: 'Email-Addr',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 60,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'phish@evil.com',
  display_name: 'Phisher',
};

