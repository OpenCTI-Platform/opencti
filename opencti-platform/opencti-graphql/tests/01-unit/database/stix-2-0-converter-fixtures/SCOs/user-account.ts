import type { StoreCyberObservable } from '../../../../../src/types/store';

export const USER_ACCOUNT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000035',
  standard_id: 'user-account--20000000-0000-4000-8000-000000000035',
  entity_type: 'User-Account',
  defanged: false,
  user_id: '1001',
  account_login: 'admin',
  account_type: 'unix',
  display_name: 'Root Admin',
  is_privileged: true,
  is_service_account: false,
  is_disabled: false,
  account_created: '2025-01-01T00:00:00.000Z',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_USER_ACCOUNT = {
  id: 'user-account--20000000-0000-4000-8000-000000000035',
  type: 'user-account',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000035',
  x_opencti_type: 'User-Account',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  user_id: '1001',
  account_login: 'admin',
  account_type: 'unix',
  display_name: 'Root Admin',
  is_privileged: true,
  is_service_account: false,
  is_disabled: false,
  account_created: '2025-01-01T00:00:00.000Z',
};

