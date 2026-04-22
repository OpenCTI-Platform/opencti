import type { StoreCyberObservable } from '../../../../../src/types/store';

export const MAC_ADDR_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000031',
  standard_id: 'mac-addr--20000000-0000-4000-8000-000000000031',
  entity_type: 'Mac-Addr',
  defanged: false,
  value: '00:1B:44:11:3A:B7',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_MAC_ADDR = {
  id: 'mac-addr--20000000-0000-4000-8000-000000000031',
  type: 'mac-addr',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000031',
  x_opencti_type: 'Mac-Addr',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '00:1B:44:11:3A:B7',
};

