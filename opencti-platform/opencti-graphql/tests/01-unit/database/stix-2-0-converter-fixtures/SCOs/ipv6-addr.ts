import type { StoreCyberObservable } from '../../../../../src/types/store';

export const IPV6_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000030',
  standard_id: 'ipv6-addr--20000000-0000-4000-8000-000000000030',
  entity_type: 'IPv6-Addr',
  defanged: false,
  value: '2001:0db8:85a3::8a2e:0370:7334',
  x_opencti_score: 60,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_IPV6 = {
  id: 'ipv6-addr--20000000-0000-4000-8000-000000000030',
  type: 'ipv6-addr',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000030',
  x_opencti_type: 'IPv6-Addr',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 60,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '2001:0db8:85a3::8a2e:0370:7334',
  resolves_to_refs: [],
  belongs_to_refs: [],
};

