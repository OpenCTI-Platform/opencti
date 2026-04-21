import type { StoreCyberObservable } from '../../../../../src/types/store';

export const IPV4_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000020',
  standard_id: 'ipv4-addr--20000000-0000-4000-8000-000000000020',
  entity_type: 'IPv4-Addr',
  defanged: false,
  value: '198.51.100.1',
  x_opencti_score: 70,
  x_opencti_description: 'Malicious IP',
  objectLabel: [{ value: 'stix 2.0' }],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
} as unknown as StoreCyberObservable;

export const EXPECTED_IPV4 = {
  id: 'ipv4-addr--20000000-0000-4000-8000-000000000020',
  type: 'ipv4-addr',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000020',
  x_opencti_type: 'IPv4-Addr',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  x_opencti_score: 70,
  x_opencti_description: 'Malicious IP',
  x_opencti_labels: ['stix 2.0'],
  x_opencti_created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  x_opencti_external_references: [],
  value: '198.51.100.1',
  resolves_to_refs: [],
  belongs_to_refs: [],
};

