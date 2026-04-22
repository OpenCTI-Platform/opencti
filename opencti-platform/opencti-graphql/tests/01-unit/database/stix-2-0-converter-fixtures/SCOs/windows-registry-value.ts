import type { StoreCyberObservable } from '../../../../../src/types/store';

export const WINDOWS_REGISTRY_VALUE_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000052',
  standard_id: 'windows-registry-value-type--20000000-0000-4000-8000-000000000052',
  entity_type: 'Windows-Registry-Value-Type',
  defanged: false,
  name: '3',
  data: '1',
  data_type: '2',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_WINDOWS_REGISTRY_VALUE = {
  id: 'windows-registry-value-type--20000000-0000-4000-8000-000000000052',
  type: 'windows-registry-value-type',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000052',
  x_opencti_type: 'Windows-Registry-Value-Type',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  name: '3',
  data: '1',
  data_type: '2',
};

