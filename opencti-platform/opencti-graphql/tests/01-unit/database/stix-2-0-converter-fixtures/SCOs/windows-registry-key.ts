import type { StoreCyberObservable } from '../../../../../src/types/store';

export const WINDOWS_REGISTRY_KEY_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000051',
  standard_id: 'windows-registry-key--20000000-0000-4000-8000-000000000051',
  entity_type: 'Windows-Registry-Key',
  defanged: false,
  attribute_key: 'HKCU\\Software\\Classes\\CLSID\\{84DA0A92}',
  x_opencti_score: 40,
  x_opencti_description: 'COM hijacking',
  objectLabel: [{ value: 'apt' }],
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_WINDOWS_REGISTRY_KEY = {
  id: 'windows-registry-key--20000000-0000-4000-8000-000000000051',
  type: 'windows-registry-key',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000051',
  x_opencti_type: 'Windows-Registry-Key',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 40,
  x_opencti_description: 'COM hijacking',
  x_opencti_labels: ['apt'],
  x_opencti_external_references: [],
  key: 'HKCU\\Software\\Classes\\CLSID\\{84DA0A92}',
  values: [],
};

