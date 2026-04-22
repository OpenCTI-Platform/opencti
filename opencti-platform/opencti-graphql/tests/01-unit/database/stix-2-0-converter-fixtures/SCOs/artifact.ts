import type { StoreCyberObservable } from '../../../../../src/types/store';

export const ARTIFACT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000038',
  standard_id: 'artifact--20000000-0000-4000-8000-000000000038',
  entity_type: 'Artifact',
  defanged: false,
  mime_type: 'application/pdf',
  hashes: { 'SHA-256': 'abcdef1234567890' },
  x_opencti_additional_names: ['report.pdf'],
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_ARTIFACT = {
  id: 'artifact--20000000-0000-4000-8000-000000000038',
  type: 'artifact',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000038',
  x_opencti_type: 'Artifact',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  mime_type: 'application/pdf',
  hashes: { 'SHA-256': 'abcdef1234567890' },
  x_opencti_additional_names: ['report.pdf'],
};

