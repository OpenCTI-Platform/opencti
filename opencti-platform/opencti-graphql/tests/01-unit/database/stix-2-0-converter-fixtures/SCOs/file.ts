import type { StoreCyberObservable } from '../../../../../src/types/store';

export const FILE_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000024',
  standard_id: 'file--20000000-0000-4000-8000-000000000024',
  entity_type: 'StixFile',
  defanged: false,
  hashes: { MD5: 'd41d8cd98f00b204e9800998ecf8427e', 'SHA-256': 'e3b0c44298fc1c149afbf4c8996fb924' },
  size: 1024,
  name: 'malware.exe',
  mime_type: 'application/x-executable',
  x_opencti_additional_names: ['trojan.exe'],
  x_opencti_score: 90,
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
} as unknown as StoreCyberObservable;

export const EXPECTED_FILE = {
  id: 'file--20000000-0000-4000-8000-000000000024',
  type: 'file',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000024',
  x_opencti_type: 'StixFile',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  x_opencti_score: 90,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  hashes: { MD5: 'd41d8cd98f00b204e9800998ecf8427e', 'SHA-256': 'e3b0c44298fc1c149afbf4c8996fb924' },
  size: 1024,
  name: 'malware.exe',
  mime_type: 'application/x-executable',
  contains_refs: [],
  x_opencti_additional_names: ['trojan.exe'],
};

