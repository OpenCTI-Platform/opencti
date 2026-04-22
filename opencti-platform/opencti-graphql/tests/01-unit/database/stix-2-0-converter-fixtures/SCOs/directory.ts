import type { StoreCyberObservable } from '../../../../../src/types/store';

export const DIRECTORY_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000033',
  standard_id: 'directory--20000000-0000-4000-8000-000000000033',
  entity_type: 'Directory',
  defanged: false,
  path: '/etc/malware',
  path_enc: 'utf-8',
  ctime: '2026-01-01T00:00:00.000Z',
  mtime: '2026-01-02T00:00:00.000Z',
  atime: '2026-01-03T00:00:00.000Z',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_DIRECTORY = {
  id: 'directory--20000000-0000-4000-8000-000000000033',
  type: 'directory',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000033',
  x_opencti_type: 'Directory',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  path: '/etc/malware',
  path_enc: 'utf-8',
  ctime: '2026-01-01T00:00:00.000Z',
  mtime: '2026-01-02T00:00:00.000Z',
  atime: '2026-01-03T00:00:00.000Z',
  contains_refs: [],
};

