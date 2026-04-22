import type { StoreCyberObservable } from '../../../../../src/types/store';

export const MEDIA_CONTENT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000057',
  standard_id: 'media-content--20000000-0000-4000-8000-000000000057',
  entity_type: 'Media-Content',
  defanged: false,
  url: 'https://t.me/noname05716/5077',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_MEDIA_CONTENT = {
  id: 'media-content--20000000-0000-4000-8000-000000000057',
  type: 'media-content',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000057',
  x_opencti_type: 'Media-Content',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  url: 'https://t.me/noname05716/5077',
  labels: [],
  external_references: [],
};

