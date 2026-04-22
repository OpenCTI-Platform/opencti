import type { StoreCyberObservable } from '../../../../../src/types/store';

export const EMAIL_MIME_PART_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000065',
  standard_id: 'email-mime-part-type--20000000-0000-4000-8000-000000000065',
  entity_type: 'Email-Mime-Part-Type',
  defanged: false,
  content_type: 'text/plain',
  body: 'Hello world',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_EMAIL_MIME_PART = {
  id: 'email-mime-part-type--20000000-0000-4000-8000-000000000065',
  type: 'email-mime-part-type',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000065',
  x_opencti_type: 'Email-Mime-Part-Type',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  content_type: 'text/plain',
  body: 'Hello world',
  labels: [],
  external_references: [],
};

