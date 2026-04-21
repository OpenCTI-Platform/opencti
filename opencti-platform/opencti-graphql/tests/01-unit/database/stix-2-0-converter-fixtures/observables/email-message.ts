import type { StoreCyberObservable } from '../../../../../src/types/store';

export const EMAIL_MESSAGE_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000050',
  standard_id: 'email-message--20000000-0000-4000-8000-000000000050',
  entity_type: 'Email-Message',
  defanged: false,
  is_multipart: false,
  subject: 'Test subject',
  body: '<html>test</html>',
  x_opencti_score: 50,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_EMAIL_MESSAGE = {
  id: 'email-message--20000000-0000-4000-8000-000000000050',
  type: 'email-message',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000050',
  x_opencti_type: 'Email-Message',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 50,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  is_multipart: false,
  subject: 'Test subject',
  body: '<html>test</html>',
  to_refs: [],
  cc_refs: [],
  bcc_refs: [],
  additional_header_fields: {},
  body_multipart: [],
  x_opencti_contains_refs: [],
};

