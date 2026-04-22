import type { StoreCyberObservable } from '../../../../../src/types/store';

export const X509_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000039',
  standard_id: 'x509-certificate--20000000-0000-4000-8000-000000000039',
  entity_type: 'X509-Certificate',
  defanged: false,
  is_self_signed: false,
  hashes: { 'SHA-256': 'certHashValue' },
  serial_number: '01:02:03:04',
  issuer: 'CN=Evil CA',
  subject: 'CN=malware.com',
  validity_not_before: '2025-01-01T00:00:00.000Z',
  validity_not_after: '2026-01-01T00:00:00.000Z',
  subject_public_key_algorithm: 'RSA',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_X509 = {
  id: 'x509-certificate--20000000-0000-4000-8000-000000000039',
  type: 'x509-certificate',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000039',
  x_opencti_type: 'X509-Certificate',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  is_self_signed: false,
  hashes: { 'SHA-256': 'certHashValue' },
  serial_number: '01:02:03:04',
  issuer: 'CN=Evil CA',
  subject: 'CN=malware.com',
  validity_not_before: '2025-01-01T00:00:00.000Z',
  validity_not_after: '2026-01-01T00:00:00.000Z',
  subject_public_key_algorithm: 'RSA',
  x509_v3_extensions: {},
};

