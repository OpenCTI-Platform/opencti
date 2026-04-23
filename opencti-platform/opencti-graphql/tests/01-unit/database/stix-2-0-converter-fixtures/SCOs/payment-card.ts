import type { StoreCyberObservable } from '../../../../../src/types/store';

export const PAYMENT_CARD_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000061',
  standard_id: 'payment-card--20000000-0000-4000-8000-000000000061',
  entity_type: 'Payment-Card',
  defanged: false,
  card_number: '4111111111111111',
  holder_name: 'John Doe',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_PAYMENT_CARD = {
  id: 'payment-card--20000000-0000-4000-8000-000000000061',
  type: 'payment-card',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000061',
  x_opencti_type: 'Payment-Card',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  card_number: '4111111111111111',
  holder_name: 'John Doe',
  labels: [],
  external_references: [],
};

