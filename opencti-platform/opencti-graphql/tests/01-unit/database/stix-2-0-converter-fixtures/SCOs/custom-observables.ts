import type { StoreCyberObservable } from '../../../../../src/types/store';

export const HOSTNAME_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000040',
  standard_id: 'hostname--20000000-0000-4000-8000-000000000040',
  entity_type: 'Hostname',
  defanged: false,
  value: 'c2.evil.com',
  x_opencti_description: 'C2 hostname',
  x_opencti_score: 85,
  objectLabel: [{ value: 'malware' }],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_HOSTNAME = {
  id: 'hostname--20000000-0000-4000-8000-000000000040',
  type: 'hostname',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000040',
  x_opencti_type: 'Hostname',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 85,
  x_opencti_description: 'C2 hostname',
  x_opencti_labels: ['malware'],
  x_opencti_created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  x_opencti_external_references: [],
  value: 'c2.evil.com',
  labels: ['malware'],
  description: 'C2 hostname',
  score: 85,
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [],
};

export const CRYPTOCURRENCY_WALLET_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000041',
  standard_id: 'cryptocurrency-wallet--20000000-0000-4000-8000-000000000041',
  entity_type: 'Cryptocurrency-Wallet',
  defanged: false,
  value: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
  x_opencti_score: 90,
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_CRYPTOCURRENCY_WALLET = {
  id: 'cryptocurrency-wallet--20000000-0000-4000-8000-000000000041',
  type: 'cryptocurrency-wallet',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000041',
  x_opencti_type: 'Cryptocurrency-Wallet',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_score: 90,
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
  labels: [],
  score: 90,
  external_references: [],
};

export const BANK_ACCOUNT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000042',
  standard_id: 'bank-account--20000000-0000-4000-8000-000000000042',
  entity_type: 'Bank-Account',
  defanged: false,
  iban: 'DE89370400440532013000',
  bic: 'COBADEFFXXX',
  account_number: '0532013000',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_BANK_ACCOUNT = {
  id: 'bank-account--20000000-0000-4000-8000-000000000042',
  type: 'bank-account',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000042',
  x_opencti_type: 'Bank-Account',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  iban: 'DE89370400440532013000',
  bic: 'COBADEFFXXX',
  account_number: '0532013000',
  labels: [],
  external_references: [],
};

export const PHONE_NUMBER_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000043',
  standard_id: 'phone-number--20000000-0000-4000-8000-000000000043',
  entity_type: 'Phone-Number',
  defanged: false,
  value: '+33612345678',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_PHONE_NUMBER = {
  id: 'phone-number--20000000-0000-4000-8000-000000000043',
  type: 'phone-number',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000043',
  x_opencti_type: 'Phone-Number',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: '+33612345678',
  labels: [],
  external_references: [],
};

export const PERSONA_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000044',
  standard_id: 'persona--20000000-0000-4000-8000-000000000044',
  entity_type: 'Persona',
  defanged: false,
  persona_name: 'DarkOperator',
  persona_type: 'social-media',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_PERSONA = {
  id: 'persona--20000000-0000-4000-8000-000000000044',
  type: 'persona',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000044',
  x_opencti_type: 'Persona',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  persona_name: 'DarkOperator',
  persona_type: 'social-media',
  labels: [],
  external_references: [],
};

