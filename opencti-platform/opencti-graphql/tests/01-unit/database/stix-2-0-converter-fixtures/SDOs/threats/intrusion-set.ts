import type { StoreEntity } from '../../../../../../src/types/store';

export const INTRUSION_SET_INSTANCE = {
  id: '22222222-2222-4222-8222-222222222222',
  standard_id: 'intrusion-set--22222222-2222-4222-8222-222222222222',
  entity_type: 'Intrusion-Set',
  name: 'Intrusion Set Stix 2.0',
  description: 'intrusion set description',
  created: '2025-02-01T00:00:00.000Z',
  modified: '2025-02-04T00:00:00.000Z',
  confidence: 65,
  revoked: false,
  aliases: ['iset-1'],
  first_seen: '2025-02-01T00:00:00.000Z',
  last_seen: '2025-02-03T00:00:00.000Z',
  goals: ['disruption'],
  resource_level: 'organization',
  primary_motivation: 'organizational-gain',
  secondary_motivations: ['coercion'],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  objectLabel: [{ value: 'covid-19' }],
  createdBy: { standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024' },
} as unknown as StoreEntity;

export const EXPECTED_INTRUSION_SET = {
  id: 'intrusion-set--22222222-2222-4222-8222-222222222222',
  type: 'intrusion-set',
  spec_version: '2.0',
  x_opencti_id: '22222222-2222-4222-8222-222222222222',
  x_opencti_type: 'Intrusion-Set',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2025-02-01T00:00:00.000Z',
  modified: '2025-02-04T00:00:00.000Z',
  revoked: false,
  confidence: 65,
  labels: [
    'covid-19',
  ],
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  name: 'Intrusion Set Stix 2.0',
  description: 'intrusion set description',
  aliases: ['iset-1'],
  first_seen: '2025-02-01T00:00:00.000Z',
  last_seen: '2025-02-03T00:00:00.000Z',
  goals: ['disruption'],
  resource_level: 'organization',
  primary_motivation: 'organizational-gain',
  secondary_motivations: ['coercion'],
};
