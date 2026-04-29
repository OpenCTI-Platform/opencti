import type { StoreEntity } from '../../../../../../src/types/store';

export const CAMPAIGN_INSTANCE = {
  id: '11111111-1111-4111-8111-111111111111',
  standard_id: 'campaign--11111111-1111-4111-8111-111111111111',
  entity_type: 'Campaign',
  name: 'Campaign Stix 2.0',
  description: 'campaign description',
  created: '2025-01-01T00:00:00.000Z',
  modified: '2025-01-03T00:00:00.000Z',
  confidence: 80,
  revoked: false,
  aliases: ['camp-1'],
  first_seen: '2025-01-01T00:00:00.000Z',
  last_seen: '2025-01-02T00:00:00.000Z',
  objective: 'credential theft',
  createdBy: { standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024' },
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  objectLabel: [{ value: 'covid-19' }],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
} as unknown as StoreEntity;

export const EXPECTED_CAMPAIGN = {
  id: 'campaign--11111111-1111-4111-8111-111111111111',
  type: 'campaign',
  spec_version: '2.0',
  x_opencti_id: '11111111-1111-4111-8111-111111111111',
  x_opencti_type: 'Campaign',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2025-01-01T00:00:00.000Z',
  modified: '2025-01-03T00:00:00.000Z',
  revoked: false,
  confidence: 80,
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
  name: 'Campaign Stix 2.0',
  description: 'campaign description',
  aliases: ['camp-1'],
  first_seen: '2025-01-01T00:00:00.000Z',
  last_seen: '2025-01-02T00:00:00.000Z',
  objective: 'credential theft',
};
