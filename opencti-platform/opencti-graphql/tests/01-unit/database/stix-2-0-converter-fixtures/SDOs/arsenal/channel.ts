import type { StoreEntityChannel } from '../../../../../../src/modules/channel/channel-types';

export const CHANNEL_INSTANCE = {
  id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  standard_id: 'channel--6e66b6f7-f60b-50d9-8d6c-6686192695d6',
  entity_type: 'Channel',
  name: 'Channel Stix 2.0',
  description: 'description',
  channel_types: [
    'Facebook',
  ],
  created: '2025-08-01T15:34:01.690Z',
  modified: '2025-08-01T15:36:28.567Z',
  confidence: 100,
  revoked: false,
  objectMarking: [
    {
      standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
    },
  ],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  objectLabel: [
    {
      value: 'covid-19',
    },
  ],
  createdBy: {
    standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  },
} as unknown as StoreEntityChannel;

export const EXPECTED_CHANNEL = {
  id: 'channel--6e66b6f7-f60b-50d9-8d6c-6686192695d6',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-08-01T15:34:01.690Z',
  modified: '2025-08-01T15:36:28.567Z',
  name: 'Channel Stix 2.0',
  aliases: [],
  description: 'description',
  channel_types: [
    'Facebook',
  ],
  labels: [
    'covid-19',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  x_opencti_type: 'Channel',
  type: 'channel',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
  ],
  x_opencti_files: [],
  x_opencti_granted_refs: [],
};
