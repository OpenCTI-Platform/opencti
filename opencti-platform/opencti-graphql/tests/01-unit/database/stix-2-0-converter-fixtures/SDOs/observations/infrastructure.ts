import type { StoreEntity } from '../../../../../../src/types/store';

export const INFRASTRUCTURE_INSTANCE = {
  id: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
  standard_id: 'infrastructure--ae4b2f9c-3e7d-5a1f-8b9c-2d4e6f8a0b1c',
  entity_type: 'Infrastructure',
  created: '2025-08-01T14:00:00.000Z',
  modified: '2025-08-01T16:00:00.000Z',
  confidence: 90,
  revoked: false,
  name: 'Infrastructure Stix 2.0',
  description: 'C2 server infrastructure',
  infrastructure_types: [
    'command-and-control',
  ],
  aliases: [
    'C2-Infra-Alpha',
  ],
  first_seen: '2025-06-01T00:00:00.000Z',
  last_seen: '2025-08-01T00:00:00.000Z',
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  killChainPhases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      x_opencti_order: 0,
    },
  ],
  objectMarking: [
    {
      standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
    },
  ],
  createdBy: {
    standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  },
  objectLabel: [
    {
      value: 'ryuk',
    },
  ],
} as unknown as StoreEntity;

export const EXPECTED_INFRASTRUCTURE = {
  id: 'infrastructure--ae4b2f9c-3e7d-5a1f-8b9c-2d4e6f8a0b1c',
  spec_version: '2.0',
  revoked: false,
  confidence: 90,
  created: '2025-08-01T14:00:00.000Z',
  modified: '2025-08-01T16:00:00.000Z',
  name: 'Infrastructure Stix 2.0',
  description: 'C2 server infrastructure',
  infrastructure_types: [
    'command-and-control',
  ],
  aliases: [
    'C2-Infra-Alpha',
  ],
  first_seen: '2025-06-01T00:00:00.000Z',
  last_seen: '2025-08-01T00:00:00.000Z',
  labels: [
    'ryuk',
  ],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      x_opencti_order: 0,
    },
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
  x_opencti_type: 'Infrastructure',
  type: 'infrastructure',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  x_opencti_files: [],
  x_opencti_granted_refs: [],
};
