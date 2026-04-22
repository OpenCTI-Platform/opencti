import type { StoreEntity } from '../../../../../../src/types/store';

export const INDICATOR_INSTANCE = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  standard_id: 'indicator--d5e8a68e-59d8-524f-9a9a-7c2c1cadf2ff',
  entity_type: 'Indicator',
  created: '2025-08-01T10:00:00.000Z',
  modified: '2025-08-01T12:00:00.000Z',
  confidence: 85,
  revoked: false,
  name: 'Indicator Stix 2.0',
  description: 'Malicious IP indicator',
  indicator_types: [
    'malicious-activity',
  ],
  pattern: "[ipv4-addr:value = '198.51.100.1']",
  pattern_type: 'stix',
  pattern_version: '2.1',
  valid_from: '2025-08-01T10:00:00.000Z',
  valid_until: '2026-08-01T10:00:00.000Z',
  x_opencti_score: 75,
  x_opencti_detection: true,
  x_opencti_main_observable_type: 'IPv4-Addr',
  x_mitre_platforms: [
    'linux',
  ],
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

export const EXPECTED_INDICATOR = {
  id: 'indicator--d5e8a68e-59d8-524f-9a9a-7c2c1cadf2ff',
  spec_version: '2.0',
  revoked: false,
  confidence: 85,
  created: '2025-08-01T10:00:00.000Z',
  modified: '2025-08-01T12:00:00.000Z',
  name: 'Indicator Stix 2.0',
  description: 'Malicious IP indicator',
  indicator_types: [
    'malicious-activity',
  ],
  pattern: "[ipv4-addr:value = '198.51.100.1']",
  pattern_type: 'stix',
  pattern_version: '2.1',
  valid_from: '2025-08-01T10:00:00.000Z',
  valid_until: '2026-08-01T10:00:00.000Z',
  x_opencti_score: 75,
  x_opencti_detection: true,
  x_opencti_main_observable_type: 'IPv4-Addr',
  x_mitre_platforms: [
    'linux',
  ],
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
  x_opencti_id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  x_opencti_type: 'Indicator',
  type: 'indicator',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  x_opencti_files: [],
  x_opencti_granted_refs: [],
};
