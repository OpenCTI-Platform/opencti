import type { StoreEntity } from '../../../../../../src/types/store';

export const ATTACK_PATTERN_INSTANCE = {
  id: '737e0a89-31dc-4fb0-a224-2e8b91b3816a',
  standard_id: 'attack-pattern--e79f2d1c-4c56-5176-98f3-2c062f49ef4e',
  entity_type: 'Attack-Pattern',
  created: '2026-03-18T09:53:13.663Z',
  modified: '2026-03-18T10:11:36.491Z',
  confidence: 100,
  revoked: false,
  name: 'Attack Pattern STIX 2.0',
  description: 'description',
  x_mitre_id: 'testID',
  x_mitre_platforms: ['android'],
  x_mitre_permissions_required: ['Administrator'],
  x_mitre_detection: 'rule',
  killChainPhases: [
    {
      kill_chain_name: 'kill chain name 1',
      phase_name: 'phase 1',
      x_opencti_order: 1,
    },
  ],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectLabel: [{ value: 'stix 2.0' }],
} as unknown as StoreEntity;

export const EXPECTED_ATTACK_PATTERN = {
  id: 'attack-pattern--e79f2d1c-4c56-5176-98f3-2c062f49ef4e',
  type: 'attack-pattern',
  spec_version: '2.0',
  x_opencti_id: '737e0a89-31dc-4fb0-a224-2e8b91b3816a',
  x_opencti_type: 'Attack-Pattern',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2026-03-18T09:53:13.663Z',
  modified: '2026-03-18T10:11:36.491Z',
  revoked: false,
  confidence: 100,
  labels: ['stix 2.0'],
  object_marking_refs: [],
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [],
  name: 'Attack Pattern STIX 2.0',
  description: 'description',
  aliases: [],
  kill_chain_phases: [
    {
      kill_chain_name: 'kill chain name 1',
      phase_name: 'phase 1',
      x_opencti_order: 1,
    },
  ],
  x_mitre_id: 'testID',
  x_mitre_platforms: ['android'],
  x_mitre_permissions_required: ['Administrator'],
  x_mitre_detection: 'rule',
};
