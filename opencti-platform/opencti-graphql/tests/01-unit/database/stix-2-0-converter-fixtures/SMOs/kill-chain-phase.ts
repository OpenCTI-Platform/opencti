import type { StoreEntity } from '../../../../../src/types/store';

export const KILL_CHAIN_PHASE_INSTANCE = {
  id: 'e05e3f45-eb3c-485d-a86b-50e48f9a4dce',
  entity_type: 'Kill-Chain-Phase',
  standard_id: 'kill-chain-phase--498ccf4c-2534-5534-83cd-9a3c61a4f287',
  kill_chain_name: 'mitre-pre-attack',
  phase_name: 'launch',
  x_opencti_order: 3,
} as unknown as StoreEntity;

export const EXPECTED_KILL_CHAIN_PHASE = {
  id: 'kill-chain-phase--498ccf4c-2534-5534-83cd-9a3c61a4f287',
  type: 'kill-chain-phase',
  spec_version: '2.0',
  kill_chain_name: 'mitre-pre-attack',
  phase_name: 'launch',
  x_opencti_order: 3,
  x_opencti_id: 'e05e3f45-eb3c-485d-a86b-50e48f9a4dce',
  x_opencti_type: 'Kill-Chain-Phase',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
};
