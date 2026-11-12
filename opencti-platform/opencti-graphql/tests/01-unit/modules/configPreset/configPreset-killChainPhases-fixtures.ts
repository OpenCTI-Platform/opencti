import type { BasicStoreEntityKillChainPhase } from '../../../../src/modules/killChainPhase/killChainPhase-types';

export const killChainPhase = {
  id: 'phase-id',
  internal_id: 'phase-id',
  standard_id: 'kill-chain-phase--4c3b2a19-8e7d-5f6a-9b0c-1d2e3f4a5b6c',
  entity_type: 'Kill-Chain-Phase',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  kill_chain_name: 'mitre-attack',
  phase_name: 'execution',
  x_opencti_order: 2,
} as unknown as BasicStoreEntityKillChainPhase;

export const otherKillChainPhase = {
  ...killChainPhase,
  id: 'other-phase-id',
  internal_id: 'other-phase-id',
  standard_id: 'kill-chain-phase--7e6d5c4b-3a29-5180-9f8e-7d6c5b4a3921',
  phase_name: 'initial-access',
  x_opencti_order: 1,
} as unknown as BasicStoreEntityKillChainPhase;

export const disarmKillChainPhase = {
  ...killChainPhase,
  id: 'disarm-phase-id',
  internal_id: 'disarm-phase-id',
  standard_id: 'kill-chain-phase--0a1b2c3d-4e5f-5061-8273-94a5b6c7d8e9',
  kill_chain_name: 'disarm',
  phase_name: 'plan-strategy',
  x_opencti_order: 0,
} as unknown as BasicStoreEntityKillChainPhase;

// By kill chain, then by order in the kill chain
export const ALL_KILL_CHAIN_PHASES = [killChainPhase, otherKillChainPhase, disarmKillChainPhase];
