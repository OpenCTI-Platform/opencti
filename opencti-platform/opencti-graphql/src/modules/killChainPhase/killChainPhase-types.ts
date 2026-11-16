import type { BasicStoreEntity } from '../../types/store';

export interface BasicStoreEntityKillChainPhase extends BasicStoreEntity {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}
