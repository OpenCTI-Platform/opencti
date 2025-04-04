// External reference
export interface StixInternalExternalReference {
  source_name: string;
  description: string;
  url: string;
  // external_id: string; ?
  // hashes: e.hashes, ?
}

export interface StixInternalKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number,
}
