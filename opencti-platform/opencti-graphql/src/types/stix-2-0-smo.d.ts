// External reference
export interface StixInternalExternalReference {
  source_name: string;
  description: string;
  url: string;
  hash: object;
  external_id: string;
}

export interface StixInternalKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number,
}
