// POC ingestion sequencer (plan 0009, Stage D6). Identity-change barrier registry: the
// functions that change identities (mergeEntities, elUpdateConnectionsOfElement,
// elRawUpdateByQuery, the delete path) call sequencerIdentityBarrier at their entry with the
// involved ids (undefined = unknown scope, the map clears entirely). The identity map
// registers itself at load. Zero imports on purpose: engine.ts and middleware.ts can call
// this without any cycle risk. In Stage E the barrier additionally commits the pending write
// buffer; in Stage D there is no buffer yet, eviction is the whole contract.
type BarrierFn = (ids?: string[]) => void;

let barrierFn: BarrierFn | null = null;

export const registerSequencerBarrier = (fn: BarrierFn) => {
  barrierFn = fn;
};

export const sequencerIdentityBarrier = (ids?: string[]) => {
  if (barrierFn) barrierFn(ids);
};
