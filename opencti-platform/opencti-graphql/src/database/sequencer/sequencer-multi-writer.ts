// POC ingestion sequencer (task 0040 multi-platform, step 1): what the retention stores and the
// loop need when several platforms write (app:ingestion_sequencer:multi_writer). A retention record
// is owned by the node that wrote it: a node rehydrates and sweeps its own records only (and the
// records written before multi_writer, without owner); a producer landing on another node is
// reached by the sweeper. Taking over the records of a dead node is out of the POC.
import { SEQUENCER_CONFIG } from './sequencer-config';

// The owner field a new record carries, none on a single writer (documents unchanged)
export const recordOwner = (): { node?: string } => (SEQUENCER_CONFIG.multiWriter ? { node: SEQUENCER_CONFIG.nodeId } : {});

export const NODE_FIELD_MAPPING = { node: { type: 'keyword' } };

// The rehydration query of a store: its pending records, on a multi writer those of this node or
// of no node
export const ownedPendingQuery = (multiWriter: boolean, nodeId: string): Record<string, any> => {
  const pending = { term: { status: 'pending' } };
  if (!multiWriter) return pending;
  return {
    bool: {
      filter: [
        pending,
        { bool: { should: [{ term: { node: nodeId } }, { bool: { must_not: { exists: { field: 'node' } } } }], minimum_should_match: 1 } },
      ],
    },
  };
};

// Two platforms starting together both find a store index absent and create it: the second
// creation is refused, the index exists, the store goes on
export const ignoreIndexAlreadyExists = (error: any): null => {
  const type = error?.meta?.body?.error?.type ?? error?.body?.error?.type;
  if (type === 'resource_already_exists_exception' || String(error?.message ?? '').includes('resource_already_exists_exception')) return null;
  throw error;
};
