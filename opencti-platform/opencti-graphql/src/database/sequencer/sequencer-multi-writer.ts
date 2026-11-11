// POC ingestion sequencer (task 0040 multi-platform, step 1): what the retention stores and the
// loop need when several platforms write (app:ingestion_sequencer:multi_writer). A retention record
// is owned by the node that wrote it: a node rehydrates and sweeps its own records only (and the
// records written before multi_writer, without owner); a producer landing on another node is
// reached by the sweeper. Taking over the records of a dead node is out of the POC.
import { TYPE_LOCK_ERROR } from '../../config/errors';
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

// A lock that could not be taken: the redlock error of an acquisition out of retries (name
// ExecutionError, kept across the lock child process), the LOCK_ERROR the middleware lock sites
// convert it to, or that error once GraphQL replaced it, when it reached the execution as a plain
// object (the lock child's IPC), by "Unexpected error value: { ... LOCK_ERROR ... }" without extensions
const LOCK_ERROR_TEXT = /LOCK_ERROR|too many concurrent call on the same entities/;
export const isLockError = (error: any): boolean => error?.name === TYPE_LOCK_ERROR
  || error?.extensions?.code === 'LOCK_ERROR'
  || LOCK_ERROR_TEXT.test(String(error?.message ?? ''));
