// POC ingestion sequencer (task 0040 multi-platform, step 1): what the retention stores and the
// loop need when several platforms write (app:ingestion_sequencer:multi_writer). A retention record
// is owned by the node that wrote it: a node rehydrates and sweeps its own records only (and the
// records written before multi_writer, without owner); a producer landing on another node is
// reached by the sweeper. Taking over the records of a dead node is out of the POC.
import { generateStandardId } from '../../schema/identifier';
import { idLabel } from '../../schema/schema-labels';
import { INPUT_EXTERNAL_REFS, INPUT_KILLCHAIN, INPUT_LABELS } from '../../schema/general';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
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

// The keys a LOCK_ERROR of a middleware lock site was refused (LockTimeoutError({ participantIds }))
export const lockErrorKeys = (error: any): string[] => {
  const keys = error?.extensions?.data?.participantIds ?? error?.data?.participantIds;
  return Array.isArray(keys) ? keys.filter((key: unknown): key is string => typeof key === 'string' && key.length > 0) : [];
};

// task 0040 defect 2: two bundles assert the same relation with different start / stop times, so
// different standard ids and different lock keys, while the dedup (same type, from, to within a time
// window, middleware buildExistingRelationsSearch) lands both on one document: concurrent upserts of
// x_opencti_stix_ids replace each other (multi-writer: 29 to 142 stix ids erased per mix285k run, the
// reports citing them lost their refs). The key the dedup can never split: type, from, to (internal
// ids, the search is directional), wider than the dedup window, never narrower.
export const relationDedupLockKey = (relationshipType: string, fromInternalId: string, toInternalId: string) => (
  `relation-dedup:${relationshipType}:${fromInternalId}:${toInternalId}`
);

const STIX_LIKE_ID = /^[a-z][a-z0-9-]*--/;

// Step 2 (narrowed lock): the meta objects an apply may CREATE from its own input, so two platforms
// could create them at once: a label given by its value, an external reference or a kill chain
// phase given as an object. A meta object given by its id already exists (or is created by its own
// intent): the apply only reads it and appends to it, it needs no lock across platforms.
export const creatableNestedIds = (input: Record<string, any>): string[] => {
  const out: string[] = [];
  const labels = input[INPUT_LABELS];
  if (Array.isArray(labels)) {
    labels.forEach((label: unknown) => {
      if (typeof label === 'string' && !STIX_LIKE_ID.test(label)) out.push(idLabel(label));
    });
  }
  const objects = (entries: unknown, type: string) => {
    if (!Array.isArray(entries)) return;
    entries.forEach((entry: unknown) => {
      if (entry === null || typeof entry !== 'object') return;
      try {
        out.push(generateStandardId(type, entry as Record<string, any>));
      } catch {
        // underspecified: the apply fails the same way, before any write
      }
    });
  };
  objects(input[INPUT_EXTERNAL_REFS], ENTITY_TYPE_EXTERNAL_REFERENCE);
  objects(input[INPUT_KILLCHAIN], ENTITY_TYPE_KILL_CHAIN_PHASE);
  return out;
};
