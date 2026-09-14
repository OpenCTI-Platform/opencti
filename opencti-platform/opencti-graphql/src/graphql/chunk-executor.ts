// POC chunk-queue direct intake (kb note opencti-chunk-queue-direct-intake-design), graft
// option B: execute a worker chunk's GraphQL operations IN PROCESS, with no HTTP leg. Everything
// below the executor is untouched (validation of the document, variable coercion including the
// StixRef scalar, auth directive, resolvers, sequencer boundary), which is exactly why option B
// is the POC choice: zero behavior divergence against the HTTP path for the same operations.
//
// What the HTTP path adds that this one does not: the Apollo plugins (constraint-directive
// argument validation, request logging, armor). Ingestion mutations are produced by pycti, not
// by a client we defend against; the POC measures the transport, so those stay out for now
// (option B', the operation registry, is where this becomes a contract question).
import { execute, parse, validate } from 'graphql';
import type { DocumentNode, ExecutionResult } from 'graphql';
import { LRUCache } from 'lru-cache';
import createSchema from './schema';
import { UnsupportedError } from '../config/errors';
import type { AuthContext } from '../types/user';

export interface ChunkOperation {
  query: string;
  variables?: Record<string, any>;
  operationName?: string;
  // Optional, for diagnostics only: the STIX id the operation carries.
  object_id?: string;
}

// pycti emits a small, stable set of ingestion mutations (~30 documents): the cache turns
// parse + validate into a startup cost instead of a per-object one.
const documentCache = new LRUCache<string, DocumentNode>({ max: 200 });

export const chunkOperationDocument = (query: string): DocumentNode => {
  const cached = documentCache.get(query);
  if (cached) {
    return cached;
  }
  const document = parse(query);
  const errors = validate(createSchema(), document);
  if (errors.length > 0) {
    throw UnsupportedError('Invalid chunk operation document', { errors: errors.map((e) => e.message) });
  }
  documentCache.set(query, document);
  return document;
};

// Resolves when the operation is DONE, which for a sequencer-eligible write means after the
// batch commit (the boundary awaits the intent): the caller can tie the chunk ack to it.
export const executeChunkOperation = async (context: AuthContext, operation: ChunkOperation): Promise<ExecutionResult> => {
  const document = chunkOperationDocument(operation.query);
  return execute({
    schema: createSchema(),
    document,
    contextValue: context,
    variableValues: operation.variables ?? {},
    operationName: operation.operationName,
  });
};
