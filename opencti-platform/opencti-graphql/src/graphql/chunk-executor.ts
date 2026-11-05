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
import { booleanConf } from '../config/conf';
import bytes from 'bytes';
import nconf from 'nconf';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { DEFAULT_MAX_UPLOAD_FILE_SIZE } from '../http/httpUtils';
import { isFileValue, uploadFilesOf, withUploads } from '../intake/file-values';
import { pruneResponseConnections } from './chunk-document-prune';
import type { AuthContext } from '../types/user';

export interface ChunkOperation {
  query: string;
  variables?: Record<string, any>;
  operationName?: string;
  // Optional, for diagnostics only: the STIX id the operation carries.
  object_id?: string | null;
  // Set on a PRODUCER: a pycti pre-created sub-object (label, external reference, kill
  // chain phase) whose platform id the following operations reference through this echo
  // id. The manager executes producers first and substitutes the real ids.
  echo_id?: string;
}

// Replace, in place, every string equal to a resolved echo id by the real platform id.
export const substituteEchoIds = (value: any, resolved: Map<string, string>): any => {
  if (isFileValue(value)) return value;
  if (typeof value === 'string') {
    return resolved.get(value) ?? value;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      value[i] = substituteEchoIds(value[i], resolved);
    }
    return value;
  }
  if (value !== null && typeof value === 'object') {
    Object.keys(value).forEach((key) => {
      value[key] = substituteEchoIds(value[key], resolved);
    });
    return value;
  }
  return value;
};

// pycti emits a small, stable set of ingestion mutations (~30 documents): the cache turns
// parse + validate into a startup cost instead of a per-object one.
const documentCache = new LRUCache<string, DocumentNode>({ max: 200 });

// The chunk manager reads nothing of a response but its errors and the root id, yet pycti's
// documents select paginated connections (indicatorAdd { observables { edges ... } },
// stixCyberObservableAdd { indicators { edges ... } }): each resolves a regardingOf listing
// (2+ engine searches per object), and every intent of a batch settles at the same commit, so
// those listings fire together. Measured 2026-09-25 on the full mix at max_batch_size 400:
// 62,310 search rejections at intake start, the long stacks ending in these resolvers. The
// connections are pruned from the chunk documents (the HTTP path is untouched).
const PRUNE_RESPONSE_CONNECTIONS = booleanConf('chunk_intake_manager:prune_response_connections', true);

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
  let executable = document;
  if (PRUNE_RESPONSE_CONNECTIONS) {
    const pruned = pruneResponseConnections(document);
    // a selection set left empty by the pruning is invalid: keep the original then
    if (pruned !== document && validate(createSchema(), pruned).length === 0) executable = pruned;
  }
  documentCache.set(query, executable);
  return executable;
};

// The per-file limit of the HTTP edge (graphqlUploadExpress maxFileSize, httpUtils.ts): a file over
// it is refused in process too, the operation fails as the worker's request did (413)
const MAX_UPLOAD_FILE_SIZE = bytes.parse(nconf.get('app:max_upload_file_size') || DEFAULT_MAX_UPLOAD_FILE_SIZE) ?? (bytes.parse(DEFAULT_MAX_UPLOAD_FILE_SIZE) as number);

// Resolves when the operation is DONE, which for a sequencer-eligible write means after the
// batch commit (the boundary awaits the intent): the caller can tie the chunk ack to it.
// The files of an in-process operation (UploadFile) reach the resolvers as the Upload a multipart
// request gives them (file-values.ts).
export const executeChunkOperation = async (context: AuthContext, operation: ChunkOperation): Promise<ExecutionResult> => {
  const tooLarge = uploadFilesOf(operation.variables).filter((file) => file.data.length > MAX_UPLOAD_FILE_SIZE);
  if (tooLarge.length > 0) {
    return { errors: [FunctionalError('File too large for upload', { files: tooLarge.map((file) => file.name), limit: MAX_UPLOAD_FILE_SIZE })] };
  }
  const document = chunkOperationDocument(operation.query);
  return execute({
    schema: createSchema(),
    document,
    contextValue: context,
    variableValues: (withUploads(operation.variables ?? {}) as Record<string, any>),
    operationName: operation.operationName,
  });
};

// A read of the transformation (worker-less intake: vocabularies, categories...): the same
// in-process execution, its document never pruned (the answer is what the transformation reads)
const readDocumentCache = new LRUCache<string, DocumentNode>({ max: 200 });
export const executeInProcessRead = async (context: AuthContext, query: string, variables: Record<string, any> = {}): Promise<ExecutionResult> => {
  let document = readDocumentCache.get(query);
  if (!document) {
    document = parse(query);
    const errors = validate(createSchema(), document);
    if (errors.length > 0) {
      throw UnsupportedError('Invalid read document', { errors: errors.map((e) => e.message) });
    }
    readDocumentCache.set(query, document);
  }
  return execute({ schema: createSchema(), document, contextValue: context, variableValues: variables });
};
