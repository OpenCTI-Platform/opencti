// Chunk-queue intake: producers resolved by standard id (2026-09-24).
//
// pycti pre-creates an object's sub-objects (labels, external references, kill chain phases,
// an author by name, a vocabulary value) through separate mutations and puts the ids the
// platform returned into the object's input. On the capture transport those creates answer
// with an echo id, and the manager used to run them FIRST (a wave per chunk) so the real ids
// could replace the echo ids before the objects ran. That wave is an HTTP inheritance: every
// producer type here has a deterministic standard id, computable from the input alone, and
// once the reference carries that standard id the sequencer does the rest (the producer's
// intent is matched by its candidate ids, ordered before its consumers in the same batch, or
// waited for as an in-chunk member). The whole chunk then runs as ONE wave.
//
// A producer whose standard id cannot be computed (unknown mutation, input the platform
// itself would refuse) keeps the legacy path: executed first, real id substituted.
import { parse } from 'graphql';
import type { OperationDefinitionNode } from 'graphql';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_IDENTITY_SYSTEM } from '../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import type { ChunkOperation } from '../graphql/chunk-executor';

type ProducerShape = { type: string; data: Record<string, any> };

// The id-contributing input of each producer mutation, shaped as the domain layer hands it
// to createEntity (identity classes are fixed by the domain, not sent by pycti).
const identityShape = (type: string, input: Record<string, any>): ProducerShape => ({
  type,
  data: { ...input, identity_class: type === ENTITY_TYPE_IDENTITY_SECTOR ? 'class' : type.toLowerCase() },
});
const PRODUCER_MUTATIONS: Record<string, (input: Record<string, any>) => ProducerShape | null> = {
  labelAdd: (input) => ({ type: ENTITY_TYPE_LABEL, data: input }),
  externalReferenceAdd: (input) => ({ type: ENTITY_TYPE_EXTERNAL_REFERENCE, data: input }),
  killChainPhaseAdd: (input) => ({ type: ENTITY_TYPE_KILL_CHAIN_PHASE, data: input }),
  vocabularyAdd: (input) => ({ type: ENTITY_TYPE_VOCABULARY, data: input }),
  markingDefinitionAdd: (input) => ({ type: ENTITY_TYPE_MARKING_DEFINITION, data: input }),
  organizationAdd: (input) => identityShape(ENTITY_TYPE_IDENTITY_ORGANIZATION, input),
  individualAdd: (input) => identityShape(ENTITY_TYPE_IDENTITY_INDIVIDUAL, input),
  systemAdd: (input) => identityShape(ENTITY_TYPE_IDENTITY_SYSTEM, input),
  sectorAdd: (input) => identityShape(ENTITY_TYPE_IDENTITY_SECTOR, input),
  identityAdd: (input) => {
    if (typeof input.type !== 'string' || input.type.length === 0) return null;
    const { type, ...rest } = input;
    return identityShape(type, rest);
  },
};

// pycti emits a small, stable set of documents: the root field of each is parsed once.
const rootFieldCache = new Map<string, string | null>();

// Root mutation field of a chunk operation (labelAdd, externalReferenceAdd, ...), null when
// the document is not a single-field mutation.
export const chunkOperationRootField = (operation: ChunkOperation): string | null => {
  const key = `${operation.operationName ?? ''}|${operation.query}`;
  const cached = rootFieldCache.get(key);
  if (cached !== undefined) return cached;
  let root: string | null = null;
  try {
    const document = parse(operation.query);
    const definition = document.definitions.find((d): d is OperationDefinitionNode => d.kind === 'OperationDefinition'
      && d.operation === 'mutation'
      && (!operation.operationName || d.name?.value === operation.operationName));
    const first = definition?.selectionSet.selections[0];
    if (first && first.kind === 'Field') root = first.name.value;
  } catch {
    root = null;
  }
  rootFieldCache.set(key, root);
  return root;
};

// The standard id the platform will give the producer's entity, or null when it cannot be
// computed here (the caller then falls back to executing the producer first).
export const producerStandardId = (operation: ChunkOperation): string | null => {
  const root = chunkOperationRootField(operation);
  if (!root) return null;
  const shape = PRODUCER_MUTATIONS[root];
  if (!shape) return null;
  const input = operation.variables?.input;
  if (input === null || typeof input !== 'object' || Array.isArray(input)) return null;
  try {
    const resolved = shape(input);
    if (!resolved) return null;
    return generateStandardId(resolved.type, resolved.data);
  } catch {
    return null; // the platform would refuse the same input: legacy path, same failure
  }
};

// Echo id -> standard id for every producer of the chunk that can be resolved up front.
export const resolveProducerIds = (operations: ChunkOperation[]): { resolved: Map<string, string>; unresolved: ChunkOperation[] } => {
  const resolved = new Map<string, string>();
  const unresolved: ChunkOperation[] = [];
  operations.forEach((operation) => {
    if (!operation.echo_id) return;
    const standardId = producerStandardId(operation);
    if (standardId) resolved.set(operation.echo_id, standardId);
    else unresolved.push(operation);
  });
  return { resolved, unresolved };
};
