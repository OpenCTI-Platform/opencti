import type { ChunkOperation } from '../../graphql/chunk-executor';
import { ECHO_PREFIX } from '../chunk-capture/capture-client';
import { MEMBER_REF_MARK } from '../chunk-capture/chunks';
import { describeOperation } from '../dry-intake/simulated-answers';
import { isFileValue } from '../file-values';
import { shouldHandleHasCoveredRel } from '../../modules/securityCoverage/securityCoverage-utils';

// The operations of a push message as a dependency graph (worker-less intake, KB note
// opencti-workerless-intake-target-design §4.1). The capture answers a creation with its STIX id
// and a pre-created sub-object (label, external reference...) with an echo id, so an operation
// references what it depends on by one of them: an echo id, a member ref marked ||M|| by the
// split, or the plain STIX id of an object created earlier in the message (pycti passes the id
// it got back, e.g. reportEdit relationAdd toId). An operation depends on the first operation of
// the message that creates (or produces) each id it references.
//
// Capture order is a topological order: pycti imports a split bundle after the ones it depends
// on and creates a sub-object before using it. A reference to a LATER operation can only be a
// soft ref of a cycle (a report referencing a note that references it): it is not an edge, the
// sequencer's strip-and-reconcile handles it as any missing soft ref.

// What an operation needs from the operations it depends on before it starts:
// - sequenced: a creation the sequencer intercepts, its references are resolved inside the batch,
//   so its producers only need to be QUEUED (FIFO puts them in the same batch or an earlier one);
// - direct: an operation that reads or writes its targets outside the sequencer (edits, ref adds,
//   addStixRefRelationship, deletions, merges, file pushes), its producers must be WRITTEN.
// Anything not known as a sequenced creation is direct: waiting for the write is always correct.
export type OperationKind = 'sequenced' | 'direct';

// Creations whose domain reads their references before the sequencer boundary
// (stixRefRelationship.js: the from and to are loaded before createRelation)
const DIRECT_CREATIONS = new Set(['stixRefRelationshipAdd']);

export const operationKindOf = (operation: ChunkOperation): OperationKind => {
  const { root, sub } = describeOperation(operation.query);
  if (sub !== null || !root.endsWith('Add') || DIRECT_CREATIONS.has(root)) return 'direct';
  // A has-covered from a security coverage loads it and its results before createRelation
  // (stixCoreRelationship.js, transformHasCoveredFromId); the ||M|| suffix keeps the prefix test
  const input = operation.variables?.input;
  if (root === 'stixCoreRelationshipAdd' && typeof input?.fromId === 'string' && shouldHandleHasCoveredRel(input)) return 'direct';
  return 'sequenced';
};

export interface OperationNode {
  operation: ChunkOperation;
  kind: OperationKind;
  // Indexes of the operations it depends on, all earlier in capture order
  deps: number[];
  // The STIX ids it creates first in the message
  creates: string[];
  // The STIX ids it references and no operation of the message creates (another message may)
  external: string[];
}

export interface OperationGraph {
  nodes: OperationNode[];
  // Echo ids referenced and produced by no operation of the message
  dangling: string[];
  // Member ids referenced (||M||) and created by no operation of the message (an object whose
  // transformation failed or the split set aside)
  unproduced: string[];
  // References to an operation captured later (a cycle): not edges
  forward: { index: number; id: string }[];
}

const STIX_ID = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const referencedIds = (value: unknown, ids: Set<string>, marked: Set<string>) => {
  if (isFileValue(value)) return;
  if (typeof value === 'string') {
    if (value.endsWith(MEMBER_REF_MARK) && value.length > MEMBER_REF_MARK.length) {
      const id = value.slice(0, -MEMBER_REF_MARK.length);
      ids.add(id);
      marked.add(id);
    } else {
      ids.add(value);
    }
  } else if (Array.isArray(value)) {
    value.forEach((item) => referencedIds(item, ids, marked));
  } else if (value !== null && typeof value === 'object') {
    Object.values(value).forEach((item) => referencedIds(item, ids, marked));
  }
};

export const buildOperationGraph = (operations: ChunkOperation[]): OperationGraph => {
  // The first operation creating each STIX id, producing each echo id
  const firstOf = new Map<string, number>();
  operations.forEach((operation, index) => {
    [operation.object_id, operation.echo_id].forEach((id) => {
      if (id && !firstOf.has(id)) firstOf.set(id, index);
    });
  });
  const dangling = new Set<string>();
  const unproduced = new Set<string>();
  const forward: OperationGraph['forward'] = [];
  const nodes = operations.map((operation, index) => {
    const ids = new Set<string>();
    const marked = new Set<string>();
    referencedIds(operation.variables, ids, marked);
    if (operation.object_id) ids.add(operation.object_id);
    const deps = new Set<number>();
    const external: string[] = [];
    ids.forEach((id) => {
      const producer = firstOf.get(id);
      if (producer === undefined) {
        if (id.startsWith(ECHO_PREFIX)) dangling.add(id);
        else if (marked.has(id)) unproduced.add(id);
        else if (STIX_ID.test(id)) external.push(id);
        return;
      }
      if (producer < index) deps.add(producer);
      else if (producer > index) forward.push({ index, id });
    });
    const creates = operation.object_id && firstOf.get(operation.object_id) === index ? [operation.object_id] : [];
    return { operation, kind: operationKindOf(operation), deps: [...deps].sort((a, b) => a - b), creates, external };
  });
  return { nodes, dangling: [...dangling], unproduced: [...unproduced], forward };
};
