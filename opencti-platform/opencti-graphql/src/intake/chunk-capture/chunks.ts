import type { ChunkOperation } from '../../graphql/chunk-executor';
import { ECHO_PREFIX } from './capture-client';

// The worker's chunk building (opencti-worker/src/push_handler.py mark_member_refs,
// chunk_transport.py build_chunks), the same rules so that the chunks are the same.

export const MEMBER_REF_MARK = '||M||';

// Suffix every ref pointing to an object of the same bundle with ||M|| ("travels with me"):
// the manager strips it at its write boundary and knows the producer is in flight, so a missing
// ref is deferred instead of failed. In place, on the split objects.
export const markMemberRefs = (node: unknown, memberIds: Set<string>) => {
  if (Array.isArray(node)) {
    node.forEach((item) => markMemberRefs(item, memberIds));
    return;
  }
  if (node === null || typeof node !== 'object') {
    return;
  }
  const record = node as Record<string, unknown>;
  Object.entries(record).forEach(([key, value]) => {
    const isRefKey = key.endsWith('_ref') || key.endsWith('_refs');
    if (isRefKey && typeof value === 'string') {
      if (memberIds.has(value)) {
        record[key] = value + MEMBER_REF_MARK;
      }
    } else if (isRefKey && Array.isArray(value)) {
      record[key] = value.map((item) => (typeof item === 'string' && memberIds.has(item) ? item + MEMBER_REF_MARK : item));
    } else if (value !== null && typeof value === 'object') {
      markMemberRefs(value, memberIds);
    }
  });
};

const collectEchoRefs = (value: unknown, refs: Set<string>) => {
  if (typeof value === 'string') {
    if (value.startsWith(ECHO_PREFIX)) {
      refs.add(value);
    }
  } else if (Array.isArray(value)) {
    value.forEach((item) => collectEchoRefs(item, refs));
  } else if (value !== null && typeof value === 'object') {
    Object.values(value).forEach((item) => collectEchoRefs(item, refs));
  }
};

// Group the operations into chunks of `size` OBJECTS, in capture order. Producers do not count,
// and every chunk carries the producers its operations reference, even those captured in an
// earlier chunk (repeating an idempotent upsert is safe, a dangling echo fails the object). An
// echo no operation produces goes to `dangling`: it can only come from another message.
export const buildChunks = (operations: ChunkOperation[], size: number, dangling?: Set<string>): ChunkOperation[][] => {
  const producers = new Map(operations.filter((operation) => operation.echo_id).map((operation) => [operation.echo_id as string, operation]));
  const chunks: ChunkOperation[][] = [];
  let current: ChunkOperation[] = [];
  let currentEchoes = new Set<string>();
  let objectsInCurrent = 0;
  const closeCurrent = () => {
    if (current.length > 0) {
      chunks.push(current);
    }
    current = [];
    currentEchoes = new Set();
    objectsInCurrent = 0;
  };
  operations.forEach((operation) => {
    if (operation.echo_id) {
      if (!currentEchoes.has(operation.echo_id)) {
        current.push(operation);
        currentEchoes.add(operation.echo_id);
      }
      return;
    }
    if (objectsInCurrent >= size) {
      closeCurrent();
    }
    const refs = new Set<string>();
    collectEchoRefs(operation.variables, refs);
    refs.forEach((echoId) => {
      const producer = producers.get(echoId);
      if (!producer) {
        dangling?.add(echoId);
      } else if (!currentEchoes.has(echoId)) {
        current.push(producer);
        currentEchoes.add(echoId);
      }
    });
    current.push(operation);
    objectsInCurrent += 1;
  });
  closeCurrent();
  return chunks;
};

export interface ChunkContent {
  operations: ChunkOperation[];
  // Objects this chunk reports to the work: an object is reported by the first chunk it is in
  work_objects: number;
}

export const chunkContents = (operations: ChunkOperation[], size: number, dangling?: Set<string>): ChunkContent[] => {
  const accounted = new Set<string>();
  return buildChunks(operations, size, dangling).map((chunkOperations) => {
    const objects = new Set(chunkOperations.filter((operation) => operation.object_id && !operation.echo_id).map((operation) => operation.object_id as string));
    const reported = [...objects].filter((objectId) => !accounted.has(objectId));
    reported.forEach((objectId) => accounted.add(objectId));
    return { operations: chunkOperations, work_objects: reported.length };
  });
};
