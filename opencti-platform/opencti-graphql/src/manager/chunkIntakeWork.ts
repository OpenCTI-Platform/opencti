// Work accounting of a chunk (ADR 0007). A work expects one report per OBJECT, and a chunk
// carries several operations per object (pycti's pre-created labels, external references and
// kill chain phases are producer operations without an object id). The worker tells each chunk
// how many objects it accounts for (`work_objects`: an object is reported by the first chunk it
// appears in), and the bundle's last chunk carries the objects no chunk holds (`work_extra`:
// no mutation, incompatible, too large). The manager reports all of it in ONE call at the ack.
import type { ChunkOperation } from '../graphql/chunk-executor';

export interface ChunkWorkError {
  error: string;
  source: string;
}

export interface ChunkWorkFields {
  work_objects?: number;
  work_extra?: { objects?: number; errors?: ChunkWorkError[] };
}

export interface ChunkOperationResult {
  error?: string;
  deferred?: boolean;
}

export interface ChunkWorkProgress {
  count: number;
  errors: ChunkWorkError[];
  messages: string[];
}

const objectIdOf = (operation: ChunkOperation) => (operation.echo_id ? undefined : operation.object_id);

export const chunkWorkProgress = (
  message: ChunkWorkFields,
  operations: ChunkOperation[],
  results: ChunkOperationResult[],
): ChunkWorkProgress => {
  // An older worker does not send work_objects: fall back to the chunk's distinct objects.
  const distinctObjects = new Set(operations.map(objectIdOf).filter((id): id is string => !!id));
  const objects = typeof message.work_objects === 'number' ? message.work_objects : distinctObjects.size;
  const extraObjects = message.work_extra?.objects ?? 0;
  const errors: ChunkWorkError[] = [];
  const failed = new Set<string>();
  const retained = new Set<string>();
  operations.forEach((operation, index) => {
    const result = results[index] ?? {};
    const objectId = objectIdOf(operation) ?? operation.echo_id ?? `operation-${index}`;
    if (result.deferred) {
      retained.add(objectId);
    } else if (result.error && !failed.has(objectId)) {
      failed.add(objectId);
      errors.push({ error: result.error, source: `chunk intake: ${objectId}` });
    }
  });
  errors.push(...(message.work_extra?.errors ?? []));
  // Retained creations are counted now (their chunk is done); an expiry adds an error later.
  const messages = retained.size > 0 ? [`${retained.size} creations awaiting references`] : [];
  return { count: objects + extraObjects, errors, messages };
};
