import { randomUUID } from 'node:crypto';
import { DRAFT_LOCKED_ERROR, WORK_NOT_ALIVE_ERROR } from '../../config/errors';
import type { ChunkOperation } from '../../graphql/chunk-executor';
import { captureBundle } from '../chunk-capture/capture-bundle';
import { bundleOf, decodeData } from '../dry-intake/dry-intake-message';
import { type IntakeEnvelope, intakeEnvelopeOfMessage } from '../intake-envelope';
import type { ImportContext } from '../stix-import/context';
import type { ImportClient } from '../stix-import/types';

// The worker-less intake (POC): the platform consumes the connector push queues in place of the
// workers. A push message is decoded as the worker decodes it, its bundle transformed with the
// mutations captured (chunk-capture), the captured operations run in process as the chunks the
// worker would have published, through the chunk intake machinery (the sequencer included). The
// push message is answered once all its chunks are: acked when every chunk is written, nacked
// (not requeued) when one is dead-lettered or when the message cannot be decoded or transformed,
// as the worker nacks it.

// A chunk of a push message: the envelope of the message, its operations
export interface PushChunk extends IntakeEnvelope {
  v: number;
  chunk_id: string;
  operations: ChunkOperation[];
  work_objects: number;
}

// How a chunk ended: written (or refused, acked as the worker skips it), or dead-lettered
export type ChunkVerdict = 'acked' | 'dead_lettered';

export interface PushIntakeDeps {
  // Runs one chunk to its end (the chunk intake manager's processChunk)
  runChunk: (chunk: PushChunk) => Promise<ChunkVerdict>;
  // The transformation's reads for a message, run in process under its context
  readsClient: (envelope: IntakeEnvelope) => ImportClient;
  // The transformation context of a draft, kept for the life of the intake (pycti's caches)
  contextFor: (draftId: string) => ImportContext;
  chunkSize: number;
}

export type PushReason = 'written' | 'undecodable' | 'transformation_failed' | 'chunk_dead_lettered' | 'work_not_alive' | 'draft_locked';

export interface PushOutcome {
  ack: boolean;
  reason: PushReason;
  chunks: number;
  objects: number;
}

// The push message, parsed: the intake reads its type before handling it (an event queue is consumed in order)
export const parsePushMessage = (body: string): Record<string, any> | null => {
  try {
    const data = JSON.parse(body);
    return data !== null && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
};

export const isEventMessage = (data: Record<string, any>) => data.type === 'event';

export const handlePushMessage = async (data: Record<string, any> | null, deps: PushIntakeDeps): Promise<PushOutcome> => {
  if (!data) {
    return { ack: false, reason: 'undecodable', chunks: 0, objects: 0 };
  }
  let decoded: ReturnType<typeof decodeData>;
  let bundle: Record<string, any>;
  let update: boolean;
  try {
    decoded = decodeData(data);
    ({ bundle, update } = bundleOf(decoded));
  } catch {
    return { ack: false, reason: 'undecodable', chunks: 0, objects: 0 };
  }
  const objects = Array.isArray(bundle.objects) ? bundle.objects.length : 0;
  // The worker sends retry number 0 on the first attempt: worker origin (sequencer eligibility)
  const envelope: IntakeEnvelope = { ...intakeEnvelopeOfMessage(data), retry_number: 0 };
  let chunkContents: Awaited<ReturnType<typeof captureBundle>>['chunks'];
  try {
    const context = { ...deps.contextFor(decoded.draftId), client: deps.readsClient(envelope) };
    ({ chunks: chunkContents } = await captureBundle(context, bundle, update, decoded.types, deps.chunkSize, { byLevel: true }));
  } catch (error: any) {
    // A read of the transformation refused by the context checks (the HTTP edge's): a deleted work
    // or a closed draft, skipped as the worker skips it (the chunks report the draft case)
    const code = error?.extensions?.code;
    if (code === WORK_NOT_ALIVE_ERROR) {
      return { ack: true, reason: 'work_not_alive', chunks: 0, objects };
    }
    if (code === DRAFT_LOCKED_ERROR) {
      return { ack: true, reason: 'draft_locked', chunks: 0, objects };
    }
    // The split fails (a malformed message) or the transformation has a defect: the worker nacks
    return { ack: false, reason: 'transformation_failed', chunks: 0, objects };
  }
  const chunks: (PushChunk & { level?: number })[] = chunkContents.map((chunk) => ({
    ...envelope,
    v: 1,
    chunk_id: randomUUID(),
    operations: chunk.operations,
    work_objects: chunk.work_objects,
    level: chunk.level,
  }));
  // Level by level, the chunks of a level at once: a level starts once the previous one is written
  // (a chunk ends after the commit), so an object never runs before its in-bundle dependencies.
  // A dead-lettered chunk does not stop the next levels, as the worker's inline import went on.
  const verdicts: ChunkVerdict[] = [];
  const levels = [...new Set(chunks.map((chunk) => chunk.level ?? 0))];
  for (const level of levels) {
    const levelChunks = chunks.filter((chunk) => (chunk.level ?? 0) === level);
    verdicts.push(...(await Promise.all(levelChunks.map(({ level: _level, ...chunk }) => deps.runChunk(chunk)))));
  }
  const written = verdicts.every((verdict) => verdict === 'acked');
  return { ack: written, reason: written ? 'written' : 'chunk_dead_lettered', chunks: chunks.length, objects };
};

// The bytes of the messages in flight: a message starts once the budget has room for it (alone, it
// always starts). The decoded bundle, its objects, the captured operations and the files are held
// several times over the size of the message: a message count does not bound the memory.
export const createByteBudget = (maxBytes: number) => {
  let inFlight = 0;
  const waiting: { bytes: number; start: () => void }[] = [];
  const startWaiting = () => {
    while (waiting.length > 0 && (inFlight === 0 || inFlight + waiting[0].bytes <= maxBytes)) {
      const next = waiting.shift() as (typeof waiting)[number];
      inFlight += next.bytes;
      next.start();
    }
  };
  return {
    acquire: (bytes: number) => new Promise<void>((resolve) => {
      waiting.push({ bytes, start: resolve });
      startWaiting();
    }),
    release: (bytes: number) => {
      inFlight -= bytes;
      startWaiting();
    },
    inFlight: () => inFlight,
    waiting: () => waiting.length,
  };
};

// The order of a queue: the messages of a queue that carries stream events (create, update, delete,
// merge of the same entities) run one at a time, each once the previous one is written, as a single
// worker consumes a queue (prefetch 1, ack after the write). Other queues run their messages
// concurrently. A queue turns ordered with its first event, after the messages already running.
export const createQueueOrder = () => {
  const ordered = new Map<string, Promise<void>>();
  const running = new Map<string, Set<Promise<void>>>();
  const track = (queue: string, run: Promise<void>) => {
    let set = running.get(queue);
    if (!set) {
      set = new Set();
      running.set(queue, set);
    }
    set.add(run);
    run.finally(() => set?.delete(run)).catch(() => {});
    return run;
  };
  return {
    schedule: (queue: string, isEvent: boolean, handle: () => Promise<void>): Promise<void> => {
      if (isEvent && !ordered.has(queue)) {
        ordered.set(queue, Promise.all([...(running.get(queue) ?? [])]).then(() => undefined, () => undefined));
      }
      const tail = ordered.get(queue);
      if (!tail) {
        return track(queue, handle());
      }
      const next = tail.then(handle);
      ordered.set(queue, next.then(() => undefined, () => undefined));
      return track(queue, next);
    },
    isOrdered: (queue: string) => ordered.has(queue),
  };
};
