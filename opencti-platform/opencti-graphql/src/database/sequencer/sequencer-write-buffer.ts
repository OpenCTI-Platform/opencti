// POC ingestion sequencer (plan 0009, Stage E). Per-batch write buffer, zero-dependency on
// purpose: engine.ts and stream-handler.ts append operations here while a batch is applying
// (guarded by context.sequencer.scope === 'applying' AND the module holder being set by the
// batch loop), and the loop flushes at commit:
//   - E1: elIndexElements calls buffered whole (documents + denormalization side-writes are
//     re-emitted at flush through ONE elIndexElements call, whose existing per-impacted-id
//     grouping then merges side-writes across intents natively); elUpdate calls (the upsert's
//     elReplace scripted update) buffered as raw bulk update operations;
//   - E4: stream events buffered in application order (already-built events as-is, raw update
//     records kept unbuilt so E8 can coalesce them per entity before building);
//   - E8: groupEventRecords merges consecutive-or-not update records of the same
//     (entity, origin user): previous = first touch, current = last touch, changes
//     concatenated; the merged event is emitted at the LAST constituent's position so the
//     final state lands at the final position. Built events and commit-carrying updates are
//     never merged.
// Deletes are NOT buffered in v1 (rare in ingestion; the refresh mass sits on the two create
// bulks): they keep the direct path, documented divergence from E1.

export interface BufferedIndexCall {
  indexingType: string | undefined;
  elements: Record<string, any>[];
}

export interface BufferedUpdateOp {
  index: string;
  id: string;
  body: any;
  retry: number;
}

export interface BuiltEventRecord {
  kind: 'built';
  seq: number;
  event: any;
}

export interface UpdateEventRecord {
  kind: 'update';
  seq: number;
  context: any;
  user: any;
  previous: any;
  instance: any;
  changes: any[];
  opts: any;
}

export type EventRecord = BuiltEventRecord | UpdateEventRecord;

export interface MergedUpdateGroup {
  kind: 'merged';
  seq: number; // position of the LAST constituent
  context: any;
  user: any;
  previous: any; // state at first touch
  instance: any; // state after last touch
  changes: any[];
  opts: any;
  merged: number; // constituents absorbed beyond the first
}

export class SequencerWriteBuffer {
  readonly indexCalls: BufferedIndexCall[] = [];

  readonly updateOps: BufferedUpdateOp[] = [];

  readonly events: EventRecord[] = [];

  private seq = 0;

  private nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  addIndexCall(indexingType: string | undefined, elements: Record<string, any>[]) {
    this.indexCalls.push({ indexingType, elements });
  }

  addUpdateOp(op: BufferedUpdateOp) {
    this.updateOps.push(op);
  }

  addBuiltEvent(event: any) {
    this.events.push({ kind: 'built', seq: this.nextSeq(), event });
  }

  addUpdateRecord(record: Omit<UpdateEventRecord, 'kind' | 'seq'>) {
    this.events.push({ kind: 'update', seq: this.nextSeq(), ...record });
  }

  get isEmpty(): boolean {
    return this.indexCalls.length === 0 && this.updateOps.length === 0 && this.events.length === 0;
  }
}

// E8 grouping, pure: walk the records in order; update records of the same
// (entity internal_id, user id) collapse into one merged group placed at the last
// constituent's seq; built events keep their position. Returns the flush plan, seq-ordered.
export const groupEventRecords = (records: EventRecord[]): (BuiltEventRecord | MergedUpdateGroup)[] => {
  const groups = new Map<string, MergedUpdateGroup>();
  const plan: (BuiltEventRecord | MergedUpdateGroup)[] = [];
  records.forEach((record) => {
    if (record.kind === 'built') {
      plan.push(record);
      return;
    }
    const key = `${record.instance?.internal_id}|${record.user?.id}`;
    const group = groups.get(key);
    if (!group) {
      const merged: MergedUpdateGroup = {
        kind: 'merged',
        seq: record.seq,
        context: record.context,
        user: record.user,
        previous: record.previous,
        instance: record.instance,
        changes: [...record.changes],
        opts: record.opts,
        merged: 0,
      };
      groups.set(key, merged);
      plan.push(merged);
    } else {
      group.seq = record.seq; // moves to the last constituent's position
      group.instance = record.instance;
      group.changes.push(...record.changes);
      group.opts = record.opts;
      group.context = record.context;
      group.merged += 1;
    }
  });
  return plan.sort((a, b) => a.seq - b.seq);
};

// Module holder, set by the batch loop for the duration of one batch's apply+flush. Consumers
// (engine, stream-handler) must ALSO check context.sequencer.scope === 'applying' so that
// non-intent work interleaved on the event loop never lands in the buffer.
let currentBuffer: SequencerWriteBuffer | null = null;
export const setCurrentWriteBuffer = (buffer: SequencerWriteBuffer | null) => {
  currentBuffer = buffer;
};
export const getCurrentWriteBuffer = (): SequencerWriteBuffer | null => currentBuffer;
