import { describe, expect, it } from 'vitest';
import { groupEventRecords, SequencerWriteBuffer } from '../../../src/database/sequencer/sequencer-write-buffer';
import type { MergedUpdateGroup } from '../../../src/database/sequencer/sequencer-write-buffer';

const updateRecord = (buffer: SequencerWriteBuffer, entityId: string, userId: string, tag: string) => {
  buffer.addUpdateRecord({
    context: { eventId: `ev-${tag}` },
    user: { id: userId },
    previous: { internal_id: entityId, state: `before-${tag}` },
    instance: { internal_id: entityId, state: `after-${tag}` },
    changes: [{ message: tag }],
    opts: {},
  });
};

describe('sequencer write buffer (plan 0009 E1/E4/E8)', () => {
  it('accumulates index calls, update ops and events, and reports emptiness', () => {
    const buffer = new SequencerWriteBuffer();
    expect(buffer.isEmpty).toBe(true);
    buffer.addIndexCall('stix-entities', [{ _index: 'idx', internal_id: 'a' }]);
    buffer.addUpdateOp({ index: 'idx', id: 'b', body: { doc: {} }, retry: 3 });
    buffer.addBuiltEvent({ type: 'create' });
    expect(buffer.isEmpty).toBe(false);
    expect(buffer.indexCalls.length).toBe(1);
    expect(buffer.updateOps.length).toBe(1);
    expect(buffer.events.length).toBe(1);
  });

  it('keeps built events in application order', () => {
    const buffer = new SequencerWriteBuffer();
    buffer.addBuiltEvent({ type: 'create', id: 1 });
    buffer.addBuiltEvent({ type: 'create', id: 2 });
    const plan = groupEventRecords(buffer.events);
    expect(plan.map((p: any) => p.event?.id)).toEqual([1, 2]);
  });

  it('merges update records of the same (entity, user): previous of first, current of last (E8)', () => {
    const buffer = new SequencerWriteBuffer();
    updateRecord(buffer, 'ent-1', 'u1', 'first');
    updateRecord(buffer, 'ent-1', 'u1', 'second');
    updateRecord(buffer, 'ent-1', 'u1', 'third');
    const plan = groupEventRecords(buffer.events);
    expect(plan.length).toBe(1);
    const merged = plan[0] as MergedUpdateGroup;
    expect(merged.kind).toBe('merged');
    expect(merged.previous.state).toBe('before-first');
    expect(merged.instance.state).toBe('after-third');
    expect(merged.changes.map((c: any) => c.message)).toEqual(['first', 'second', 'third']);
    expect(merged.merged).toBe(2);
  });

  it('never merges across entities or across users', () => {
    const buffer = new SequencerWriteBuffer();
    updateRecord(buffer, 'ent-1', 'u1', 'a');
    updateRecord(buffer, 'ent-2', 'u1', 'b');
    updateRecord(buffer, 'ent-1', 'u2', 'c');
    const plan = groupEventRecords(buffer.events);
    expect(plan.length).toBe(3);
    expect(plan.every((p: any) => p.merged === 0)).toBe(true);
  });

  it('emits a merged group at its LAST constituent position, after interleaved built events', () => {
    const buffer = new SequencerWriteBuffer();
    updateRecord(buffer, 'ent-1', 'u1', 'first'); // seq 1
    buffer.addBuiltEvent({ type: 'create', id: 'x' }); // seq 2
    updateRecord(buffer, 'ent-1', 'u1', 'last'); // seq 3
    const plan = groupEventRecords(buffer.events);
    expect(plan.length).toBe(2);
    expect((plan[0] as any).event?.id).toBe('x');
    const merged = plan[1] as MergedUpdateGroup;
    expect(merged.kind).toBe('merged');
    expect(merged.previous.state).toBe('before-first');
    expect(merged.instance.state).toBe('after-last');
  });
});
