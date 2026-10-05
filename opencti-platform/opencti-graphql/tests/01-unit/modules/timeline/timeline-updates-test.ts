import { describe, expect, it } from 'vitest';
import { visibleTimelineUpdates } from '../../../../src/modules/timeline/timeline-domain';
import type { TimelineUpdatePayload } from '../../../../src/modules/timeline/timeline-engine';

type Message = { instance: TimelineUpdatePayload };

const message = (changedEventIds: string[]): Message => ({
  instance: { id: 'case', container_id: 'case', update_type: 'manual', changed_event_ids: changedEventIds, updated_at: '2026-10-04T00:00:00.000Z' },
});

// Hands out the queued messages, then waits for the next one until it is closed, like a pub/sub listener
const listener = (queued: Message[]) => {
  let closed = false;
  let release: (() => void) | undefined;
  const source: AsyncIterator<Message> = {
    next: () => {
      const value = queued.shift();
      if (value) return Promise.resolve({ done: false, value });
      if (closed) return Promise.resolve({ done: true, value: undefined });
      return new Promise((resolve) => {
        release = () => resolve({ done: true, value: undefined });
      });
    },
    return: () => {
      closed = true;
      release?.();
      return Promise.resolve({ done: true, value: undefined });
    },
  };
  return { source, isClosed: () => closed };
};

// Stands for the access check: the subscriber cannot read the event 'restricted'
const withoutRestricted = async (update: TimelineUpdatePayload) => {
  const visible = update.changed_event_ids.filter((id) => id !== 'restricted');
  return visible.length > 0 ? { ...update, changed_event_ids: visible } : null;
};

describe('Timeline live updates', () => {
  it('should skip the updates the subscriber cannot read and name only the readable events of the others', async () => {
    const { source } = listener([message(['restricted']), message(['visible', 'restricted'])]);
    const updates = visibleTimelineUpdates(source, withoutRestricted);
    const first = await updates.next();
    expect(first.done).toBe(false);
    expect(first.value.instance.changed_event_ids).toEqual(['visible']);
  });

  it('should go through a long run of unreadable updates and stop at the first readable one', async () => {
    const unreadable = Array.from({ length: 5000 }, () => message(['restricted']));
    const queued = [...unreadable, message(['visible']), message(['later'])];
    const { source } = listener(queued);
    const updates = visibleTimelineUpdates(source, withoutRestricted);
    const first = await updates.next();
    expect(first.value.instance.changed_event_ids).toEqual(['visible']);
    // The update after the readable one is left for the next pull
    expect(queued).toHaveLength(1);
  });

  it('should close the listener at once, even while an update is awaited', async () => {
    const { source, isClosed } = listener([]);
    const updates = visibleTimelineUpdates(source, withoutRestricted);
    const pending = updates.next();
    await updates.return?.();
    expect(isClosed()).toBe(true);
    await expect(pending).resolves.toEqual({ done: true, value: undefined });
  });

  it('should be its own async iterable', () => {
    const { source } = listener([]);
    const updates = visibleTimelineUpdates(source, withoutRestricted);
    expect(updates[Symbol.asyncIterator]()).toBe(updates);
  });
});
