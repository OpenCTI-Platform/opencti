import { describe, expect, it } from 'vitest';
import { buildUpdateEventContext } from '../../../src/manager/notificationManager';
import type { DataEvent, SseEvent } from '../../../src/types/event';

const buildUpdateStreamEvent = () => {
  const data = {
    id: 'report--0a1b2c3d-0000-4000-8000-000000000001',
    type: 'report',
    name: 'current name',
    confidence: 80,
    labels: ['alpha', 'beta'],
  };
  return {
    id: '1790263557612-0',
    event: 'update',
    data: {
      type: 'update',
      data,
      message: 'updates the name',
      origin: {},
      commit: undefined,
      context: {
        patch: [{ op: 'replace', path: '/name', value: 'current name' }],
        reverse_patch: [{ op: 'replace', path: '/name', value: 'previous name' }],
        changes: [{ field: 'Report--name' }],
      },
    },
  } as unknown as SseEvent<DataEvent>;
};

describe.concurrent('notification manager update event context', () => {
  it('should rebuild the previous document from the reverse patch', async () => {
    const streamEvent = buildUpdateStreamEvent();
    const { previous } = buildUpdateEventContext(streamEvent);
    expect((previous as any).name).toEqual('previous name');
    expect((previous as any).confidence).toEqual(80);
    expect((previous as any).labels).toEqual(['alpha', 'beta']);
  });

  it('should extract the changed attributes of the event', async () => {
    const streamEvent = buildUpdateStreamEvent();
    const { eventContext } = buildUpdateEventContext(streamEvent);
    expect(eventContext.changedAttributes).toEqual(['name']);
  });

  it('should leave the live event payload untouched', async () => {
    const streamEvent = buildUpdateStreamEvent();
    const before = structuredClone(streamEvent.data.data);
    buildUpdateEventContext(streamEvent);
    expect(streamEvent.data.data).toEqual(before);
  });

  it('should return a document that shares no reference with the live payload', async () => {
    const streamEvent = buildUpdateStreamEvent();
    const { previous } = buildUpdateEventContext(streamEvent);
    const live = streamEvent.data.data as any;
    expect(previous).not.toBe(live);
    expect((previous as any).labels).not.toBe(live.labels);
  });

  // Hoisting one context out of the trigger loop is only valid if building it once
  // is indistinguishable from building it per trigger.
  it('should be deterministic so a single context can be reused across triggers', async () => {
    const streamEvent = buildUpdateStreamEvent();
    const hoisted = buildUpdateEventContext(streamEvent);
    const perTrigger = [1, 2, 3].map(() => buildUpdateEventContext(streamEvent));
    perTrigger.forEach((context) => {
      expect(context.previous).toEqual(hoisted.previous);
      expect(context.eventContext).toEqual(hoisted.eventContext);
    });
  });
});
