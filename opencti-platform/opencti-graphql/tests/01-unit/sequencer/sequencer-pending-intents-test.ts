import { describe, expect, it, vi } from 'vitest';
import { deferIntents, pendingIntentRecordKey, registerPendingIntentsEsOps } from '../../../src/database/sequencer/sequencer-pending-intents';

describe('pending intent record key', () => {
  const input = {
    stix_id: 'relationship--4641638c-5bac-5f1f-9dcc-53d92cbf35bf',
    relationship_type: 'has',
    fromId: 'software--ef7e2974-325f-50dc-a747-3d66d4bdaf90',
    toId: 'vulnerability--050cffd8-8e54-55c9-8db3-b599debb7f6f',
    confidence: undefined,
    created: new Date('2026-07-21T09:01:43.414Z'),
    objectMarking: ['marking-definition--1'],
  };

  it('should be stable across the JSON round trip a re-submission reads back', () => {
    const roundTripped = JSON.parse(JSON.stringify(input));
    expect(pendingIntentRecordKey('relation', 'has', 'user1', roundTripped)).toBe(pendingIntentRecordKey('relation', 'has', 'user1', input));
  });

  it('should not depend on the key order of the input', () => {
    const reordered = { objectMarking: input.objectMarking, toId: input.toId, fromId: input.fromId, created: input.created, relationship_type: 'has', stix_id: input.stix_id };
    expect(pendingIntentRecordKey('relation', 'has', 'user1', reordered)).toBe(pendingIntentRecordKey('relation', 'has', 'user1', input));
  });

  it('should separate distinct creations, kinds and users', () => {
    const key = pendingIntentRecordKey('relation', 'has', 'user1', input);
    expect(pendingIntentRecordKey('relation', 'has', 'user1', { ...input, toId: 'vulnerability--other' })).not.toBe(key);
    expect(pendingIntentRecordKey('operation', 'has', 'user1', input)).not.toBe(key);
    expect(pendingIntentRecordKey('relation', 'has', 'user2', input)).not.toBe(key);
  });
});

describe('retained intent envelope', () => {
  it('should keep the intake envelope the intent was written under, to rebuild its context', async () => {
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    const user = { id: 'applicant-1', origin: { applicant_id: 'applicant-1', playbook_id: 'playbook-1', call_retry_number: '0' } } as any;
    const context = {
      workId: 'work-1',
      draft_context: 'draft-1',
      eventId: 'event-1',
      previousStandard: 'malware--previous',
      synchronizedUpsert: true,
      real_authentication_id: 'writer-1',
    } as any;
    const intent = { id: 'i', kind: 'entity', type: 'Malware', input: { name: 'M' }, user, context, opts: {}, arrivedAt: 0, source: 'test', sizeBytes: 1, candidateIds: [], referencedIds: [] } as any;
    expect(await deferIntents([{ intent, missing: ['malware--x'] }])).toBe(true);
    const record = bulk.mock.calls[0][0][1];
    expect(JSON.parse(record.envelope_json)).toEqual({
      user_id: 'writer-1',
      applicant_id: 'applicant-1',
      work_id: 'work-1',
      draft_id: 'draft-1',
      event_id: 'event-1',
      playbook_id: 'playbook-1',
      synchronized: true,
      previous_standard: 'malware--previous',
      retry_number: 0,
    });
  });
});
