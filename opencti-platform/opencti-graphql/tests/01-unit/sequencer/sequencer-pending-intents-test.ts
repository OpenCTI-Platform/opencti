import { describe, expect, it } from 'vitest';
import { pendingIntentRecordKey } from '../../../src/database/sequencer/sequencer-pending-intents';

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
