import { describe, expect, it } from 'vitest';
import { filterUpdateInstanceIdsFromUpdatePatch, normalizeUpdatePatch } from '../../../src/manager/notificationManager';
import * as jsonpatch from 'fast-json-patch';
import { computeJsonPatch } from '../../../src/utils/json-patch';
import type { StixCoreObject, StixObject } from '../../../src/types/stix-2-1-common';

const malware = { id: 'malware--a', type: 'malware' } as unknown as StixObject;
const attackPattern = { id: 'attack-pattern--b', type: 'attack-pattern' } as unknown as StixObject;
const listenedInstanceIdsMap = new Map<string, StixObject>([[malware.id, malware], [attackPattern.id, attackPattern]]);

const applyPatch = (document: unknown, operations: jsonpatch.Operation[]) => jsonpatch.applyPatch(structuredClone(document), operations, true).newDocument;

const report = (objectRefs: string[]) => ({ id: 'report--r', type: 'report', object_refs: objectRefs }) as unknown as StixCoreObject;

describe('normalizeUpdatePatch', () => {
  it('should not report kept references of a whole array replacement as added', () => {
    const previous = report([malware.id, attackPattern.id, 'identity--c']);
    const current = report([malware.id]);
    const updatePatch = {
      patch: [{ op: 'replace' as const, path: '/object_refs', value: current.object_refs }],
      reverse_patch: [{ op: 'replace' as const, path: '/object_refs', value: previous.object_refs }],
    };
    const result = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, normalizeUpdatePatch(updatePatch, previous, current));
    expect(result).toEqual([{ instance: attackPattern, action: 'removed from' }]);
  });

  it('should not report kept references of a whole array replacement as removed', () => {
    const previous = report([malware.id]);
    const current = report([malware.id, attackPattern.id, 'identity--c']);
    const updatePatch = {
      patch: [{ op: 'replace' as const, path: '/object_refs', value: current.object_refs }],
      reverse_patch: [{ op: 'replace' as const, path: '/object_refs', value: previous.object_refs }],
    };
    const result = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, normalizeUpdatePatch(updatePatch, previous, current));
    expect(result).toEqual([{ instance: attackPattern, action: 'added in' }]);
  });

  it('should resolve a nested array replacement after an index shifting operation', () => {
    const kept = { id: 'group--kept', type: 'group' } as unknown as StixObject;
    const removed = { id: 'group--removed', type: 'group' } as unknown as StixObject;
    const groupsMap = new Map<string, StixObject>([[kept.id, kept], [removed.id, removed]]);
    const previous = { id: 'report--r', type: 'report', authorized_members: [{ id: 'A', groups_restriction_ids: [kept.id, removed.id, 'group--other'] }] } as unknown as StixCoreObject;
    const current = { id: 'report--r', type: 'report', authorized_members: [{ id: 'B' }, { id: 'A', groups_restriction_ids: [kept.id] }] } as unknown as StixCoreObject;
    const updatePatch = {
      patch: [
        { op: 'add' as const, path: '/authorized_members/0', value: { id: 'B' } },
        { op: 'replace' as const, path: '/authorized_members/1/groups_restriction_ids', value: [kept.id] },
      ],
      reverse_patch: [
        { op: 'remove' as const, path: '/authorized_members/0' },
        { op: 'replace' as const, path: '/authorized_members/0/groups_restriction_ids', value: [kept.id, removed.id, 'group--other'] },
      ],
    };
    expect(applyPatch(previous, updatePatch.patch)).toEqual(current);
    expect(applyPatch(current, updatePatch.reverse_patch)).toEqual(previous);
    const result = filterUpdateInstanceIdsFromUpdatePatch(groupsMap, normalizeUpdatePatch(updatePatch, previous, current));
    expect(result).toEqual([{ instance: removed, action: 'removed from' }]);
  });

  it('should report references added and removed by element operations', () => {
    const previous = report([malware.id, 'identity--c']);
    const current = report(['identity--c', attackPattern.id]);
    const updatePatch = { patch: computeJsonPatch(previous, current), reverse_patch: computeJsonPatch(current, previous) };
    const result = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, normalizeUpdatePatch(updatePatch, previous, current));
    expect(result).toEqual([{ instance: attackPattern, action: 'added in' }, { instance: malware, action: 'removed from' }]);
  });
});
