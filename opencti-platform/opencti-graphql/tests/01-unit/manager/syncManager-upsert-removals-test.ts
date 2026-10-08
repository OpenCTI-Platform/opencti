import { describe, expect, it } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { type SyncStixData, withUpsertRemovals } from '../../../src/manager/syncManager-upsert-removals';

const SURVIVOR = 'intrusion-set--2e895354-534c-548a-80d7-6e83ea44b58a';
const RESTORED = 'intrusion-set--304eb2c0-d45e-5c56-83ad-d717888509d8';
const OTHER = 'intrusion-set--5f0c2b4e-0c4b-5c48-9a61-2f1d0f9a2b11';
const STIX_IDS_PATH = `/extensions/${STIX_EXT_OCTI}/stix_ids`;

const entity = (stixIds?: string[], aliases?: string[]): SyncStixData => ({
  id: SURVIVOR,
  type: 'intrusion-set',
  name: 'Velvet Lynx',
  ...(aliases ? { aliases } : {}),
  extensions: { [STIX_EXT_OCTI]: { id: 'internal-id', type: 'Intrusion-Set', ...(stixIds ? { stix_ids: stixIds } : {}) } },
});

const operationsOf = (data: SyncStixData) => data.extensions?.[STIX_EXT_OCTI]?.opencti_upsert_operations;

describe('synchronized updates removing identity values', () => {
  it('sends the ids and aliases removed by an unmerge as explicit removals', () => {
    // After an unmerge the survivor no longer carries the restored entity's id nor its name as an alias.
    const current = entity();
    const context = {
      reverse_patch: [
        { op: 'add' as const, path: STIX_IDS_PATH, value: [RESTORED] },
        { op: 'add' as const, path: '/aliases', value: ['velvet lynx group'] },
      ],
    };
    const result = withUpsertRemovals(current, context);
    expect(operationsOf(result)).toEqual([
      { key: 'x_opencti_stix_ids', value: [RESTORED], operation: 'remove' },
      { key: 'aliases', value: ['velvet lynx group'], operation: 'remove' },
    ]);
    expect(current.extensions?.[STIX_EXT_OCTI]).not.toHaveProperty('opencti_upsert_operations');
  });

  it('sends the markings and organizations an update removed as explicit removals', () => {
    const red = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed';
    const green = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';
    const current: SyncStixData = {
      ...entity(),
      object_marking_refs: [green],
      extensions: { [STIX_EXT_OCTI]: { id: 'internal-id', type: 'Intrusion-Set', granted_refs: [] } },
    };
    const context = {
      reverse_patch: [
        { op: 'replace' as const, path: '/object_marking_refs', value: [green, red] },
        { op: 'replace' as const, path: `/extensions/${STIX_EXT_OCTI}/granted_refs`, value: ['identity--org'] },
      ],
    };
    expect(operationsOf(withUpsertRemovals(current, context))).toEqual([
      { key: 'objectMarking', value: [red], operation: 'remove' },
      { key: 'objectOrganization', value: ['identity--org'], operation: 'remove' },
    ]);
  });

  it('removes the aliases kept in the OpenCTI extension under their own attribute', () => {
    const current: SyncStixData = { id: 'identity--a', type: 'identity', extensions: { [STIX_EXT_OCTI]: { aliases: ['Kept'] } } };
    const context = { reverse_patch: [{ op: 'replace' as const, path: `/extensions/${STIX_EXT_OCTI}/aliases`, value: ['Kept', 'Gone'] }] };
    expect(operationsOf(withUpsertRemovals(current, context))).toEqual([{ key: 'x_opencti_aliases', value: ['Gone'], operation: 'remove' }]);
  });

  it('only removes the values that are gone, and replaces its own operations when retried', () => {
    const current = entity([OTHER], ['kept alias']);
    const context = {
      reverse_patch: [
        { op: 'replace' as const, path: STIX_IDS_PATH, value: [OTHER, RESTORED] },
        { op: 'replace' as const, path: '/aliases', value: ['kept alias', 'gone alias'] },
      ],
    };
    const once = withUpsertRemovals(current, context);
    const twice = withUpsertRemovals(once, context);
    expect(operationsOf(twice)).toEqual([
      { key: 'x_opencti_stix_ids', value: [RESTORED], operation: 'remove' },
      { key: 'aliases', value: ['gone alias'], operation: 'remove' },
    ]);
  });

  it('keeps the upsert operations the event already carries', () => {
    const current = entity();
    const existing = { key: 'objectLabel', value: ['label--a'], operation: 'add' };
    current.extensions = { [STIX_EXT_OCTI]: { ...current.extensions?.[STIX_EXT_OCTI], opencti_upsert_operations: [existing] } };
    const result = withUpsertRemovals(current, { reverse_patch: [{ op: 'add', path: STIX_IDS_PATH, value: [RESTORED] }] });
    expect(operationsOf(result)).toEqual([existing, { key: 'x_opencti_stix_ids', value: [RESTORED], operation: 'remove' }]);
  });

  it('merges a removal the event already carries for the same attribute', () => {
    const current = entity();
    const carried = { key: 'aliases', value: ['already removed alias'], operation: 'remove' };
    current.extensions = { [STIX_EXT_OCTI]: { ...current.extensions?.[STIX_EXT_OCTI], opencti_upsert_operations: [carried] } };
    const result = withUpsertRemovals(current, { reverse_patch: [{ op: 'add', path: '/aliases', value: ['velvet lynx group'] }] });
    expect(operationsOf(result)).toEqual([{ key: 'aliases', value: ['already removed alias', 'velvet lynx group'], operation: 'remove' }]);
  });

  it('leaves events without removed values unchanged', () => {
    const current = entity([OTHER], ['kept alias']);
    expect(withUpsertRemovals(current, undefined)).toBe(current);
    expect(withUpsertRemovals(current, { reverse_patch: [{ op: 'replace', path: '/name', value: 'Old name' }] })).toBe(current);
    expect(withUpsertRemovals(current, { reverse_patch: [{ op: 'remove', path: `${STIX_IDS_PATH}/0` }] })).toBe(current);
    expect(withUpsertRemovals(current, { reverse_patch: [{ op: 'remove', path: '/aliases/0' }] })).toBe(current);
  });

  it('keeps the event as received when its reverse patch does not apply', () => {
    const current = entity();
    expect(withUpsertRemovals(current, { reverse_patch: [{ op: 'remove', path: '/unknown/deep/path' }] })).toBe(current);
  });
});
