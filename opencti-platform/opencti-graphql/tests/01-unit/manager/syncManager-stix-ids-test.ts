import { describe, expect, it } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { withRemovedStixIdsOperation } from '../../../src/manager/syncManager-stix-ids';

const SURVIVOR = 'intrusion-set--2e895354-534c-548a-80d7-6e83ea44b58a';
const RESTORED = 'intrusion-set--304eb2c0-d45e-5c56-83ad-d717888509d8';
const OTHER = 'intrusion-set--5f0c2b4e-0c4b-5c48-9a61-2f1d0f9a2b11';

const entity = (stixIds?: string[]) => ({
  id: SURVIVOR,
  type: 'intrusion-set',
  name: 'Velvet Lynx',
  extensions: { [STIX_EXT_OCTI]: { id: 'internal-id', type: 'Intrusion-Set', ...(stixIds ? { stix_ids: stixIds } : {}) } },
});

describe('synchronized updates removing alternative standard ids', () => {
  it('sends the ids removed by the update as an explicit removal', () => {
    // After an unmerge the survivor no longer carries the restored entity's id.
    const current = entity();
    const context = { reverse_patch: [{ op: 'add' as const, path: `/extensions/${STIX_EXT_OCTI}/stix_ids`, value: [RESTORED] }] };
    const result = withRemovedStixIdsOperation(current, context);
    expect(result.extensions[STIX_EXT_OCTI].opencti_upsert_operations).toEqual([{ key: 'x_opencti_stix_ids', value: [RESTORED], operation: 'remove' }]);
    expect(current.extensions[STIX_EXT_OCTI]).not.toHaveProperty('opencti_upsert_operations');
  });

  it('only removes the ids that are gone, and replaces its own operation when retried', () => {
    const current = entity([OTHER]);
    const context = { reverse_patch: [{ op: 'replace' as const, path: `/extensions/${STIX_EXT_OCTI}/stix_ids`, value: [OTHER, RESTORED] }] };
    const once = withRemovedStixIdsOperation(current, context);
    const twice = withRemovedStixIdsOperation(once, context);
    expect(twice.extensions[STIX_EXT_OCTI].opencti_upsert_operations).toEqual([{ key: 'x_opencti_stix_ids', value: [RESTORED], operation: 'remove' }]);
  });

  it('leaves events without removed ids unchanged', () => {
    const current = entity([OTHER]);
    expect(withRemovedStixIdsOperation(current, undefined)).toBe(current);
    expect(withRemovedStixIdsOperation(current, { reverse_patch: [{ op: 'replace', path: '/name', value: 'Old name' }] })).toBe(current);
    expect(withRemovedStixIdsOperation(current, { reverse_patch: [{ op: 'remove', path: `/extensions/${STIX_EXT_OCTI}/stix_ids/0` }] })).toBe(current);
  });

  it('keeps the event as received when its reverse patch does not apply', () => {
    const current = entity();
    expect(withRemovedStixIdsOperation(current, { reverse_patch: [{ op: 'remove', path: '/unknown/deep/path' }] })).toBe(current);
  });
});
