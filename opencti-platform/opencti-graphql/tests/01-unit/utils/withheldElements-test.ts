import { describe, expect, it } from 'vitest';
import {
  registerWithheldElements,
  registerWithheldElementsCheck,
  unlessWithheld,
  withheldElementIds,
  withoutWithheldElements,
  withoutWithheldHits,
} from '../../../src/utils/withheldElements';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreBase } from '../../../src/types/store';

const TYPE = 'Test-Withheld-Element';

describe('Withheld elements', () => {
  let calls = 0;
  registerWithheldElements(TYPE, async () => {
    calls += 1;
    return ['withheld-1'];
  });

  it('should read the withheld elements of a type once per request', async () => {
    calls = 0;
    const context = { ...testContext } as AuthContext;
    expect(await withheldElementIds(context, ADMIN_USER, TYPE)).toEqual(['withheld-1']);
    expect(await withheldElementIds(context, ADMIN_USER, TYPE)).toEqual(['withheld-1']);
    expect(calls).toBe(1);
    expect(await withheldElementIds(context, ADMIN_USER, 'Test-Other-Type')).toEqual([]);
  });

  it('should answer for a withheld element as for an unknown one, and leave it out of the listings', async () => {
    const context = { ...testContext } as AuthContext;
    const withheld = { internal_id: 'withheld-1' } as BasicStoreBase;
    const visible = { internal_id: 'visible-1' } as BasicStoreBase;
    expect(await unlessWithheld(context, ADMIN_USER, TYPE, withheld)).toBeUndefined();
    expect(await unlessWithheld(context, ADMIN_USER, TYPE, visible)).toBe(visible);
    const filters = await withoutWithheldElements(context, ADMIN_USER, TYPE, null);
    expect(filters?.filters).toEqual([expect.objectContaining({ key: ['internal_id'], values: ['withheld-1'], operator: 'not_eq', mode: 'and' })]);
    expect(await withoutWithheldElements(context, ADMIN_USER, 'Test-Other-Type', null)).toBeNull();
  });

  it('should leave a withheld element out of every load by id, and ask nothing for the other types', async () => {
    calls = 0;
    const context = { ...testContext } as AuthContext;
    const other = { internal_id: 'other-1', entity_type: 'Test-Other-Type' };
    expect(await withoutWithheldHits(context, ADMIN_USER, [other])).toEqual([other]);
    expect(calls).toBe(0);
    const visible = { internal_id: 'visible-1', entity_type: TYPE };
    const withheld = { internal_id: 'withheld-1', entity_type: TYPE };
    expect(await withoutWithheldHits(context, ADMIN_USER, [visible, withheld, other])).toEqual([visible, other]);
    expect(calls).toBe(1);
  });

  it('should check each loaded element once per request, never from within a check, and leave the listings to the providers', async () => {
    const CHECKED = 'Test-Checked-Element';
    const asked: string[][] = [];
    registerWithheldElementsCheck(CHECKED, async (checkContext, user, ids) => {
      asked.push(ids);
      // What a check loads to decide is not checked again.
      expect(await withoutWithheldHits(checkContext, user, [{ internal_id: 'checked-2', entity_type: CHECKED }])).toHaveLength(1);
      return ids.filter((id) => id === 'checked-2');
    });
    const context = { ...testContext } as AuthContext;
    const visible = { internal_id: 'checked-1', entity_type: CHECKED };
    const withheld = { internal_id: 'checked-2', entity_type: CHECKED };
    expect(await withoutWithheldHits(context, ADMIN_USER, [visible, withheld])).toEqual([visible]);
    expect(await withoutWithheldHits(context, ADMIN_USER, [withheld])).toEqual([]);
    expect(await unlessWithheld(context, ADMIN_USER, CHECKED, { internal_id: 'checked-2' } as BasicStoreBase)).toBeUndefined();
    expect(asked).toEqual([['checked-1', 'checked-2']]);
    expect(await withoutWithheldElements(context, ADMIN_USER, CHECKED, null)).toBeNull();
  });
});
