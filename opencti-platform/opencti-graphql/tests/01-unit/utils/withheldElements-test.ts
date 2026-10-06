import { describe, expect, it } from 'vitest';
import { registerWithheldElements, unlessWithheld, withheldElementIds, withoutWithheldElements } from '../../../src/utils/withheldElements';
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
});
