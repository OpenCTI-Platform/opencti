import React from 'react';
import { describe, expect, it } from 'vitest';
import { filterNavGroups, NavItem, RawNavGroup } from './useNavMenu';

const item = (id: string, extra: Partial<NavItem> = {}): NavItem => ({
  id, label: id, icon: <svg />, link: `/${id}`, ...extra,
});

describe('filterNavGroups', () => {
  it('drops entries whose permission expression evaluated to false', () => {
    const groups: RawNavGroup[] = [{ id: 'g', items: [item('visible'), false, undefined, item('other')] }];
    expect(filterNavGroups(groups).map((g) => g.items.map((i) => i.id))).toEqual([['visible', 'other']]);
  });

  it('drops whole groups the user has no permission for', () => {
    // A group whose permission gate failed is declared as `false`, and one
    // whose entries were all filtered out must not leave a stray separator.
    const groups: (RawNavGroup | false)[] = [
      { id: 'kept', items: [item('a')] },
      false,
      { id: 'emptied', items: [false, false] },
    ];
    expect(filterNavGroups(groups).map((g) => g.id)).toEqual(['kept']);
  });

  it('drops submenu rows the user is not granted', () => {
    const groups: RawNavGroup[] = [{
      id: 'g',
      items: [item('parent', {
        subItems: [
          { link: '/a', label: 'A', granted: true },
          { link: '/b', label: 'B', granted: false },
        ],
      })],
    }];
    expect(filterNavGroups(groups)[0].items[0].subItems?.map((s) => s.link)).toEqual(['/a']);
  });

  it('treats an unspecified granted flag as granted', () => {
    const groups: RawNavGroup[] = [{
      id: 'g',
      items: [item('parent', { subItems: [{ link: '/a', label: 'A' }] })],
    }];
    expect(filterNavGroups(groups)[0].items[0].subItems).toHaveLength(1);
  });

  it('keeps a leaf entry that never declared a submenu', () => {
    const groups: RawNavGroup[] = [{ id: 'g', items: [item('leaf')] }];
    const result = filterNavGroups(groups);
    expect(result[0].items).toHaveLength(1);
    expect(result[0].items[0].subItems).toBeUndefined();
  });

  it('returns nothing at all when the user may see nothing', () => {
    expect(filterNavGroups([{ id: 'g', items: [false] }, false])).toEqual([]);
  });
});
