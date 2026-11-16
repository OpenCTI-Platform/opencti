import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import useNavMenu, { filterNavGroups, NavItem, RawNavGroup } from './useNavMenu';
import { testRenderHook } from '../../../utils/tests/test-render';

let mockHiddenEntities: string[] = [];

vi.mock('../../../utils/hooks/useEntitySettings', () => ({
  useHiddenEntities: () => mockHiddenEntities,
  useIsHiddenEntities: (...types: string[]) => types.every((type) => mockHiddenEntities.includes(type)),
}));

vi.mock('../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  default: () => true,
}));

vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: () => false, isTrashEnable: () => false }),
}));

vi.mock('../../../utils/hooks/useImportAccess', () => ({
  default: () => ({ hasOnlyAccessToImportDraftTab: false }),
}));

const item = (id: string, extra: Partial<NavItem> = {}): NavItem => ({
  id, label: id, icon: <svg />, link: `/${id}`, ...extra,
});

/**
 * The permission filtering used to be spread across the rail's JSX, mixing three mechanisms
 * (capability checks, `<Security>` wrappers and feature flags) with rendering.
 */
describe('filterNavGroups', () => {
  it('drops entries whose permission expression evaluated to false', () => {
    const groups: RawNavGroup[] = [{ id: 'g', items: [item('visible'), false, undefined, item('other')] }];
    expect(filterNavGroups(groups, []).map((g) => g.items.map((i) => i.id))).toEqual([['visible', 'other']]);
  });

  it('drops whole groups the user has no permission for', () => {
    // A group whose permission gate failed is declared as `false`, and one
    // whose entries were all filtered out must not leave a stray separator.
    const groups: (RawNavGroup | false)[] = [
      { id: 'kept', items: [item('a')] },
      false,
      { id: 'emptied', items: [false, false] },
    ];
    expect(filterNavGroups(groups, []).map((g) => g.id)).toEqual(['kept']);
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
    expect(filterNavGroups(groups, [])[0].items[0].subItems?.map((s) => s.link)).toEqual(['/a']);
  });

  it('treats an unspecified granted flag as granted', () => {
    const groups: RawNavGroup[] = [{
      id: 'g',
      items: [item('parent', { subItems: [{ link: '/a', label: 'A' }] })],
    }];
    expect(filterNavGroups(groups, [])[0].items[0].subItems).toHaveLength(1);
  });

  it('drops submenu rows whose entity type is hidden on the platform', () => {
    const groups: RawNavGroup[] = [{
      id: 'g',
      items: [item('threats', {
        subItems: [
          { link: '/a', label: 'A', type: 'Campaign' },
          { link: '/b', label: 'B', type: 'Intrusion-Set' },
        ],
      })],
    }];
    expect(filterNavGroups(groups, ['Campaign'])[0].items[0].subItems?.map((s) => s.link)).toEqual(['/b']);
  });

  it('keeps a parent whose submenu ended up empty, as a leaf entry', () => {
    // The component this replaced rendered such a parent as a plain navigable link
    // (`LeftBarItem`'s "No Subitems" branch).
    const groups: RawNavGroup[] = [{
      id: 'g',
      items: [
        item('kept'),
        item('gutted', { link: '/gutted', subItems: [{ link: '/a', label: 'A', type: 'Campaign' }] }),
      ],
    }];
    const items = filterNavGroups(groups, ['Campaign'])[0].items;
    expect(items.map((i) => i.id)).toEqual(['kept', 'gutted']);
    expect(items[1].link).toEqual('/gutted');
    expect(items[1].subItems).toEqual([]);
  });

  it('keeps a leaf entry that never declared a submenu', () => {
    const groups: RawNavGroup[] = [{ id: 'g', items: [item('leaf')] }];
    const result = filterNavGroups(groups, ['Campaign']);
    expect(result[0].items).toHaveLength(1);
    expect(result[0].items[0].subItems).toBeUndefined();
  });

  it('returns nothing at all when the user may see nothing', () => {
    expect(filterNavGroups([{ id: 'g', items: [false] }, false], [])).toEqual([]);
  });
});

describe('useNavMenu, Techniques group', () => {
  const techniqueTypes = ['Attack-Pattern', 'Narrative', 'Course-Of-Action', 'Data-Component', 'Data-Source', 'Procedure'];

  const techniquesItem = () => {
    const { hook } = testRenderHook(() => useNavMenu());
    return hook.result.current.flatMap((group) => group.items).find((entry) => entry.id === 'techniques');
  };

  beforeEach(() => {
    mockHiddenEntities = [];
  });

  it('lists the Procedures entry under Techniques', () => {
    const subItems = techniquesItem()?.subItems ?? [];
    expect(subItems.map(({ type, link }) => ({ type, link }))).toContainEqual({
      type: 'Procedure',
      link: '/dashboard/techniques/procedures',
    });
  });

  it('lists Procedures right under Attack patterns', () => {
    const subItems = techniquesItem()?.subItems ?? [];
    expect(subItems.map(({ type }) => type).slice(0, 2)).toEqual(['Attack-Pattern', 'Procedure']);
  });

  it('keeps the Techniques group when only Procedure is left visible', () => {
    mockHiddenEntities = techniqueTypes.filter((type) => type !== 'Procedure');
    const subItems = techniquesItem()?.subItems ?? [];
    expect(subItems.map(({ type }) => type)).toEqual(['Procedure']);
  });

  it('hides the Techniques group when every Techniques type, Procedure included, is hidden', () => {
    mockHiddenEntities = techniqueTypes;
    expect(techniquesItem()).toBeUndefined();
  });
});
