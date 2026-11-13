import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import useNavMenu, { filterNavGroups, NavItem, RawNavGroup } from './useNavMenu';

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

// An entry is hidden by its own entity type: hiding IPv4-Addr must not hide the Observables page they share with
// Stix-Cyber-Observable (both resolve to the same URL), while hiding Stix-Cyber-Observable itself must.
const hidden: string[] = [];
vi.mock('../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => hidden }));
// The real gate (useVisibleEntries) runs: a BYPASS user passes the capability rules, so only the hidden types matter.
vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  default: () => ({ me: { draftContext: null, capabilities: [{ name: 'BYPASS' }], capabilitiesInDraft: [] } }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({ default: () => ({ isTrashEnable: () => true, isFeatureEnable: () => true }) }));
vi.mock('../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));

describe('Hook: useNavMenu hidden entity types', () => {
  const observablesLinks = () => testRenderHook(() => useNavMenu()).hook.result.current
    .flatMap((group) => group.items.flatMap((i) => i.subItems ?? []))
    .map((sub) => sub.link)
    .filter((link) => link === '/dashboard/observations/observables');

  it('keeps Observables when only one observable type is hidden', () => {
    hidden.splice(0, hidden.length, 'IPv4-Addr');
    expect(observablesLinks()).toHaveLength(1);
  });

  it('hides Observables when Stix-Cyber-Observable is hidden', () => {
    hidden.splice(0, hidden.length, 'Stix-Cyber-Observable');
    expect(observablesLinks()).toHaveLength(0);
  });
});

describe('Hook: useNavMenu, Techniques group', () => {
  const techniqueTypes = ['Attack-Pattern', 'Narrative', 'Course-Of-Action', 'Data-Component', 'Data-Source', 'Procedure'];

  const techniquesItem = () => testRenderHook(() => useNavMenu()).hook.result.current
    .flatMap((group) => group.items)
    .find((entry) => entry.id === 'techniques');

  it('lists the Procedures entry under Techniques', () => {
    hidden.splice(0, hidden.length);
    const links = (techniquesItem()?.subItems ?? []).map((sub) => sub.link);
    expect(links).toContain('/dashboard/techniques/procedures');
  });

  it('keeps the Techniques group when only Procedure is left visible', () => {
    hidden.splice(0, hidden.length, ...techniqueTypes.filter((type) => type !== 'Procedure'));
    const links = (techniquesItem()?.subItems ?? []).map((sub) => sub.link);
    expect(links).toEqual(['/dashboard/techniques/procedures']);
  });

  it('hides the Techniques group when every Techniques type, Procedure included, is hidden', () => {
    hidden.splice(0, hidden.length, ...techniqueTypes);
    expect(techniquesItem()).toBeUndefined();
  });
});
