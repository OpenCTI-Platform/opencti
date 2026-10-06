import React, { lazy } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import { DEFENSE_AREAS, type DefenseArea } from '../defense/defenseAreas';
import { CURATION_TABS, type CurationTab } from '../data/curation/curationTabs';
import useNavMenu, { type NavGroup } from './useNavMenu';

const hidden = vi.hoisted(() => ({ entities: [] as string[] }));

vi.mock('../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useGranted')>()),
  default: () => true,
}));
vi.mock('../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useEntitySettings')>()),
  useHiddenEntities: () => hidden.entities,
  useIsHiddenEntities: () => false,
}));
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: () => false, isTrashEnable: () => false }),
}));
vi.mock('../../../utils/hooks/useImportAccess', () => ({
  default: () => ({ hasOnlyAccessToImportDraftTab: false }),
}));

const lazyNothing = lazy(async () => ({ default: () => null }));
const area = (path: string, label: string, entityType?: string): DefenseArea => ({
  order: 0, path, label, entityType, icon: <svg />, component: lazyNothing,
});
const tab = (path: string, label: string): CurationTab => ({ order: 0, path, label, component: lazyNothing });

const menu = (): NavGroup[] => testRenderHook(() => useNavMenu()).hook.result.current;
const knowledgeIds = (groups: NavGroup[]) => groups.find((g) => g.id === 'knowledge')?.items.map((i) => i.id);
const defenseEntry = (groups: NavGroup[]) => groups.find((g) => g.id === 'knowledge')?.items.find((i) => i.id === 'defense');
const dataLinks = (groups: NavGroup[]) => groups
  .find((g) => g.id === 'data')?.items.find((i) => i.id === 'data')?.subItems?.map((s) => s.link);

// The registries are module-level arrays the product registers its areas and tabs into: each test
// starts from empty ones and gets the registered entries back afterwards.
let registeredAreas: DefenseArea[] = [];
let registeredTabs: CurationTab[] = [];
beforeEach(() => {
  registeredAreas = DEFENSE_AREAS.splice(0);
  registeredTabs = CURATION_TABS.splice(0);
});
afterEach(() => {
  DEFENSE_AREAS.splice(0, DEFENSE_AREAS.length, ...registeredAreas);
  CURATION_TABS.splice(0, CURATION_TABS.length, ...registeredTabs);
  hidden.entities = [];
});

describe('useNavMenu - Defense hub', () => {
  it('lists Defense right after Observations as a link to its landing page while no area is registered', () => {
    const groups = menu();
    expect(knowledgeIds(groups)).toEqual(['analyses', 'cases', 'events', 'observations', 'defense']);
    expect(defenseEntry(groups)?.link).toEqual('/dashboard/defense');
    expect(defenseEntry(groups)?.subItems).toBeUndefined();
  });

  it('lists the registered areas under Defense, in registration order', () => {
    DEFENSE_AREAS.push(area('alpha', 'Alpha', 'Report'), area('beta', 'Beta'));
    const defense = defenseEntry(menu());
    expect(defense?.link).toEqual('/dashboard/defense');
    expect(defense?.subItems?.map((s) => [s.link, s.label])).toEqual([
      ['/dashboard/defense/alpha', 'Alpha'],
      ['/dashboard/defense/beta', 'Beta'],
    ]);
  });

  it('removes the entry, not just its rows, when every registered area is hidden', () => {
    // A parent left with no rows would degrade to a plain link to a hub with nothing for the reader.
    DEFENSE_AREAS.push(area('alpha', 'Alpha', 'Report'));
    hidden.entities = ['Report'];
    expect(knowledgeIds(menu())).not.toContain('defense');
  });

  it('gives a row a pending count only when its area counts pending work', () => {
    DEFENSE_AREAS.push({ ...area('alpha', 'Alpha'), useBadgeCount: () => 3 }, area('beta', 'Beta'));
    expect(defenseEntry(menu())?.subItems?.map((s) => !!s.badge)).toEqual([true, false]);
  });
});

describe('useNavMenu - Curation hub', () => {
  it('lists Curation right after Relationships, a link to its landing page while no tab is registered', () => {
    const links = dataLinks(menu()) ?? [];
    expect(links.slice(0, 3)).toEqual(['/dashboard/data/entities', '/dashboard/data/relationships', '/dashboard/data/curation']);
  });

  it('keeps Curation after Relationships once a tab is registered', () => {
    CURATION_TABS.push(tab('alpha', 'Alpha'));
    const links = dataLinks(menu()) ?? [];
    expect(links.slice(0, 3)).toEqual(['/dashboard/data/entities', '/dashboard/data/relationships', '/dashboard/data/curation']);
  });

  it('removes the Curation row when every registered tab is unavailable', () => {
    CURATION_TABS.push({ ...tab('alpha', 'Alpha'), isAvailable: () => false });
    expect(dataLinks(menu())).not.toContain('/dashboard/data/curation');
  });

  it('sums the pending counts of the tabs on the Curation row, and shows none without counting tabs', () => {
    const curationRow = () => menu().find((g) => g.id === 'data')?.items.find((i) => i.id === 'data')
      ?.subItems?.find((s) => s.link === '/dashboard/data/curation');
    expect(curationRow()?.badge).toBeUndefined();
    CURATION_TABS.push(tab('beta', 'Beta'));
    expect(curationRow()?.badge).toBeUndefined();
    CURATION_TABS.push({ ...tab('alpha', 'Alpha'), useBadgeCount: () => 2 });
    expect(curationRow()?.badge).toBeTruthy();
  });
});
