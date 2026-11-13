import React, { lazy } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import { DEFENSE_AREAS, type DefenseArea } from '../defense/defenseAreas';
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

const menu = (): NavGroup[] => testRenderHook(() => useNavMenu()).hook.result.current;
const knowledgeIds = (groups: NavGroup[]) => groups.find((g) => g.id === 'knowledge')?.items.map((i) => i.id);

// The registry is a module-level array the product registers its areas into: each test starts from
// an empty one and gets the registered entries back afterwards.
let registeredAreas: DefenseArea[] = [];
beforeEach(() => {
  registeredAreas = DEFENSE_AREAS.splice(0);
});
afterEach(() => {
  DEFENSE_AREAS.splice(0, DEFENSE_AREAS.length, ...registeredAreas);
  hidden.entities = [];
});

describe('useNavMenu - Defense hub', () => {
  it('adds no Defense entry while no area is registered', () => {
    expect(knowledgeIds(menu())).not.toContain('defense');
  });

  it('places Defense right after Observations, with its areas in registration order', () => {
    DEFENSE_AREAS.push(area('hunts', 'Hunts', 'Hunt'), area('second', 'Second area'));
    const groups = menu();
    expect(knowledgeIds(groups)).toEqual(['analyses', 'cases', 'events', 'observations', 'defense']);
    const defense = groups.find((g) => g.id === 'knowledge')?.items.find((i) => i.id === 'defense');
    expect(defense?.link).toEqual('/dashboard/defense');
    expect(defense?.subItems?.map((s) => [s.link, s.label])).toEqual([
      ['/dashboard/defense/hunts', 'Hunts'],
      ['/dashboard/defense/second', 'Second area'],
    ]);
  });

  it('removes the entry, not just its rows, when every area is hidden', () => {
    // A parent left with no rows would degrade to a plain link to an empty hub.
    DEFENSE_AREAS.push(area('hunts', 'Hunts', 'Hunt'));
    hidden.entities = ['Hunt'];
    expect(knowledgeIds(menu())).not.toContain('defense');
  });
});
