import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import { CURATION_TABS, grantedCurationTabs } from '../data/curation/curationTabs';
import { DEFENSE_AREAS, type DefenseArea, defenseAreaSection, visibleDefenseAreas } from './defenseAreas';

const area = (path: string, entityType?: string): DefenseArea => ({
  order: 0,
  path,
  label: path,
  icon: null,
  entityType,
  component: lazy(async () => ({ default: () => null })),
});

const ROUTE_SEGMENT = /^[a-z][a-z0-9_-]*$/;

describe('visibleDefenseAreas', () => {
  it('keeps the areas in their registration order', () => {
    const areas = [area('alpha', 'Report'), area('beta'), area('gamma')];
    expect(visibleDefenseAreas(areas, []).map((a) => a.path)).toEqual(['alpha', 'beta', 'gamma']);
  });

  it('drops an area whose entity type is hidden on the platform', () => {
    const areas = [area('alpha', 'Report'), area('beta')];
    expect(visibleDefenseAreas(areas, ['Report']).map((a) => a.path)).toEqual(['beta']);
  });

  it('keeps an area that names no entity type whatever is hidden', () => {
    expect(visibleDefenseAreas([area('beta')], ['Report', 'Indicator'])).toHaveLength(1);
  });
});

// The two registries are where each feature adds its entry, so a bad entry must fail here rather
// than as a broken route or a duplicated menu row.
describe.each([
  ['DEFENSE_AREAS', DEFENSE_AREAS],
  ['CURATION_TABS', CURATION_TABS],
])('%s registry', (_name, entries) => {
  it('gives every entry a unique route segment', () => {
    const paths = entries.map((entry) => entry.path);
    expect(new Set(paths).size).toEqual(paths.length);
  });

  it('gives every entry its own position, in ascending order', () => {
    const orders = entries.map((entry) => entry.order);
    expect(new Set(orders).size).toEqual(orders.length);
    expect(orders).toEqual([...orders].sort((a, b) => a - b));
  });

  it('uses lowercase route segments, as the rest of the dashboard does', () => {
    entries.forEach((entry) => expect(entry.path).toMatch(ROUTE_SEGMENT));
  });

  it('labels every entry with a sentence-case source string', () => {
    entries.forEach((entry) => {
      expect(entry.label.trim()).not.toEqual('');
      expect(entry.label[0]).toEqual(entry.label[0].toUpperCase());
    });
  });

  it('describes an entry, when it does, with a sentence-case source string', () => {
    entries.forEach((entry) => {
      if (entry.description === undefined) return;
      expect(entry.description.trim()).not.toEqual('');
      expect(entry.description[0]).toEqual(entry.description[0].toUpperCase());
    });
  });
});

describe('DEFENSE_AREAS sections', () => {
  it('give every area page a unique lowercase segment and a sentence-case label', () => {
    DEFENSE_AREAS.forEach((entry) => {
      const sections = entry.sections ?? [];
      expect(new Set(sections.map((section) => section.path)).size).toEqual(sections.length);
      sections.forEach((section) => {
        expect(section.path).toMatch(ROUTE_SEGMENT);
        expect(section.label[0]).toEqual(section.label[0].toUpperCase());
      });
    });
  });
});

describe('defenseAreaSection', () => {
  const gamma: DefenseArea = {
    ...area('gamma'),
    sections: [{ path: 'overview', label: 'Overview' }, { path: 'lists', label: 'Lists' }],
  };

  it('finds the section a path opens, its own sub-paths included', () => {
    expect(defenseAreaSection(gamma, 'lists')?.label).toEqual('Lists');
    expect(defenseAreaSection(gamma, 'lists/list-1')?.label).toEqual('Lists');
  });

  it('finds no section for the area root, an unknown path or a path that only starts like one', () => {
    expect(defenseAreaSection(gamma, '')).toBeUndefined();
    expect(defenseAreaSection(gamma, 'unknown')).toBeUndefined();
    expect(defenseAreaSection(gamma, 'listsx')).toBeUndefined();
    expect(defenseAreaSection(area('beta'), 'gaps')).toBeUndefined();
  });
});

describe('the capability an area or a tab needs', () => {
  const granted = (needs: string[]) => needs.includes('KNOWLEDGE');
  const lazyNothing = lazy(async () => ({ default: () => null }));

  it('drops an area the user is not granted, and keeps an area that needs nothing', () => {
    const areas = [
      { ...area('alpha', 'Report'), needs: ['KNOWLEDGE_KNUPDATE'] },
      { ...area('beta'), needs: ['KNOWLEDGE'] },
      area('gamma'),
    ];
    expect(visibleDefenseAreas(areas, [], granted).map((a) => a.path)).toEqual(['beta', 'gamma']);
  });

  it('drops a tab the user is not granted', () => {
    const tabs = [
      { order: 10, path: 'alpha', label: 'Alpha', needs: ['KNOWLEDGE_KNUPDATE_KNMERGE'], component: lazyNothing },
      { order: 50, path: 'beta', label: 'Beta', component: lazyNothing },
    ];
    expect(grantedCurationTabs(tabs, granted).map((t) => t.path)).toEqual(['beta']);
  });
});
