import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import { CURATION_TABS, grantedCurationTabs } from '../data/curation/curationTabs';
import { DEFENSE_AREAS, type DefenseArea, visibleDefenseAreas } from './defenseAreas';

const area = (path: string, entityType?: string): DefenseArea => ({
  path,
  label: path,
  icon: null,
  entityType,
  component: lazy(async () => ({ default: () => null })),
});

const ROUTE_SEGMENT = /^[a-z][a-z0-9_]*$/;

describe('visibleDefenseAreas', () => {
  it('keeps the areas in their registration order', () => {
    const areas = [area('hunts', 'Hunt'), area('matrix'), area('assurance')];
    expect(visibleDefenseAreas(areas, []).map((a) => a.path)).toEqual(['hunts', 'matrix', 'assurance']);
  });

  it('drops an area whose entity type is hidden on the platform', () => {
    const areas = [area('hunts', 'Hunt'), area('matrix')];
    expect(visibleDefenseAreas(areas, ['Hunt']).map((a) => a.path)).toEqual(['matrix']);
  });

  it('keeps an area that names no entity type whatever is hidden', () => {
    expect(visibleDefenseAreas([area('matrix')], ['Hunt', 'Indicator'])).toHaveLength(1);
  });
});

// The two registries are where every innovation adds its entry, so a bad entry must fail here rather
// than as a broken route or a duplicated menu row.
describe.each([
  ['DEFENSE_AREAS', DEFENSE_AREAS],
  ['CURATION_TABS', CURATION_TABS],
])('%s registry', (_name, entries) => {
  it('gives every entry a unique route segment', () => {
    const paths = entries.map((entry) => entry.path);
    expect(new Set(paths).size).toEqual(paths.length);
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
});

describe('the capability an area or a tab needs', () => {
  const granted = (needs: string[]) => needs.includes('KNOWLEDGE');
  const lazyNothing = lazy(async () => ({ default: () => null }));

  it('drops an area the user is not granted, and keeps an area that needs nothing', () => {
    const areas = [
      { ...area('hunts', 'Hunt'), needs: ['KNOWLEDGE_KNUPDATE'] },
      { ...area('matrix'), needs: ['KNOWLEDGE'] },
      area('assurance'),
    ];
    expect(visibleDefenseAreas(areas, [], granted).map((a) => a.path)).toEqual(['matrix', 'assurance']);
  });

  it('drops a tab the user is not granted', () => {
    const tabs = [
      { path: 'inbox', label: 'Inbox', needs: ['KNOWLEDGE_KNUPDATE_KNMERGE'], component: lazyNothing },
      { path: 'health', label: 'Knowledge health', component: lazyNothing },
    ];
    expect(grantedCurationTabs(tabs, granted).map((t) => t.path)).toEqual(['health']);
  });
});
