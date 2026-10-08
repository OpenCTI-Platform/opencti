import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import { DEFENSE_AREAS, type DefenseArea, defenseAreaSection, visibleDefenseAreas } from './defenseAreas';

const area = (path: string, needs?: string[]): DefenseArea => ({
  order: 0,
  path,
  label: path,
  icon: null,
  needs,
  component: lazy(async () => ({ default: () => null })),
});

const ROUTE_SEGMENT = /^[a-z][a-z0-9_-]*$/;

describe('visibleDefenseAreas', () => {
  it('keeps the areas in their registration order', () => {
    const areas = [area('matrix'), area('second'), area('third')];
    expect(visibleDefenseAreas(areas).map((a) => a.path)).toEqual(['matrix', 'second', 'third']);
  });

  it('drops an area the user is not granted, and keeps an area that needs nothing', () => {
    const granted = (needs: string[]) => needs.includes('KNOWLEDGE');
    const areas = [area('restricted', ['KNOWLEDGE_KNUPDATE']), area('matrix', ['KNOWLEDGE']), area('open')];
    expect(visibleDefenseAreas(areas, granted).map((a) => a.path)).toEqual(['matrix', 'open']);
  });
});

// The registry is where every Defense area adds its entry, so a bad entry must fail here rather than
// as a broken route or a duplicated menu row.
describe('DEFENSE_AREAS registry', () => {
  it('gives every entry a unique route segment', () => {
    const paths = DEFENSE_AREAS.map((entry) => entry.path);
    expect(new Set(paths).size).toEqual(paths.length);
  });

  it('gives every entry its own position, in ascending order', () => {
    const orders = DEFENSE_AREAS.map((entry) => entry.order);
    expect(new Set(orders).size).toEqual(orders.length);
    expect(orders).toEqual([...orders].sort((a, b) => a - b));
  });

  it('uses lowercase route segments, as the rest of the dashboard does', () => {
    DEFENSE_AREAS.forEach((entry) => expect(entry.path).toMatch(ROUTE_SEGMENT));
  });

  it('labels every entry with a sentence-case source string', () => {
    DEFENSE_AREAS.forEach((entry) => {
      expect(entry.label.trim()).not.toEqual('');
      expect(entry.label[0]).toEqual(entry.label[0].toUpperCase());
    });
  });

  it('describes an entry, when it does, with a sentence-case source string', () => {
    DEFENSE_AREAS.forEach((entry) => {
      if (entry.description === undefined) return;
      expect(entry.description.trim()).not.toEqual('');
      expect(entry.description[0]).toEqual(entry.description[0].toUpperCase());
    });
  });

  it('gives every area page a unique lowercase segment and a sentence-case label', () => {
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
  const matrix: DefenseArea = {
    ...area('matrix'),
    sections: [{ path: 'coverage', label: 'Matrix' }, { path: 'gaps', label: 'Gaps' }],
  };

  it('finds the section a path opens, its own sub-paths included', () => {
    expect(defenseAreaSection(matrix, 'gaps')?.label).toEqual('Gaps');
    expect(defenseAreaSection(matrix, 'gaps/gap-1')?.label).toEqual('Gaps');
  });

  it('finds no section for the area root, an unknown path or a path that only starts like one', () => {
    expect(defenseAreaSection(matrix, '')).toBeUndefined();
    expect(defenseAreaSection(matrix, 'unknown')).toBeUndefined();
    expect(defenseAreaSection(matrix, 'gapsx')).toBeUndefined();
    expect(defenseAreaSection(area('second'), 'details')).toBeUndefined();
  });
});
