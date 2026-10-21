import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import { DEFENSE_AREAS, type DefenseArea, visibleDefenseAreas } from './defenseAreas';

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
    const areas = [area('hunts', 'Hunt'), area('second'), area('third')];
    expect(visibleDefenseAreas(areas, []).map((a) => a.path)).toEqual(['hunts', 'second', 'third']);
  });

  it('drops an area whose entity type is hidden on the platform', () => {
    const areas = [area('hunts', 'Hunt'), area('second')];
    expect(visibleDefenseAreas(areas, ['Hunt']).map((a) => a.path)).toEqual(['second']);
  });

  it('keeps an area that names no entity type whatever is hidden', () => {
    expect(visibleDefenseAreas([area('second')], ['Hunt', 'Indicator'])).toHaveLength(1);
  });
});

// The registry is where every area adds its entry, so a bad entry must fail here rather than as a
// broken route or a duplicated menu row.
describe('DEFENSE_AREAS registry', () => {
  it('registers the Hunts area', () => {
    expect(DEFENSE_AREAS.map((entry) => entry.path)).toContain('hunts');
  });

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
});

describe('the capability an area needs', () => {
  const granted = (needs: string[]) => needs.includes('KNOWLEDGE');

  it('drops an area the user is not granted, and keeps an area that needs nothing', () => {
    const areas = [
      { ...area('hunts', 'Hunt'), needs: ['KNOWLEDGE_KNUPDATE'] },
      { ...area('second'), needs: ['KNOWLEDGE'] },
      area('third'),
    ];
    expect(visibleDefenseAreas(areas, [], granted).map((a) => a.path)).toEqual(['second', 'third']);
  });
});
