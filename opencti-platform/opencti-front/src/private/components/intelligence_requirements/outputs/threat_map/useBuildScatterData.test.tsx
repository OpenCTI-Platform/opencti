import { describe, it, expect } from 'vitest';
import { faker } from '@faker-js/faker';
import useBuildScatterData from './useBuildScatterData';
import { testRenderHook } from '../../../../../utils/tests/test-render';
import { buildTypeStyles, IR_THREAT_MAP_MAX_MARKER, IrThreatMapMarker, IrThreatMapMatch, markerSize, toThreatMapMarkers } from './irThreatMapUtils';

const ENTITY_TYPES = ['Administrative-Area', 'City', 'Data-Source', 'Malware', 'System'];
const PALETTE = ['#111111', '#222222', '#333333', '#444444', '#555555', '#666666'];
const TYPE_STYLES = buildTypeStyles(ENTITY_TYPES, PALETTE);

const fakeMarker = (overwrites?: { date?: Date; score?: number; type?: string; criteria?: number }): IrThreatMapMarker => {
  const { date, score, type, criteria } = overwrites ?? {};
  return {
    id: faker.string.uuid(),
    entityId: faker.string.uuid(),
    date: (date ?? faker.date.recent({ days: 30 })).toISOString(),
    score: score ?? faker.number.int({ min: 25, max: 100 }),
    name: faker.animal.bird(),
    type: type ?? 'Malware',
    matchedCriteria: criteria ?? 1,
  };
};

const render = (markers: IrThreatMapMarker[], args?: { entityTypes?: string[]; scoreMin?: number }) => {
  const { hook } = testRenderHook(() => useBuildScatterData({
    markers,
    entityTypes: args?.entityTypes ?? ENTITY_TYPES,
    typeStyles: TYPE_STYLES,
    scoreMin: args?.scoreMin,
  }));
  return hook.result.current;
};

describe('Hook: useBuildScatterData', () => {
  it('should return empty series if no marker', () => {
    expect(render([]).series).toEqual([]);
  });

  it('should return empty series if no entity types', () => {
    expect(render([fakeMarker(), fakeMarker(), fakeMarker()], { entityTypes: [] }).series).toEqual([]);
  });

  it('should return markers formatted into scatter data, named by type', () => {
    const m1 = fakeMarker({ date: new Date('2025-01-01T00:00:00.000Z'), criteria: 3 });
    const m2 = fakeMarker({ date: new Date('2025-10-01T00:00:00.000Z'), type: 'City' });
    const { series } = render([m1, m2]);
    expect(series.length).toEqual(2);
    expect(series[0].name).toEqual('Malware');
    expect(series[0].data[0].meta.group[0].name).toEqual(m1.name);
    expect(series[0].data[0].meta.group[0].matchedCriteria).toEqual(3);
    expect(series[1].name).toEqual('City');
  });

  it('should group markers of the same type if close enough in time and score, highest score first', () => {
    const m1 = fakeMarker({ date: new Date('2025-01-01T00:00:00.000Z'), score: 50 });
    const m2 = fakeMarker({ date: new Date('2025-01-01T00:01:00.000Z'), score: 54 });
    const m3 = fakeMarker({ date: new Date('2025-10-01T00:00:00.000Z') });
    const { series, markerSizes } = render([m1, m2, m3]);
    expect(series.length).toEqual(2);
    expect(series[0].data[0].meta.size).toEqual(2);
    expect(series[0].data[0].meta.group[0].name).toEqual(m2.name);
    expect(series[0].data[0].meta.group[1].name).toEqual(m1.name);
    expect(series[1].data[0].meta.size).toEqual(1);
    expect(markerSizes[0]).toBeGreaterThan(markerSizes[1]);
  });

  it('should never group two entity types in one cluster', () => {
    const m1 = fakeMarker({ date: new Date('2025-01-01T00:00:00.000Z'), score: 50, type: 'Malware' });
    const m2 = fakeMarker({ date: new Date('2025-01-01T00:01:00.000Z'), score: 51, type: 'City' });
    expect(render([m1, m2]).series.length).toEqual(2);
  });

  it('should draw each type with its own colour and shape', () => {
    const m1 = fakeMarker({ score: 50, type: 'Malware' });
    const m2 = fakeMarker({ score: 90, type: 'City' });
    const { series, markerShapes } = render([m1, m2]);
    expect(series[0].data[0].fillColor).toEqual(TYPE_STYLES.Malware.color);
    expect(series[1].data[0].fillColor).toEqual(TYPE_STYLES.City.color);
    expect(series[0].data[0].fillColor).not.toEqual(series[1].data[0].fillColor);
    expect(markerShapes[0]).toEqual(TYPE_STYLES.Malware.shape);
    expect(markerShapes[1]).toEqual(TYPE_STYLES.City.shape);
  });

  it('should leave out entities below the score band', () => {
    const m1 = fakeMarker({ score: 40, date: new Date('2025-01-01T00:00:00.000Z') });
    const m2 = fakeMarker({ score: 80, date: new Date('2025-06-01T00:00:00.000Z') });
    const { series } = render([m1, m2], { scoreMin: 75 });
    expect(series.length).toEqual(1);
    expect(series[0].data[0].y).toEqual(80);
  });
});

describe('irThreatMapUtils', () => {
  it('gives each type a distinct colour and shape pair, stable whatever the input order', () => {
    const a = buildTypeStyles(['Malware', 'City', 'System'], PALETTE);
    const b = buildTypeStyles(['System', 'Malware', 'City'], PALETTE);
    expect(a).toEqual(b);
    const pairs = Object.values(a).map(({ color, shape }) => `${color}/${shape}`);
    expect(new Set(pairs).size).toEqual(pairs.length);
  });

  it('grows the marker with the cluster size, capped', () => {
    expect(markerSize(1)).toBeLessThan(markerSize(5));
    expect(markerSize(10000)).toEqual(IR_THREAT_MAP_MAX_MARKER);
  });

  describe('toThreatMapMarkers', () => {
    const NOW = new Date('2026-11-23T00:00:00.000Z').getTime();
    const match = (overwrites: Partial<IrThreatMapMatch>): IrThreatMapMatch => ({
      id: 'match-1',
      match_status: 'auto',
      match_excluded: false,
      match_score: 60,
      match_entity_id: 'entity-1',
      match_entity_type: 'Vulnerability',
      match_entity_name: 'CVE-2024-7347',
      match_last_fact_at: '2026-11-20T10:00:00.000Z',
      match_criteria_ids: ['c1', 'c2'],
      entity: null,
      ...overwrites,
    });

    it('places an entity of the requirement by its last fact and score, keyed by the match id', () => {
      expect(toThreatMapMarkers([match({})], 7, NOW)).toEqual([{
        id: 'match-1',
        entityId: 'entity-1',
        date: '2026-11-20T10:00:00.000Z',
        score: 60,
        name: 'CVE-2024-7347',
        type: 'Vulnerability',
        matchedCriteria: 2,
      }]);
    });

    it('keeps proposed entities and leaves out the rejected, removed and no longer eligible ones', () => {
      const markers = toThreatMapMarkers([
        match({ id: 'proposed', match_status: 'proposed' }),
        match({ id: 'accepted', match_status: 'accepted' }),
        match({ id: 'rejected', match_status: 'rejected' }),
        match({ id: 'removed', match_status: 'removed' }),
        match({ id: 'excluded', match_excluded: true }),
      ], 7, NOW);
      expect(markers.map((m) => m.id)).toEqual(['proposed', 'accepted']);
    });

    it('leaves out an entity without a dated fact or outside the window', () => {
      const markers = toThreatMapMarkers([
        match({ id: 'undated', match_last_fact_at: null }),
        match({ id: 'invalid', match_last_fact_at: 'not a date' }),
        match({ id: 'old', match_last_fact_at: '2026-10-01T00:00:00.000Z' }),
        match({ id: 'future', match_last_fact_at: '2026-12-01T00:00:00.000Z' }),
        match({ id: 'in' }),
      ], 7, NOW);
      expect(markers.map((m) => m.id)).toEqual(['in']);
      expect(toThreatMapMarkers([match({ id: 'old', match_last_fact_at: '2026-10-01T00:00:00.000Z' })], 90, NOW)).toHaveLength(1);
    });

    it('names the entity by its match name, then its representative, then its id', () => {
      const [byRepresentative, byId] = toThreatMapMarkers([
        match({ id: 'a', match_entity_name: null, entity: { representative: { main: 'NGINX 1.27.1' } } }),
        match({ id: 'b', match_entity_name: null, entity: null }),
      ], 7, NOW);
      expect(byRepresentative.name).toEqual('NGINX 1.27.1');
      expect(byId.name).toEqual('entity-1');
    });
  });
});
