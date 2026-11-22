import { describe, it, expect } from 'vitest';
import { faker } from '@faker-js/faker';
import useBuildScatterData from './useBuildScatterData';
import { testRenderHook } from '../../../../../utils/tests/test-render';
import { buildTypeStyles, markerSize, PIR_THREAT_MAP_MAX_MARKER } from './pirThreatMapUtils';

const ENTITY_TYPES = ['Administrative-Area', 'City', 'Data-Source', 'Malware', 'System'];
const PALETTE = ['#111111', '#222222', '#333333', '#444444', '#555555', '#666666'];
const TYPE_STYLES = buildTypeStyles(ENTITY_TYPES, PALETTE);

const fakeSDO = (overwrites?: { refreshed_at?: Date; pir_score?: number; entity_type?: string; criteria?: number }) => {
  const { refreshed_at, pir_score, entity_type, criteria } = overwrites ?? {};
  const updated_at = faker.date.recent({ days: 30 });
  return {
    node: {
      updated_at,
      id: faker.string.uuid(),
      entity_type: entity_type ?? 'Malware',
      refreshed_at: refreshed_at ?? faker.date.soon({ days: 1, refDate: updated_at }),
      representative: {
        main: faker.animal.bird(),
      },
      pirInformation: {
        pir_score: pir_score ?? faker.number.int({ min: 25, max: 100 }),
        pir_explanation: Array.from({ length: criteria ?? 1 }, () => ({ criterion: { weight: 1 } })),
      },
    },
  };
};

const render = (edges: ReturnType<typeof fakeSDO>[], args?: { entityTypes?: string[]; scoreMin?: number }) => {
  const { hook } = testRenderHook(() => useBuildScatterData({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    stixDomainObjects: { edges } as any,
    entityTypes: args?.entityTypes ?? ENTITY_TYPES,
    typeStyles: TYPE_STYLES,
    scoreMin: args?.scoreMin,
  }));
  return hook.result.current;
};

describe('Hook: useBuildScatterData', () => {
  it('should return empty series if no SDO', () => {
    expect(render([]).series).toEqual([]);
  });

  it('should return empty series if no entity types', () => {
    expect(render([fakeSDO(), fakeSDO(), fakeSDO()], { entityTypes: [] }).series).toEqual([]);
  });

  it('should return SDO formatted into scatter data, named by type', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), criteria: 3 });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-10-01T00:00:00.000Z'), entity_type: 'City' });
    const { series } = render([sdo1, sdo2]);
    expect(series.length).toEqual(2);
    expect(series[0].name).toEqual('Malware');
    expect(series[0].data[0].meta.group[0].name).toEqual(sdo1.node.representative.main);
    expect(series[0].data[0].meta.group[0].matchedCriteria).toEqual(3);
    expect(series[1].name).toEqual('City');
  });

  it('should group SDO of the same type if close enough in time and score, highest score first', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), pir_score: 50 });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:01:00.000Z'), pir_score: 54 });
    const sdo3 = fakeSDO({ refreshed_at: new Date('2025-10-01T00:00:00.000Z') });
    const { series, markerSizes } = render([sdo1, sdo2, sdo3]);
    expect(series.length).toEqual(2);
    expect(series[0].data[0].meta.size).toEqual(2);
    expect(series[0].data[0].meta.group[0].name).toEqual(sdo2.node.representative.main);
    expect(series[0].data[0].meta.group[1].name).toEqual(sdo1.node.representative.main);
    expect(series[1].data[0].meta.size).toEqual(1);
    expect(markerSizes[0]).toBeGreaterThan(markerSizes[1]);
  });

  it('should never group two entity types in one cluster', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), pir_score: 50, entity_type: 'Malware' });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:01:00.000Z'), pir_score: 51, entity_type: 'City' });
    const { series } = render([sdo1, sdo2]);
    expect(series.length).toEqual(2);
  });

  it('should draw each type with its own colour and shape', () => {
    const sdo1 = fakeSDO({ pir_score: 50, entity_type: 'Malware' });
    const sdo2 = fakeSDO({ pir_score: 90, entity_type: 'City' });
    const { series, markerShapes } = render([sdo1, sdo2]);
    expect(series[0].data[0].fillColor).toEqual(TYPE_STYLES.Malware.color);
    expect(series[1].data[0].fillColor).toEqual(TYPE_STYLES.City.color);
    expect(series[0].data[0].fillColor).not.toEqual(series[1].data[0].fillColor);
    expect(markerShapes[0]).toEqual(TYPE_STYLES.Malware.shape);
    expect(markerShapes[1]).toEqual(TYPE_STYLES.City.shape);
  });

  it('should leave out entities below the score band', () => {
    const sdo1 = fakeSDO({ pir_score: 40, refreshed_at: new Date('2025-01-01T00:00:00.000Z') });
    const sdo2 = fakeSDO({ pir_score: 80, refreshed_at: new Date('2025-06-01T00:00:00.000Z') });
    const { series } = render([sdo1, sdo2], { scoreMin: 75 });
    expect(series.length).toEqual(1);
    expect(series[0].data[0].y).toEqual(80);
  });
});

describe('pirThreatMapUtils', () => {
  it('gives each type a distinct colour and shape pair, stable whatever the input order', () => {
    const a = buildTypeStyles(['Malware', 'City', 'System'], PALETTE);
    const b = buildTypeStyles(['System', 'Malware', 'City'], PALETTE);
    expect(a).toEqual(b);
    const pairs = Object.values(a).map(({ color, shape }) => `${color}/${shape}`);
    expect(new Set(pairs).size).toEqual(pairs.length);
  });

  it('grows the marker with the cluster size, capped', () => {
    expect(markerSize(1)).toBeLessThan(markerSize(5));
    expect(markerSize(10000)).toEqual(PIR_THREAT_MAP_MAX_MARKER);
  });
});
