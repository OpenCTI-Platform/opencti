import { describe, it, expect } from 'vitest';
import { faker } from '@faker-js/faker';
import useBuildScatterData from './useBuildScatterData';
import { testRenderHook } from '../../../../../utils/tests/test-render';
import { itemColor } from '../../../../../utils/Colors';

const ENTITY_TYPES = ['Administrative-Area', 'City', 'Data-Source', 'Malware', 'System'];

const fakeSDO = (overwrites?: { refreshed_at?: Date, pir_score?: number }) => {
  const { refreshed_at, pir_score } = overwrites ?? {};
  const updated_at = faker.date.recent({ days: 30 });
  return {
    node: {
      updated_at,
      id: faker.string.uuid(),
      entity_type: faker.helpers.arrayElement(ENTITY_TYPES),
      refreshed_at: refreshed_at ?? faker.date.soon({ days: 1, refDate: updated_at }),
      representative: {
        main: faker.animal.bird(),
      },
      pirInformation: {
        pir_score: pir_score ?? faker.number.int({ min: 25, max: 100 }),
      },
    },
  };
};

describe('Hook: useBuildScatterData', () => {
  it('should return empty array if no SDO', () => {
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: ENTITY_TYPES });
    });
    const data = hook.result.current;
    expect(data).toEqual([]);
  });

  it('should return empty array if no entity types', () => {
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [fakeSDO(), fakeSDO(), fakeSDO()] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: [] });
    });
    const data = hook.result.current;
    expect(data).toEqual([]);
  });

  it('should return SDO formatted into scatter data', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z') });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-10-01T00:00:00.000Z') });
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [sdo1, sdo2] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: ENTITY_TYPES });
    });
    const data = hook.result.current;
    expect(data.length).toEqual(2);
    expect(data[0].data[0].meta.group[0].name).toEqual(sdo1.node.representative.main);
    expect(data[1].data[0].meta.group[0].name).toEqual(sdo2.node.representative.main);
  });

  it('should group SDO if close enough in time and score', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), pir_score: 50 });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:01:00.000Z'), pir_score: 54 });
    const sdo3 = fakeSDO({ refreshed_at: new Date('2025-10-01T00:00:00.000Z') });
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [sdo1, sdo2, sdo3] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: ENTITY_TYPES });
    });
    const data = hook.result.current;
    expect(data.length).toEqual(2);
    expect(data[0].data[0].meta.size).toEqual(2);
    expect(data[1].data[0].meta.size).toEqual(1);
    expect(data[0].data[0].meta.group[0].name).toEqual(sdo1.node.representative.main);
    expect(data[0].data[0].meta.group[0].name).toEqual(sdo1.node.representative.main);
    expect(data[0].data[0].meta.group[1].name).toEqual(sdo2.node.representative.main);
    expect(data[1].data[0].meta.group[0].name).toEqual(sdo3.node.representative.main);
  });

  it('should set group color as white if multiple entity in group', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), pir_score: 50 });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:01:00.000Z'), pir_score: 54 });
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [sdo1, sdo2] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: ENTITY_TYPES });
    });
    const data = hook.result.current;
    expect(data.length).toEqual(1);
    expect(data[0].data[0].meta.size).toEqual(2);
    expect(data[0].data[0].fillColor).toEqual('#ffffff');
  });

  it('should set group color as type color if one entity in group', () => {
    const sdo1 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:00:00.000Z'), pir_score: 50 });
    const sdo2 = fakeSDO({ refreshed_at: new Date('2025-01-01T00:01:00.000Z'), pir_score: 80 });
    const { hook } = testRenderHook(() => {
      const stixDomainObjects = { edges: [sdo1, sdo2] };
      return useBuildScatterData({ stixDomainObjects, entityTypes: ENTITY_TYPES });
    });
    const data = hook.result.current;
    expect(data.length).toEqual(2);
    expect(data[0].data[0].meta.size).toEqual(1);
    expect(data[0].data[0].fillColor).toEqual(itemColor(sdo1.node.entity_type));
    expect(data[1].data[0].fillColor).toEqual(itemColor(sdo2.node.entity_type));
  });
});
