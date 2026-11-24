import { describe, expect, it } from 'vitest';
import { buildProcedureHeatmapFilters, PROCEDURE_HEATMAP_ENTITY_TYPES, toProceduresWithTechniques } from './StixDomainObjectAttackPatternsProcedureHeatmap';
import type { StixDomainObjectAttackPatternsProcedureHeatmapQuery$data } from './__generated__/StixDomainObjectAttackPatternsProcedureHeatmapQuery.graphql';

const sampleData = {
  procedures: {
    edges: [{
      node: {
        id: 'p1',
        name: 'P1',
        stixCoreRelationships: { edges: [{ node: { to: { id: 'ap1' } } }, { node: { to: { id: 'ap2' } } }, { node: { to: null } }] },
      },
    }],
  },
} as unknown as StixDomainObjectAttackPatternsProcedureHeatmapQuery$data;

describe('StixDomainObjectAttackPatternsProcedureHeatmap', () => {
  it('asks for the procedures the entity uses, direct or inferred', () => {
    expect(buildProcedureHeatmapFilters('e1')).toEqual({
      mode: 'and',
      filterGroups: [],
      filters: [{ key: 'regardingOf', operator: 'eq', mode: 'and', values: [{ key: 'id', values: ['e1'] }, { key: 'relationship_type', values: ['uses'] }] }],
    });
  });
  it('maps each procedure to the attack pattern ids it implements', () => {
    expect(toProceduresWithTechniques(sampleData)).toEqual([{ id: 'p1', name: 'P1', techniqueIds: ['ap1', 'ap2'] }]);
  });
  it('returns no procedures for an empty result', () => {
    expect(toProceduresWithTechniques({ procedures: { edges: [] } } as unknown as StixDomainObjectAttackPatternsProcedureHeatmapQuery$data)).toEqual([]);
  });
  it('offers the heatmap only on campaigns, intrusion sets and threat actors', () => {
    expect(PROCEDURE_HEATMAP_ENTITY_TYPES).toEqual(['Campaign', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual']);
  });
});
