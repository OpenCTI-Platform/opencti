import { graphql } from 'react-relay';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import type { ProcedureWithTechniques } from '../../techniques/attack_patterns/attack_patterns_matrix/procedureHeatmap';
import type { StixDomainObjectAttackPatternsProcedureHeatmapQuery$data } from './__generated__/StixDomainObjectAttackPatternsProcedureHeatmapQuery.graphql';

// Entities whose matrix offers the procedure heatmap.
export const PROCEDURE_HEATMAP_ENTITY_TYPES = ['Campaign', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'];

export const stixDomainObjectAttackPatternsProcedureHeatmapQuery = graphql`
  query StixDomainObjectAttackPatternsProcedureHeatmapQuery($filters: FilterGroup) {
    procedures(first: 500, filters: $filters) {
      edges {
        node {
          id
          name
          stixCoreRelationships(relationship_type: "implements-technique", toTypes: ["Attack-Pattern"], first: 100) {
            edges {
              node {
                to {
                  ... on AttackPattern {
                    id
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

// The procedures the entity uses, directly or through an inferred relationship.
export const buildProcedureHeatmapFilters = (entityId: string): FilterGroup => ({
  mode: 'and',
  filters: [{
    key: 'regardingOf',
    operator: 'eq',
    mode: 'and',
    values: [{ key: 'id', values: [entityId] }, { key: 'relationship_type', values: ['uses'] }],
  }],
  filterGroups: [],
});

export const toProceduresWithTechniques = (data: StixDomainObjectAttackPatternsProcedureHeatmapQuery$data): ProcedureWithTechniques[] => (
  (data.procedures?.edges ?? []).flatMap((edge) => {
    const procedure = edge?.node;
    if (!procedure) return [];
    const techniqueIds = (procedure.stixCoreRelationships?.edges ?? [])
      .map((relationship) => relationship?.node.to?.id)
      .filter((id): id is string => !!id);
    return [{ id: procedure.id, name: procedure.name, techniqueIds }];
  })
);
