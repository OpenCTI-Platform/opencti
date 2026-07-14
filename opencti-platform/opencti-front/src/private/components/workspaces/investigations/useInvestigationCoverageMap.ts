import { useEffect, useMemo, useState } from 'react';
import { graphql } from 'react-relay';
import { ObjectToParse } from '../../../../components/graph/utils/useGraphParser';
import { fetchQuery } from '../../../../relay/environment';
import { useInvestigationCoverageMapQuery } from './__generated__/useInvestigationCoverageMapQuery.graphql';

export type CoverageInformation = ReadonlyArray<{
  readonly coverage_name: string;
  readonly coverage_score: number;
}>;

// Fetches the detection/prevention coverage scores carried by the `has-covered`
// relationships. Coverage scores are a computed field on the relationship and
// are NOT part of the investigation graph payload, so they must be fetched
// separately, scoped to the Security-Coverage entities present on the graph.
const investigationMatrixCoverageQuery = graphql`
  query useInvestigationCoverageMapQuery($filters: FilterGroup, $count: Int!) {
    stixCoreRelationships(
      relationship_type: "has-covered"
      toTypes: ["Attack-Pattern"]
      filters: $filters
      first: $count
    ) {
      edges {
        node {
          id
          coverage_information {
            coverage_name
            coverage_score
          }
          to {
            ... on AttackPattern {
              id
            }
          }
        }
      }
    }
  }
`;

const isRelationship = (o: ObjectToParse): boolean => (o.parent_types ?? []).includes('basic-relationship')
  || Boolean(o.relationship_type);

const isAttackPattern = (entityType?: string): boolean => entityType === 'Attack-Pattern';

/**
 * Build a `Map<attackPatternId, CoverageInformation>` from the `has-covered`
 * relationships present in the investigation graph.
 *
 * Only relationships that are actually on the graph are considered: results
 * from the supplementary query are filtered down to the relationship ids
 * present in the investigation.
 */
const useInvestigationCoverageMap = (
  objects: ObjectToParse[],
): Map<string, CoverageInformation> => {
  const [coverageMap, setCoverageMap] = useState<Map<string, CoverageInformation>>(new Map());

  // Collect the `has-covered` relationships present in the investigation:
  // the Security-Coverage entity ids (relationship source) and the set of
  // relationship ids we are allowed to display.
  const { coverageEntityIds, presentRelationshipIds } = useMemo(() => {
    const entityIds = new Set<string>();
    const relIds = new Set<string>();
    objects
      .filter((o) => isRelationship(o) && o.relationship_type === 'has-covered' && o.from && o.to)
      .forEach((rel) => {
        const from = rel.from!;
        const to = rel.to!;
        // has-covered goes Security-Coverage -> Attack-Pattern; the source is the coverage.
        const coverageId = isAttackPattern(to.entity_type) ? from.id : to.id;
        entityIds.add(coverageId);
        relIds.add(rel.id);
      });
    return { coverageEntityIds: [...entityIds], presentRelationshipIds: relIds };
  }, [objects]);

  // Stable key to avoid refetching on every render.
  const coverageKey = coverageEntityIds.slice().sort().join(',');

  useEffect(() => {
    let cancelled = false;
    if (coverageEntityIds.length === 0) {
      setCoverageMap(new Map());
      return () => {
        cancelled = true;
      };
    }
    const filters = {
      mode: 'and',
      filters: [{ key: 'fromId', values: coverageEntityIds, operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    fetchQuery(investigationMatrixCoverageQuery, { filters, count: 500 })
      .toPromise()
      .then((data) => {
        if (cancelled) return;
        const typedData = data as useInvestigationCoverageMapQuery['response'];
        const nextMap = new Map<string, CoverageInformation>();
        (typedData?.stixCoreRelationships?.edges ?? []).forEach((edge) => {
          const node = edge?.node;
          // Only keep relationships that are present in the investigation graph.
          if (!node || !node.to?.id || !presentRelationshipIds.has(node.id)) {
            return;
          }
          const attackPatternId = node.to.id;
          const existing = nextMap.get(attackPatternId) ?? [];
          nextMap.set(attackPatternId, [...existing, ...(node.coverage_information ?? [])]);
        });
        setCoverageMap(nextMap);
      });
    return () => {
      cancelled = true;
    };
  }, [coverageKey]);

  return coverageMap;
};

export default useInvestigationCoverageMap;
