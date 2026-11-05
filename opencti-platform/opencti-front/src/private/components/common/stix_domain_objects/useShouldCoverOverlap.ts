import { useCallback, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import { useShouldCoverOverlapQuery$data } from './__generated__/useShouldCoverOverlapQuery.graphql';

const PAGE_SIZE = 500;

const useShouldCoverOverlapQueryDef = graphql`
  query useShouldCoverOverlapQuery($first: Int!, $after: ID, $filters: FilterGroup) {
    stixCoreObjects(first: $first, after: $after, filters: $filters) {
      edges {
        node {
          id
        }
      }
      pageInfo {
        endCursor
        hasNextPage
      }
    }
  }
`;

const buildFilters = (securityPlatformIds: string[]) => ({
  mode: 'and',
  filters: [
    {
      key: 'entity_type',
      operator: 'eq',
      mode: 'or',
      values: ['Attack-Pattern'],
    },
    {
      key: 'regardingOf',
      operator: 'eq',
      mode: 'and',
      values: [
        {
          key: 'id',
          values: securityPlatformIds,
          operator: 'eq',
          mode: 'or',
        },
        {
          key: 'relationship_type',
          values: ['should-cover'],
          operator: 'eq',
          mode: 'or',
        },
      ],
    },
  ],
  filterGroups: [],
});

const fetchAllAttackPatternIds = async (securityPlatformIds: string[]): Promise<string[]> => {
  const filters = buildFilters(securityPlatformIds);
  const ids: string[] = [];
  let after: string | undefined;
  let hasNextPage = true;
  while (hasNextPage) {
    const { stixCoreObjects } = await fetchQuery(
      useShouldCoverOverlapQueryDef,
      { first: PAGE_SIZE, after, filters },
    ).toPromise() as useShouldCoverOverlapQuery$data;
    ids.push(...(stixCoreObjects?.edges ?? []).map(({ node }) => node.id));
    const pageInfo = stixCoreObjects?.pageInfo;
    hasNextPage = !!pageInfo?.hasNextPage && !!pageInfo.endCursor;
    after = pageInfo?.endCursor ?? undefined;
  }
  return ids;
};

/**
 * Looks up every attack pattern that the given security platforms "should-cover".
 * Pages through all results. `attackPatternIdsToOverlap` stays undefined until a lookup succeeds.
 */
const useShouldCoverOverlap = () => {
  const [attackPatternIdsToOverlap, setAttackPatternIdsToOverlap] = useState<string[] | undefined>();
  const [error, setError] = useState<Error | null>(null);
  const latestRequest = useRef(0);

  const setSecurityPlatformIds = useCallback(async (securityPlatformIds: string[]) => {
    latestRequest.current += 1;
    const request = latestRequest.current;
    if (securityPlatformIds.length === 0) {
      setError(null);
      setAttackPatternIdsToOverlap([]);
      return;
    }
    try {
      const ids = await fetchAllAttackPatternIds(securityPlatformIds);
      if (request !== latestRequest.current) return;
      setError(null);
      setAttackPatternIdsToOverlap(ids);
    } catch (e) {
      if (request !== latestRequest.current) return;
      setError(e instanceof Error ? e : new Error(String(e)));
      setAttackPatternIdsToOverlap(undefined);
    }
  }, []);

  return { attackPatternIdsToOverlap, setSecurityPlatformIds, error };
};

export default useShouldCoverOverlap;
