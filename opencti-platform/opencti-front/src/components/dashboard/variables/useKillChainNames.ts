import { useEffect, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import type { useKillChainNamesQuery } from './__generated__/useKillChainNamesQuery.graphql';

// Distinct values of `kill_chain_name`, an aggregation on the attribute (only the kill chain phases carry it).
const killChainNamesQuery = graphql`
  query useKillChainNamesQuery($first: Int) {
    runtimeAttributes(attributeName: "kill_chain_name", first: $first, orderMode: asc) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

// Kill chains listed at most: far beyond what a platform holds (a handful, usually).
export const KILL_CHAIN_NAMES_LIMIT = 500;

/**
 * The names of the kill chains that exist in the platform, sorted, or null while they load (none if the query fails).
 * They come out of the search index normalized (lower case, without accents): the phases of a kill chain are matched
 * the same way on the server (useKillChainPhaseSearch), so a chosen name always finds its phases.
 */
const useKillChainNames = (): string[] | null => {
  const environment = useRelayEnvironment();
  const [names, setNames] = useState<string[] | null>(null);

  useEffect(() => {
    const subscription = fetchQuery<useKillChainNamesQuery>(environment, killChainNamesQuery, { first: KILL_CHAIN_NAMES_LIMIT }, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => setNames((data.runtimeAttributes?.edges ?? []).map(({ node }) => node.value)),
        error: () => setNames([]),
      });
    return () => subscription.unsubscribe();
  }, [environment]);

  return names;
};

export default useKillChainNames;
