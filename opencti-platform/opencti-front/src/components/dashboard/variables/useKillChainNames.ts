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

export type KillChainNamesStatus = 'loading' | 'ready' | 'error';

export interface KillChainNames {
  names: string[];
  status: KillChainNamesStatus;
}

/**
 * The names of the kill chains that exist in the platform, sorted, and the state of their lookup: `loading`, `ready`
 * or `error` (then no name: the lookup needs the knowledge access, and the search index may be unavailable).
 * They come out of the search index normalized (lower case, without accents): the phases of a kill chain are matched
 * the same way on the server (useKillChainPhaseSearch), so a chosen name always finds its phases.
 * `store-and-network`: the names already in the store are shown at once, and the network refreshes them on every mount,
 * so a kill chain created since the first load is listed without reloading the page.
 */
const useKillChainNames = (): KillChainNames => {
  const environment = useRelayEnvironment();
  const [state, setState] = useState<KillChainNames>({ names: [], status: 'loading' });

  useEffect(() => {
    const subscription = fetchQuery<useKillChainNamesQuery>(environment, killChainNamesQuery, { first: KILL_CHAIN_NAMES_LIMIT }, { fetchPolicy: 'store-and-network' })
      .subscribe({
        next: (data) => setState({ names: (data.runtimeAttributes?.edges ?? []).map(({ node }) => node.value), status: 'ready' }),
        // The names of the store, when there were any, stay usable if only the refresh fails.
        error: () => setState((previous) => (previous.status === 'ready' ? previous : { names: [], status: 'error' })),
      });
    return () => subscription.unsubscribe();
  }, [environment]);

  return state;
};

export default useKillChainNames;
