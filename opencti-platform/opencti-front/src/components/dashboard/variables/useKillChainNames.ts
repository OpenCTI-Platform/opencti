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
 * `network-only`: the names are fetched again on every mount of the dialog, so a kill chain created since the first
 * load is listed without reloading the page (the list is a small aggregation, `fetchQuery` has no `store-and-network`).
 */
const useKillChainNames = (): KillChainNames => {
  const environment = useRelayEnvironment();
  const [state, setState] = useState<KillChainNames>({ names: [], status: 'loading' });

  useEffect(() => {
    const subscription = fetchQuery<useKillChainNamesQuery>(environment, killChainNamesQuery, { first: KILL_CHAIN_NAMES_LIMIT }, { fetchPolicy: 'network-only' })
      .subscribe({
        next: (data) => setState({ names: (data.runtimeAttributes?.edges ?? []).map(({ node }) => node.value), status: 'ready' }),
        // Names already received stay usable if a later emission fails.
        error: () => setState((previous) => (previous.status === 'ready' ? previous : { names: [], status: 'error' })),
      });
    return () => subscription.unsubscribe();
  }, [environment]);

  return state;
};

export default useKillChainNames;
