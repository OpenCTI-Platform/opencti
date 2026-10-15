import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import type { Subscription } from 'relay-runtime';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import type { useKillChainPhaseSearchQuery, useKillChainPhaseSearchQuery$variables } from './__generated__/useKillChainPhaseSearchQuery.graphql';

const killChainPhaseSearchQuery = graphql`
  query useKillChainPhaseSearchQuery($search: String, $first: Int, $filters: FilterGroup) {
    killChainPhases(search: $search, first: $first, filters: $filters, orderBy: x_opencti_order, orderMode: asc) {
      edges {
        node {
          id
          kill_chain_name
          phase_name
        }
      }
    }
  }
`;

// Phases listed per search: typing narrows the list further on the server.
export const KILL_CHAIN_PHASE_SEARCH_SIZE = 100;

// Restricts the search to the phases of one kill chain, on the server.
export const killChainNameFilters = (killChainName: string): useKillChainPhaseSearchQuery$variables['filters'] => ({
  mode: 'and',
  filters: [{ key: ['kill_chain_name'], values: [killChainName], operator: 'eq', mode: 'or' }],
  filterGroups: [],
});

/**
 * Server side search of the phases of the kill chain of a variable. The shared filters search lists one unscoped page
 * of every phase: with many phases in the platform, those of the kill chain could all fall outside of it.
 * Each search replaces the options with its result, labelled `[kill chain name] phase name` like the filters do.
 * `reset` puts back the result of the last search of an empty text (the whole kill chain), without a new request.
 */
const useKillChainPhaseSearch = (killChainName: string | undefined) => {
  const environment = useRelayEnvironment();
  const [options, setOptions] = useState<FilterOptionValue[]>([]);
  // Only the last search may answer: an earlier, slower one would put back the options of a previous text.
  const subscription = useRef<Subscription | null>(null);
  useEffect(() => () => subscription.current?.unsubscribe(), []);
  // Phases of the whole kill chain, as last answered for an empty text.
  const unfiltered = useRef<FilterOptionValue[]>([]);

  const search = useCallback((text: string) => {
    subscription.current?.unsubscribe();
    const variables: useKillChainPhaseSearchQuery$variables = {
      search: text,
      first: KILL_CHAIN_PHASE_SEARCH_SIZE,
      filters: killChainName ? killChainNameFilters(killChainName) : null,
    };
    subscription.current = fetchQuery<useKillChainPhaseSearchQuery>(environment, killChainPhaseSearchQuery, variables, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => {
          const phases = (data.killChainPhases?.edges ?? []).map(({ node }) => ({
            label: `[${node.kill_chain_name}] ${node.phase_name}`,
            value: node.id,
            type: 'Kill-Chain-Phase',
          }));
          if (text === '') unfiltered.current = phases;
          setOptions(phases);
        },
        // A failed search offers nothing rather than the options of a previous text.
        error: () => setOptions([]),
      });
  }, [environment, killChainName]);

  const reset = useCallback(() => {
    subscription.current?.unsubscribe();
    setOptions(unfiltered.current);
  }, []);

  return { options, search, reset };
};

export default useKillChainPhaseSearch;
