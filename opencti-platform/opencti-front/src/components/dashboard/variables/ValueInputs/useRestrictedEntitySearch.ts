import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import type { Subscription } from 'relay-runtime';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import type { useRestrictedEntitySearchQuery, useRestrictedEntitySearchQuery$variables } from './__generated__/useRestrictedEntitySearchQuery.graphql';

const restrictedEntitySearchQuery = graphql`
  query useRestrictedEntitySearchQuery($search: String, $types: [String], $first: Int, $filters: FilterGroup) {
    stixCoreObjects(search: $search, types: $types, first: $first, filters: $filters) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

// Entities listed per search: typing narrows the list further on the server.
export const RESTRICTED_ENTITY_SEARCH_SIZE = 100;

/**
 * Server side search of the entities a variable restricted by filters can take: the entities of its types that match
 * its rule. The shared filters search takes no rule, hence this query of its own. Options are grouped by entity type,
 * like the free search of an entity variable. Only the last search may answer.
 */
const useRestrictedEntitySearch = (entityTypes: string[], filters: FilterGroup | undefined) => {
  const environment = useRelayEnvironment();
  const [options, setOptions] = useState<FilterOptionValue[]>([]);
  const subscription = useRef<Subscription | null>(null);
  useEffect(() => () => subscription.current?.unsubscribe(), []);
  // Signatures keep the search stable across renders that pass new arrays or groups with the same content.
  const typesSignature = JSON.stringify(entityTypes);
  const filtersSignature = JSON.stringify(filters ?? null);
  // Options found for other types or another rule are not offered: they may not match the new one.
  useEffect(() => {
    subscription.current?.unsubscribe();
    setOptions([]);
  }, [typesSignature, filtersSignature]);

  const search = useCallback((text: string) => {
    subscription.current?.unsubscribe();
    const rule: FilterGroup | null = JSON.parse(filtersSignature);
    const variables: useRestrictedEntitySearchQuery$variables = {
      search: text,
      types: JSON.parse(typesSignature),
      first: RESTRICTED_ENTITY_SEARCH_SIZE,
      filters: rule ? normalizeFilterGroupForBackend(rule) : null,
    };
    subscription.current = fetchQuery<useRestrictedEntitySearchQuery>(environment, restrictedEntitySearchQuery, variables, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => {
          const entities = (data.stixCoreObjects?.edges ?? []).map(({ node }) => ({
            label: node.representative.main,
            value: node.id,
            type: node.entity_type,
            group: node.entity_type,
          }));
          // Grouped options must be contiguous.
          setOptions(entities.sort((a, b) => a.group.localeCompare(b.group)));
        },
        // A failed search offers nothing rather than the options of a previous text.
        error: () => setOptions([]),
      });
  }, [environment, typesSignature, filtersSignature]);

  return { options, search };
};

export default useRestrictedEntitySearch;
