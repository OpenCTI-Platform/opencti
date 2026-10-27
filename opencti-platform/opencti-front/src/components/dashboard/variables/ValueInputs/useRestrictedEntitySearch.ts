import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import type { Subscription } from 'relay-runtime';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
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
 * `error` is set when a search fails, so that a failure is not read as a rule that matches nothing, and cleared by the
 * next successful search or when the types or the rule change.
 */
const useRestrictedEntitySearch = (entityTypes: string[], filters: FilterGroup | undefined) => {
  const environment = useRelayEnvironment();
  const [options, setOptions] = useState<FilterOptionValue[]>([]);
  const subscription = useRef<Subscription | null>(null);
  useEffect(() => () => subscription.current?.unsubscribe(), []);
  // Signatures keep the search stable across renders that pass new arrays or groups with the same content.
  const typesSignature = JSON.stringify(entityTypes);
  // The rule as sent: a change that does not alter it (a filter without value yet) neither resets nor searches again.
  const filtersSignature = filters ? serializeFilterGroupForBackend(filters) : 'null';
  // A failure belongs to the types and the rule it happened for: other ones start with no failure.
  const searchSignature = `${typesSignature}${filtersSignature}`;
  const [failedSignature, setFailedSignature] = useState<string | null>(null);
  // Options found for other types or another rule are not offered: they may not match the new one.
  useEffect(() => {
    subscription.current?.unsubscribe();
    setOptions([]);
  }, [typesSignature, filtersSignature]);

  const search = useCallback((text: string) => {
    subscription.current?.unsubscribe();
    const rule: useRestrictedEntitySearchQuery$variables['filters'] = JSON.parse(filtersSignature);
    const variables: useRestrictedEntitySearchQuery$variables = {
      search: text,
      types: JSON.parse(typesSignature),
      first: RESTRICTED_ENTITY_SEARCH_SIZE,
      filters: rule,
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
          // Grouped options must be contiguous; sorted by label within a type, as the free search.
          setOptions(entities.sort((a, b) => a.group.localeCompare(b.group) || a.label.localeCompare(b.label)));
          setFailedSignature(null);
        },
        // A failed search offers nothing rather than the options of a previous text, and says so.
        error: () => {
          setOptions([]);
          setFailedSignature(searchSignature);
        },
      });
  }, [environment, typesSignature, filtersSignature, searchSignature]);

  return { options, search, error: failedSignature === searchSignature };
};

export default useRestrictedEntitySearch;
