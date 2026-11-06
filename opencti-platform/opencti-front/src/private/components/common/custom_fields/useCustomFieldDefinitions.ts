import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import type { useCustomFieldDefinitionsQuery, useCustomFieldDefinitionsQuery$data } from './__generated__/useCustomFieldDefinitionsQuery.graphql';

const customFieldDefinitionsQuery = graphql`
  query useCustomFieldDefinitionsQuery {
    customFieldDefinitions(first: 500) {
      edges {
        node {
          id
          name
          label
          field_type
          min_value
          max_value
          select_options
          entity_types
          entity_type_settings {
            entity_type
            mandatory
            default_value
          }
        }
      }
    }
  }
`;

export type CustomFieldDefinition = NonNullable<NonNullable<useCustomFieldDefinitionsQuery$data['customFieldDefinitions']>['edges']>[number]['node'];

// Definitions attached to no entity type are of no use on knowledge, they are not kept.
export const fetchCustomFieldDefinitions = async (): Promise<CustomFieldDefinition[]> => {
  const data = await fetchQuery<useCustomFieldDefinitionsQuery>(customFieldDefinitionsQuery, {}).toPromise();
  return (data?.customFieldDefinitions?.edges ?? [])
    .map((edge) => edge.node)
    .filter((definition) => (definition.entity_types ?? []).length > 0);
};

/**
 * All the custom field definitions attached to an entity type, for the screens acting on any entity type
 * (playbooks, background tasks).
 * They are loaded once, when `enabled` (e.g. only once some elements are selected).
 */
const useCustomFieldDefinitions = (enabled = true): CustomFieldDefinition[] => {
  const [definitions, setDefinitions] = useState<CustomFieldDefinition[] | null>(null);
  const shouldLoad = enabled && definitions === null;
  useEffect(() => {
    if (!shouldLoad) return undefined;
    let isMounted = true;
    fetchCustomFieldDefinitions()
      .then((result) => {
        if (isMounted) setDefinitions(result);
      })
      .catch(() => {
        if (isMounted) setDefinitions([]);
      });
    return () => {
      isMounted = false;
    };
  }, [shouldLoad]);
  return definitions ?? [];
};

export default useCustomFieldDefinitions;
