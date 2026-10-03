import { useEffect, useMemo, useState } from 'react';
import { graphql } from 'react-relay';
import type { WidgetColumn } from '../../../utils/widget/widget';
import { customFieldDefinitionsToWidgetColumns, type CustomFieldWidgetDefinition } from '../../../utils/customFields';
import useHelper from '../../../utils/hooks/useHelper';
import { fetchQuery } from '../../../relay/environment';
import type { useCustomFieldWidgetColumnsQuery } from './__generated__/useCustomFieldWidgetColumnsQuery.graphql';
const customFieldWidgetColumnsQuery = graphql`
  query useCustomFieldWidgetColumnsQuery {
    customFieldDefinitions(first: 500) {
      edges {
        node {
          id
          name
          label
          field_type
          entity_types
        }
      }
    }
  }
`;
export interface UseCustomFieldWidgetColumnsResult {
  columns: WidgetColumn[];
  // True while the definitions are being fetched (feature enabled) so callers relying on
  // `columns` to validate/clean up an already-selected value can wait instead of wrongly
  // treating not-yet-loaded custom field columns as unavailable/removed.
  loading: boolean;
}
/**
 * Centralizes the loading of custom field definitions for widgets (attribute widget available
 * attributes, list/custom-attributes widget available columns), so callers don't have to each
 * implement their own fetching/feature-flag-gating strategy.
 *
 * Returns an empty, non-loading result if the CUSTOM_FIELDS feature flag is disabled (the
 * underlying query field throws server-side in that case, so it must never be called then).
 * When `entityType` is provided, only the definitions applicable to that entity type (or with no
 * entity type restriction at all) are kept.
 */
const useCustomFieldWidgetColumns = (entityType?: string): UseCustomFieldWidgetColumnsResult => {
  const { isFeatureEnable } = useHelper();
  const isCustomFieldsEnabled = isFeatureEnable('CUSTOM_FIELDS');
  const [definitions, setDefinitions] = useState<CustomFieldWidgetDefinition[]>([]);
  const [loading, setLoading] = useState(isCustomFieldsEnabled);
  useEffect(() => {
    if (!isCustomFieldsEnabled) {
      setDefinitions([]);
      setLoading(false);
      return undefined;
    }
    let isMounted = true;
    setLoading(true);
    fetchQuery<useCustomFieldWidgetColumnsQuery>(customFieldWidgetColumnsQuery, {})
      .toPromise()
      .then((data) => {
        if (isMounted) {
          const edges = data?.customFieldDefinitions?.edges ?? [];
          setDefinitions(edges.map((edge) => edge.node));
          setLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setDefinitions([]);
          setLoading(false);
        }
      });
    return () => {
      isMounted = false;
    };
  }, [isCustomFieldsEnabled]);
  const columns = useMemo(
    () => customFieldDefinitionsToWidgetColumns(definitions, entityType),
    [definitions, entityType],
  );
  return { columns, loading };
};
export default useCustomFieldWidgetColumns;
