import { useMemo } from 'react';
import useAuth, { FilterDefinition } from '../../utils/hooks/useAuth';

const ENTITY_TYPE_FILTER_KEY = 'entity_type';

/**
 * Type hierarchy read from the filter keys schema the platform already loads at startup (no query).
 * The back keeps the `entity_type` filter on abstract types only, and lists in its `subEntityTypes`
 * the abstract type itself and all its descendants, transitively (opencti-graphql/src/domain/filterKeysSchema.ts,
 * locked by tests/03-integration/01-database/filterKeysSchema-test.ts).
 * A parent that is not an abstract type of the schema falls back to exact match.
 */
export const buildIsSubTypeOf = (filterKeysSchema: Map<string, Map<string, FilterDefinition>> | undefined) => {
  return (type: string, parent: string): boolean => {
    if (type === parent) return true;
    const descendants = filterKeysSchema?.get(parent)?.get(ENTITY_TYPE_FILTER_KEY)?.subEntityTypes ?? [];
    return descendants.includes(type);
  };
};

export const useIsSubTypeOf = () => {
  const { schema } = useAuth();
  const filterKeysSchema = schema?.filterKeysSchema;
  return useMemo(() => buildIsSubTypeOf(filterKeysSchema), [filterKeysSchema]);
};
