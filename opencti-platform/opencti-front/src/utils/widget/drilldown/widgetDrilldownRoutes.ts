import { resolveLink } from '../../Entity';
import type { FilterGroup, ListRouteResolution } from './widgetDrilldown-types';
import type { WidgetPerspective } from '../widget';

const GENERIC_LIST_ROUTES: Record<string, string> = {
  entities: '/dashboard/data/entities',
  relationships: '/dashboard/data/relationships',
  audits: '/dashboard/audits',
};

/**
 * Route prefixes whose pages are knowledge lists reading `?filters=` through
 * `useLocalStorage`. Allow-listing rather than deny-listing keeps the behaviour
 * fail-closed: an unlisted route degrades to the generic list, never to a page
 * that would silently ignore the filters.
 */
const FILTERABLE_LIST_PREFIXES = [
  '/dashboard/analyses/',
  '/dashboard/arsenal/',
  '/dashboard/cases/',
  '/dashboard/entities/',
  '/dashboard/events/',
  '/dashboard/locations/',
  '/dashboard/observations/',
  '/dashboard/techniques/',
  '/dashboard/threats/',
];

const isFilterableListRoute = (route: string) => FILTERABLE_LIST_PREFIXES.some((prefix) => route.startsWith(prefix));

/**
 * Returns the entity type a dedicated destination could be derived from, i.e. a
 * single top-level `entity_type` filter holding exactly one value under `eq`.
 * Anything else is ambiguous and yields null.
 */
const findUniqueEntityTypeValue = (filters?: FilterGroup | null): string | null => {
  if (!filters) return null;
  const candidates = filters.filters.filter((f) => f.key === 'entity_type');
  if (candidates.length !== 1) return null;
  const [filter] = candidates;
  if ((filter.operator ?? 'eq') !== 'eq') return null;
  if (filter.values.length !== 1) return null;
  const [value] = filter.values;
  return typeof value === 'string' ? value : null;
};

export const resolveListRoute = (
  perspective: WidgetPerspective,
  filters?: FilterGroup | null,
): ListRouteResolution | null => {
  const genericRoute = GENERIC_LIST_ROUTES[perspective];
  if (!genericRoute) return null;

  const entityType = findUniqueEntityTypeValue(filters);
  if (entityType) {
    const dedicated = resolveLink(entityType);
    if (dedicated && isFilterableListRoute(dedicated)) {
      return { route: dedicated, consumedEntityType: entityType };
    }
  }
  return { route: genericRoute, consumedEntityType: null };
};
