import { resolveLink } from '../../Entity';
import type { FilterGroup, ListRouteResolution } from './widgetDrilldown-types';
import type { WidgetPerspective } from '../widget';

const GENERIC_LIST_ROUTES: Record<string, string> = {
  entities: '/dashboard/data/entities',
  relationships: '/dashboard/data/relationships',
  audits: '/dashboard/audits',
};

/**
 * The entity types each generic destination pins on its own query, and whether
 * that makes it hold less than the widget counts.
 *
 * `/dashboard/data/entities` queries `stixDomainObjects` (`Entities.tsx:45`) and
 * `/dashboard/data/relationships` queries `stixCoreRelationships`
 * (`Relationships.tsx:281`), both narrower than what their widgets aggregate.
 * The audit page passes the filters through untouched, so it holds exactly what
 * an audit widget counts.
 */
const GENERIC_LIST_SCOPES: Record<string, { types: string[]; requiresScopeProof: boolean }> = {
  entities: { types: ['Stix-Domain-Object'], requiresScopeProof: true },
  relationships: { types: ['stix-core-relationship'], requiresScopeProof: true },
  audits: { types: ['History'], requiresScopeProof: false },
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
 * Dedicated lists several entity types share, with the single type their page
 * really pins on its query. `resolveLink` sends every observable type to the
 * observables list, which holds them all: consuming the requested type there
 * would drop the filter and inflate the count by every sibling type.
 */
const SHARED_LIST_SCOPES: Record<string, string> = {
  '/dashboard/observations/observables': 'Stix-Cyber-Observable', // StixCyberObservables.tsx:56
  '/dashboard/analyses/security_coverages': 'Security-Coverage', // SecurityCoverages.tsx:154
};

/**
 * Returns the entity type a dedicated destination could be derived from, i.e. a
 * single top-level `entity_type` filter holding exactly one value under `eq`.
 * Anything else is ambiguous and yields null.
 */
const findUniqueEntityTypeValue = (filters?: FilterGroup | null): string | null => {
  if (!filters) return null;
  // Under `or`, the type restriction does not narrow anything: a sibling filter
  // or sub-group brings back entities of every other type, which the dedicated
  // list would not show.
  const isNarrowing = filters.mode === 'and'
    || (filters.filters.length <= 1 && (filters.filterGroups ?? []).length === 0);
  if (!isNarrowing) return null;
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
      // The widget already carried that single type, so the destination holds
      // at most the counted population: nothing left to prove.
      const pinned = SHARED_LIST_SCOPES[dedicated] ?? entityType;
      return {
        route: dedicated,
        consumedEntityType: pinned === entityType ? entityType : null,
        scopeTypes: [pinned],
        requiresScopeProof: false,
      };
    }
  }
  const scope = GENERIC_LIST_SCOPES[perspective];
  return {
    route: genericRoute,
    consumedEntityType: null,
    scopeTypes: scope?.types ?? [],
    requiresScopeProof: scope?.requiresScopeProof ?? true,
  };
};
