import { useLazyLoadQuery } from 'react-relay';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useProvenanceCountsFetchKey from '../../common/provenance/provenanceCountsRefresh';
import { provenanceKpiStripQuery } from './ProvenanceKpiStrip';
import useProvenanceTrackedFilters from './useProvenanceTrackedFilters';
import { ProvenanceKpiStripQuery, ProvenanceKpiStripQuery$variables } from './__generated__/ProvenanceKpiStripQuery.graphql';

export const CONFLICTS_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'has_conflicts', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

export const STALE_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'freshness_stale', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

// Same query, variables and fetch key as the counters of the tab, so that the badge and the counters share one result
const useProvenanceCurationCount = (baseFilters: FilterGroup) => {
  const filters = useProvenanceTrackedFilters(baseFilters);
  const fetchKey = useProvenanceCountsFetchKey();
  // store-and-network keeps the badge shown while a new fetch key reads the count again
  const data = useLazyLoadQuery<ProvenanceKpiStripQuery>(
    provenanceKpiStripQuery,
    { filters } as unknown as ProvenanceKpiStripQuery$variables,
    { fetchPolicy: 'store-and-network', fetchKey },
  );
  return (data.entities?.total ?? 0) + (data.relationships?.total ?? 0) + (data.sightings?.total ?? 0);
};

/** Pending work of the Conflicts tab: the tracked elements with source conflicts. */
export const useConflictsCount = () => useProvenanceCurationCount(CONFLICTS_FILTERS);

/** Pending work of the Stale knowledge tab: the tracked elements flagged as stale. */
export const useStaleKnowledgeCount = () => useProvenanceCurationCount(STALE_FILTERS);
