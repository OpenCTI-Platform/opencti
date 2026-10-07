import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { HAS_COVERED_TARGETS_TYPES, SelectedEntities, StixCoreObjectNode } from '../SecurityCoverageCreation-types';

export const LOCAL_STORAGE_KEY = 'SelectEntitiesToCoverStep';

export const INITIAL_VALUES = {
  searchTerm: '',
  sortBy: 'entity_type',
  orderAsc: true,
  numberOfElements: {
    number: 0,
    symbol: '',
  },
};

/**
 * Mandatory filters restricting the list to the entities the backend receives.
 */
export const buildCoveredEntitiesFilters = (coveredEntity: StixCoreObjectNode): FilterGroup['filters'] => {
  const typeFilter = {
    key: 'entity_type',
    values: HAS_COVERED_TARGETS_TYPES,
    operator: 'eq',
    mode: 'or',
  };

  if (coveredEntity.parent_types.includes('Container')) {
    return [
      // To get the objects contained
      {
        key: 'objects',
        values: [coveredEntity.id],
        operator: 'eq',
        mode: 'or',
      },
      typeFilter,
    ];
  }

  return [
    {
      key: 'regardingOf',
      operator: 'eq',
      mode: 'or',
      values: [
        { key: 'id', values: [coveredEntity.id] },
        { key: 'relationship_type', values: ['targets', 'uses'] },
        // To keep only relationships going from the covered entity, not towards it
        { key: 'direction_forced', values: [true] },
        { key: 'direction_reverse', values: [false] },
      ],
    },
    typeFilter,
  ];
};

interface BuildEntitiesSelectionArgs {
  selectAll: boolean;
  selectedIds: string[];
  excludedIds: string[];
  searchTerm?: string;
  filters: FilterGroup;
}

export const buildEntitiesSelection = ({
  selectAll,
  selectedIds,
  excludedIds,
  searchTerm,
  filters,
}: BuildEntitiesSelectionArgs): SelectedEntities | null => {
  if (selectAll) {
    return {
      filters,
      ...(excludedIds.length > 0 && { excluded_ids: excludedIds }),
      ...(searchTerm && { search: searchTerm }),
    };
  }
  return selectedIds.length > 0 ? { selected_ids: selectedIds } : null;
};
