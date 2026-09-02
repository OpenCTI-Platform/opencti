import type {
  SelectEntitiesToCoverStepLinesQuery as SelectEntitiesToCoverStepLinesQueryType,
  SelectEntitiesToCoverStepLinesQuery$variables,
} from './__generated__/SelectEntitiesToCoverStepLinesQuery.graphql';
import type { SelectEntitiesToCoverStepLines_data$data } from './__generated__/SelectEntitiesToCoverStepLines_data.graphql';
import DataTable from 'src/components/dataGrid/DataTable';

import { DataTableVariant } from 'src/components/dataGrid/dataTableTypes';
import { graphql } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import { HAS_COVERED_TARGETS_TYPES, SelectedEntities, StixCoreObjectNode } from '../SecurityCoverageCreation-types';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from 'src/components/common/button/Button';
import { useFormatter } from 'src/components/i18n';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from 'src/utils/filters/filtersUtils';
import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import useEntityToggle from 'src/utils/hooks/useEntityToggle';
import { buildCoveredEntitiesFilters, buildEntitiesSelection, INITIAL_VALUES, LOCAL_STORAGE_KEY } from './SelectEntitiesToCoverStep-utils';

interface SelectEntitiesToCoverStepProps {
  coveredEntity: StixCoreObjectNode;
  onSelectEntities: (selection: SelectedEntities | null) => void;
}

export const selectEntitiesToCoverStepLinesQuery = graphql`
  query SelectEntitiesToCoverStepLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SelectEntitiesToCoverStepLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const selectEntitiesToCoverStepLinesFragment = graphql`
  fragment SelectEntitiesToCoverStepLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "SelectEntitiesToCoverStepLinesRefetchQuery") {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          id
          ...SelectEntitiesToCoverStepLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const selectEntitiesToCoverStepLineFragment = graphql`
  fragment SelectEntitiesToCoverStepLine_node on StixCoreObject {
    id
    standard_id
    entity_type
    parent_types
    created_at
    draftVersion {
      draft_id
      draft_operation
    }
    representative {
      main
    }
    createdBy {
      id
      entity_type
      ... on Identity {
        name
      }
    }
    objectLabel {
      id
      value
      color
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

const DATA_COLUMNS = {
  entity_type: { percentWidth: 15 },
  name: { percentWidth: 25, isSortable: false },
  creator: { percentWidth: 15 },
  created_at: { percentWidth: 15 },
  objectLabel: { percentWidth: 15 },
  objectMarking: { percentWidth: 15 },
};

const SelectEntitiesToCoverStep = ({ coveredEntity, onSelectEntities }: SelectEntitiesToCoverStepProps) => {
  const { t_i18n } = useFormatter();

  const { viewStorage: { filters, searchTerm }, helpers, paginationOptions } = usePaginationLocalStorage<SelectEntitiesToCoverStepLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    INITIAL_VALUES,
    true,
  );
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, HAS_COVERED_TARGETS_TYPES);
  const { selectedElements, deSelectedElements, selectAll } = useEntityToggle<StixCoreObjectNode>(LOCAL_STORAGE_KEY);

  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: buildCoveredEntitiesFilters(coveredEntity),
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const selection = buildEntitiesSelection({
    selectAll,
    selectedIds: Object.keys(selectedElements),
    excludedIds: Object.keys(deSelectedElements),
    searchTerm,
    filters: contextFilters,
  });

  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };

  const queryRef = useQueryLoading<SelectEntitiesToCoverStepLinesQueryType>(
    selectEntitiesToCoverStepLinesQuery,
    { ...queryPaginationOptions, count: 100 } as unknown as SelectEntitiesToCoverStepLinesQuery$variables,
  );

  const preloadedPaginationProps = {
    linesQuery: selectEntitiesToCoverStepLinesQuery,
    linesFragment: selectEntitiesToCoverStepLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SelectEntitiesToCoverStepLinesQueryType>;

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={DATA_COLUMNS}
          resolvePath={(data: SelectEntitiesToCoverStepLines_data$data) => data.stixCoreObjects?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={INITIAL_VALUES}
          lineFragment={selectEntitiesToCoverStepLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          entityTypes={HAS_COVERED_TARGETS_TYPES}
          availableEntityTypes={HAS_COVERED_TARGETS_TYPES}
          variant={DataTableVariant.inline}
          disableNavigation
          disableToolBar
          selectOnLineClick
        />
      )}
      <FormButtonContainer>
        <Button onClick={() => onSelectEntities(selection)}>
          {t_i18n('Next')}
        </Button>
      </FormButtonContainer>
    </>
  );
};

export default SelectEntitiesToCoverStep;
