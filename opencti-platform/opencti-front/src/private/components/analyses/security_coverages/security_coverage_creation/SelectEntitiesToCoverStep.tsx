import type {
  SelectEntitiesToCoverStepLinesQuery as SelectEntitiesToCoverStepLinesQueryType,
  SelectEntitiesToCoverStepLinesQuery$variables,
  SelectEntitiesToCoverStepLinesQuery,
} from './__generated__/SelectEntitiesToCoverStepLinesQuery.graphql';
import type { SelectEntitiesToCoverStepLines_data$data } from './__generated__/SelectEntitiesToCoverStepLines_data.graphql';
import DataTable from 'src/components/dataGrid/DataTable';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from 'src/utils/filters/filtersUtils';
import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { DataTableVariant } from 'src/components/dataGrid/dataTableTypes';
import { graphql } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import { SelectedEntities, StixCoreObjectNode } from './SecurityCoverageCreation-types';
import useEntityToggle from 'src/utils/hooks/useEntityToggle';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from 'src/components/common/button/Button';
import { useFormatter } from 'src/components/i18n';
interface SelectEntitiesToCoverStepProps {
  coveredEntity: StixCoreObjectNode;
  onSelectEntities: (selection: SelectedEntities | null) => void;
}

const LOCAL_STORAGE_KEY = 'SelectEntitiesToCoverStep';

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

const HAS_COVERED_TARGETS_TYPES = ['Attack-Pattern', 'Vulnerability', 'Artifact', 'Indicator', 'SecurityPlatform'];

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

  // Build filters
  // 1. Default non changeable filters
  // 1.1 Filter on has covered compatible types
  const typeFilter = {
    key: 'entity_type',
    values: HAS_COVERED_TARGETS_TYPES,
    operator: 'eq',
    mode: 'or',
  };

  // 1.2 Filter depending on object covered type
  const isContainer = coveredEntity.parent_types.includes('Container');
  const initialFilters = isContainer
    ? [
        // To get the objects contained
        {
          key: 'objects',
          values: [coveredEntity.id],
          operator: 'eq',
          mode: 'or',
        },
        typeFilter,
      ]
    : [
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

  // 2. Filters added by user
  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };

  const { viewStorage: { filters, searchTerm }, helpers, paginationOptions } = usePaginationLocalStorage<SelectEntitiesToCoverStepLinesQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, HAS_COVERED_TARGETS_TYPES);

  // 3. Final filter combining all previous filters
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: initialFilters,
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

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

  const { selectedElements, selectAll, deSelectedElements } = useEntityToggle<StixCoreObjectNode>(LOCAL_STORAGE_KEY);

  const listOfSelectedEntities = Object.keys(selectedElements);
  const listOfUnSelectedEntities = Object.keys(deSelectedElements);
  const selection = selectAll
    ? {
        filters: contextFilters,
        ...(listOfUnSelectedEntities.length > 0 && { excluded_ids: listOfUnSelectedEntities }),
        ...(searchTerm && { search: searchTerm }),
      }
    : (listOfSelectedEntities.length > 0 ? { selected_ids: listOfSelectedEntities } : null);

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={DATA_COLUMNS}
          resolvePath={(data: SelectEntitiesToCoverStepLines_data$data) => data.stixCoreObjects?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
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
