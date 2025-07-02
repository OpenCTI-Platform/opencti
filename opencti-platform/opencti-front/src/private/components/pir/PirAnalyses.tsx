import { graphql } from 'react-relay';
import { PirAnalysesContainersListQuery, PirAnalysesContainersListQuery$variables } from '@components/pir/__generated__/PirAnalysesContainersListQuery.graphql';
import { PirAnalyses_ContainersFragment$data } from '@components/pir/__generated__/PirAnalyses_ContainersFragment.graphql';
import React from 'react';
import { emptyFilterGroup, sanitizeFilterGroupKeysForBackend, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';

const pirAnalysesContainerFragment = graphql`
  fragment PirAnalyses_ContainerFragment on Container {
    id
    entity_type
    created_at
    representative {
      main
    }
    objectLabel {
      id
      color
      value
    }
    creators {
      id
      name
    }
  }
`;

const pirAnalysesContainersFragment = graphql`
  fragment PirAnalyses_ContainersFragment on Query
  @argumentDefinitions(
    id: { type: "ID!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ContainersOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirAnalyses_ContainersListRefetchQuery") {
    pir(id: $id) {
      pirContainers(
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "PaginationPirAnalyses_pirContainers") {
        edges {
          node {
            id
            ...PirAnalyses_ContainerFragment
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

const pirAnalysesContainersListQuery = graphql`
  query PirAnalysesContainersListQuery(
    $id: ID!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PirAnalyses_ContainersFragment
    @arguments(
      id: $id
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

interface PirAnalysesProps {
  pirId: string,
  flaggedIds: string[],
}

const PirAnalyses = ({
  pirId,
}: PirAnalysesProps) => {
  const LOCAL_STORAGE_KEY = `PirAnalysesContainersList-${pirId}`;
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: true,
    openExports: false,
  };

  const localStorage = usePaginationLocalStorage<PirAnalysesContainersListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { viewStorage, paginationOptions, helpers } = localStorage;

  const filters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Container']);

  const queryPaginationOptions: PirAnalysesContainersListQuery$variables = {
    ...paginationOptions,
    id: pirId,
    count: 100,
    filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
  };

  const queryRef = useQueryLoading<PirAnalysesContainersListQuery>(
    pirAnalysesContainersListQuery,
    queryPaginationOptions,
  );

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: { percentWidth: 13 },
    name: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created_at: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  return (
    <>
      {queryRef
        && <DataTable
          disableSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={filters}
          lineFragment={pirAnalysesContainerFragment}
          entityTypes={['Container']}
          searchContextFinal={{ entityTypes: ['Container'] }}
          resolvePath={(d: PirAnalyses_ContainersFragment$data) => {
            return d.pir?.pirContainers?.edges?.map((e) => e?.node);
          }}
          preloadedPaginationProps={{
            linesQuery: pirAnalysesContainersListQuery,
            linesFragment: pirAnalysesContainersFragment,
            queryRef,
            nodePath: ['pir', 'pirContainers', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
           />
      }
    </>
  );
};

export default PirAnalyses;
