import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { PirAnalysesContainersListQuery, PirAnalysesContainersListQuery$variables } from '@components/pir/__generated__/PirAnalysesContainersListQuery.graphql';
import { PirAnalyses_ContainersFragment$data } from '@components/pir/__generated__/PirAnalyses_ContainersFragment.graphql';
import { PirAnalysesEntitiesSourcesFlaggedListQuery } from '@components/pir/__generated__/PirAnalysesEntitiesSourcesFlaggedListQuery.graphql';
import React from 'react';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';

import { PaginationOptions } from '../../../components/list_lines';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import Loader, { LoaderVariant } from '../../../components/Loader';

const pirAnalysesEntitiesSourcesFlaggedListQuery = graphql`
  query PirAnalysesEntitiesSourcesFlaggedListQuery(
    $count: Int!
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

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
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ContainersOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirAnalyses_ContainersListRefetchQuery") {
    containers(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "PaginationPirAnalyses_containers") {
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
`;

const pirAnalysesContainersListQuery = graphql`
  query PirAnalysesContainersListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PirAnalyses_ContainersFragment
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

interface PirAnalysesContentProps {
  pirId: string,
  flaggedEntitiesQueryRef: PreloadedQuery<PirAnalysesEntitiesSourcesFlaggedListQuery>,
}

const PirAnalysesContent = ({
  pirId,
  flaggedEntitiesQueryRef,
}: PirAnalysesContentProps) => {
  // fetch 100 top flagged entities ids
  const { stixCoreObjects } = usePreloadedQuery<PirAnalysesEntitiesSourcesFlaggedListQuery>(
    pirAnalysesEntitiesSourcesFlaggedListQuery,
    flaggedEntitiesQueryRef,
  );
  const flaggedIds = stixCoreObjects?.edges.map((n) => n.node.id) ?? [];

  // query to fetch containers containing those ids
  const LOCAL_STORAGE_KEY = `PirAnalysesContainersList-${pirId}`;
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: true,
    openExports: false,
  };

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { viewStorage, paginationOptions, helpers } = localStorage;

  const filters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Container']);

  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'objects',
        operator: 'eq',
        mode: 'and',
        values: [flaggedIds],
      },
    ],
    filterGroups: filters && isFilterGroupNotEmpty(filters)
      ? [filters]
      : [],
  };
  const queryPaginationOptions: PirAnalysesContainersListQuery$variables = {
    ...paginationOptions,
    filters: contextFilters,
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
          toolbarFilters={contextFilters}
          lineFragment={pirAnalysesContainerFragment}
          entityTypes={['Container']}
          searchContextFinal={{ entityTypes: ['Container'] }}
          resolvePath={(d: PirAnalyses_ContainersFragment$data) => {
            return d.containers?.edges?.map((e) => e?.node);
          }}
          preloadedPaginationProps={{
            linesQuery: pirAnalysesContainersListQuery,
            linesFragment: pirAnalysesContainersFragment,
            queryRef,
            nodePath: ['containers', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
           />
      }
    </>
  );
};

interface PirAnalysesProps {
  pirId: string,
  flaggedIds: string[],
}

const PirAnalyses = ({
  pirId,
}: PirAnalysesProps) => {
  const filters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'regardingOf',
        operator: 'eq',
        mode: 'and',
        values: [
          { key: 'id', values: [pirId], operator: 'eq', mode: 'or' },
          { key: 'relationship_type', values: ['in-pir'], operator: 'eq', mode: 'or' },
        ],
      },
    ],
    filterGroups: [],
  };

  // query to fetch the 100 last flagged entities
  const flaggedEntitiesQueryRef = useQueryLoading<PirAnalysesEntitiesSourcesFlaggedListQuery>(
    pirAnalysesEntitiesSourcesFlaggedListQuery,
    {
      count: 100,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters,
    },
  );

  return (
    <>
      {flaggedEntitiesQueryRef
        && <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
           >
          <PirAnalysesContent
            pirId={pirId}
            flaggedEntitiesQueryRef={flaggedEntitiesQueryRef}
          />
        </React.Suspense>
      }
    </>
  );
};

export default PirAnalyses;
