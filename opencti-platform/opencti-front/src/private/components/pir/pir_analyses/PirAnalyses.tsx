import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { Chip, Tooltip } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { PirAnalysesContainersListQuery, PirAnalysesContainersListQuery$variables } from './__generated__/PirAnalysesContainersListQuery.graphql';
import { PirAnalyses_ContainersFragment$data } from './__generated__/PirAnalyses_ContainersFragment.graphql';
import { emptyFilterGroup, sanitizeFilterGroupKeysForBackend, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../../components/dataGrid/DataTable';
import { PirAnalysesFragment$key } from './__generated__/PirAnalysesFragment.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';

const pirAnalysesContainerFragment = graphql`
  fragment PirAnalyses_ContainerFragment on Container
  @argumentDefinitions(
    pirId: { type: "String" }
  ) {
    id
    entity_type
    created_at
    status {
      id
      order
      template {
        id
        name
        color
      }
    }
    representative {
      main
    }
    objectMarking {
      id
      definition
      definition_type
    }
    createdBy {
      id
      name
    }
    creators {
      id
      name
    }
    objects(first: 100, pirId: $pirId) {
      edges {
        node {
          ...on StixCoreObject {
            entity_type
            representative {
              main
            }
          }
        }
      }
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
    pirId: { type: "String" }
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
            @arguments(pirId: $pirId)
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
    $pirId: String
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
      pirId: $pirId
    )
  }
`;

const analysesFragment = graphql`
  fragment PirAnalysesFragment on Pir {
    id
  }
`;

interface PirAnalysesProps {
  data: PirAnalysesFragment$key,
}

const PirAnalyses = ({ data }: PirAnalysesProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { id } = useFragment(analysesFragment, data);

  const LOCAL_STORAGE_KEY = `PirAnalysesContainersList-${id}`;
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
    id,
    count: 100,
    filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
    pirId: id,
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
    entity_type: { percentWidth: 10 },
    name: {},
    container_objects: {
      id: 'container_objects',
      label: 'Entities in PIR',
      percentWidth: 15,
      isSortable: true,
      render: ({ objects }) => {
        const max = 10;
        const hasMore = objects.edges.length > max;
        const countLabel = !hasMore ? objects.edges.length : `${max}+`;
        return (
          <Tooltip
            title={(
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: theme.spacing(1),
                padding: theme.spacing(1),
              }}
              >
                {objects.edges.slice(0, max).map((e: any, i: number) => (
                  <span key={i}>
                    {e.node.representative.main} ({t_i18n(e.node.entity_type)})
                  </span>
                ))}
                {hasMore && <span>...</span>}
              </div>
            )}
          >
            <Chip
              size='small'
              label={countLabel}
              sx={{ width: 100, borderRadius: 1 }}
            />
          </Tooltip>
        );
      },
    },
    createdBy: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    creator: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    created_at: {
      percentWidth: 12,
    },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
  };

  return queryRef && (
    <DataTable
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
  );
};

export default PirAnalyses;
