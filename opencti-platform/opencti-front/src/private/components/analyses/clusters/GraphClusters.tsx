import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Chip } from '@filigran/design-system';
import { Box } from '@mui/material';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import type { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { monthsAgo, now } from '../../../../utils/Time';
import GraphAnalyticsStatus from './GraphAnalyticsStatus';
import { GRAPH_CLUSTER_KIND_LABELS, GRAPH_CLUSTER_SOURCE_LABELS, GRAPH_CLUSTERS_PATH } from '../../common/graph_analytics/graphAnalyticsUtils';
import type { GraphClustersListQuery, GraphClustersListQuery$variables } from './__generated__/GraphClustersListQuery.graphql';
import type { GraphClusters_clusters$data } from './__generated__/GraphClusters_clusters.graphql';
import type { GraphClusters_cluster$data } from './__generated__/GraphClusters_cluster.graphql';
import type { GraphClustersSizeQuery } from './__generated__/GraphClustersSizeQuery.graphql';

const clusterFragment = graphql`
  fragment GraphClusters_cluster on GraphCluster {
    id
    entity_type
    name
    cluster_kind
    cluster_source
    members_count
    last_computed_at
    representatives {
      id
      entity_type
      representative {
        main
      }
    }
    promotedTo {
      id
    }
  }
`;

const clustersFragment = graphql`
  fragment GraphClusters_clusters on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "GraphClustersOrdering", defaultValue: members_count }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "GraphClustersRefetchQuery") {
    graphClusters(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_graphClusters") {
      edges {
        node {
          id
          ...GraphClusters_cluster
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

const clustersListQuery = graphql`
  query GraphClustersListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: GraphClustersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...GraphClusters_clusters
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

const clustersSizeQuery = graphql`
  query GraphClustersSizeQuery($startDate: DateTime, $endDate: DateTime) {
    graphClustersSizeTimeSeries(startDate: $startDate, endDate: $endDate, interval: "month", limit: 5) {
      cluster {
        id
        name
      }
      data {
        date
        value
      }
    }
  }
`;

const ClustersSizeChart = ({ queryRef }: { queryRef: PreloadedQuery<GraphClustersSizeQuery> }) => {
  const { graphClustersSizeTimeSeries } = usePreloadedQuery(clustersSizeQuery, queryRef);
  if (graphClustersSizeTimeSeries.length === 0) return <WidgetNoData />;
  return (
    <WidgetMultiAreas
      series={graphClustersSizeTimeSeries.map((serie) => ({
        name: serie.cluster.name,
        data: serie.data.map((entry) => ({ x: new Date(entry.date), y: entry.value })),
      }))}
      interval="month"
      hasLegend
    />
  );
};

const LOCAL_STORAGE_KEY = 'GraphClusters';

/** Clusters of infrastructure, campaigns and tooling computed from the knowledge graph. */
const GraphClusters = () => {
  const { t_i18n, fldt } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Clusters'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'members_count',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<GraphClustersListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('Graph-Cluster', viewStorage.filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as GraphClustersListQuery$variables;
  const queryRef = useQueryLoading<GraphClustersListQuery>(clustersListQuery, queryPaginationOptions);
  const sizeQueryRef = useQueryLoading<GraphClustersSizeQuery>(clustersSizeQuery, { startDate: monthsAgo(12), endDate: now() });

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: 'Name',
      percentWidth: 25,
      isSortable: true,
      render: ({ name }: GraphClusters_cluster$data) => name,
    },
    cluster_kind: {
      id: 'cluster_kind',
      label: 'Kind',
      percentWidth: 14,
      isSortable: true,
      render: ({ cluster_kind }: GraphClusters_cluster$data) => <Chip label={t_i18n(GRAPH_CLUSTER_KIND_LABELS[cluster_kind] ?? cluster_kind)} />,
    },
    members_count: {
      id: 'members_count',
      label: 'Members',
      percentWidth: 9,
      isSortable: true,
      render: ({ members_count }: GraphClusters_cluster$data) => members_count,
    },
    representatives: {
      id: 'representatives',
      label: 'Representative entities',
      percentWidth: 26,
      isSortable: false,
      render: ({ representatives }: GraphClusters_cluster$data) => representatives.slice(0, 3).map((r) => r.representative.main).join(', '),
    },
    cluster_source: {
      id: 'cluster_source',
      label: 'Computed by',
      percentWidth: 10,
      isSortable: false,
      render: ({ cluster_source }: GraphClusters_cluster$data) => t_i18n(GRAPH_CLUSTER_SOURCE_LABELS[cluster_source] ?? cluster_source),
    },
    promoted: {
      id: 'promoted',
      label: 'Promoted',
      percentWidth: 6,
      isSortable: false,
      render: ({ promotedTo }: GraphClusters_cluster$data) => (promotedTo.length > 0 ? promotedTo.length : '-'),
    },
    last_computed_at: {
      id: 'last_computed_at',
      label: 'Last computation',
      percentWidth: 10,
      isSortable: true,
      render: ({ last_computed_at }: GraphClusters_cluster$data) => fldt(last_computed_at),
    },
  };

  return (
    <div data-testid="graph-clusters-page">
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Clusters'), current: true }]} />
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 2 }}>
        <GraphAnalyticsStatus />
        <WidgetContainer height={260} title={t_i18n('Largest clusters over time')} variant="inLine">
          {sizeQueryRef ? (
            <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <ClustersSizeChart queryRef={sizeQueryRef} />
            </Suspense>
          ) : <Loader variant={LoaderVariant.inElement} />}
        </WidgetContainer>
      </Box>
      {queryRef && (
        <DataTable
          removeSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          resolvePath={(data: GraphClusters_clusters$data) => data.graphClusters?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          getComputeLink={(node: GraphClusters_cluster$data) => `${GRAPH_CLUSTERS_PATH}/${node.id}`}
          preloadedPaginationProps={{
            linesQuery: clustersListQuery,
            linesFragment: clustersFragment,
            queryRef,
            nodePath: ['graphClusters', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={clusterFragment}
          entityTypes={['Graph-Cluster']}
          searchContextFinal={{ entityTypes: ['Graph-Cluster'] }}
        />
      )}
    </div>
  );
};

export default GraphClusters;
