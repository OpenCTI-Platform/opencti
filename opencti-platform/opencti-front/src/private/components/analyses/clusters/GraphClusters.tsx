import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Chip, Hero, HeroBody, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box, Skeleton } from '@mui/material';
import Button from '@common/button/Button';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import type { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { monthsAgo, now } from '../../../../utils/Time';
import GraphAnalyticsStatus, { GraphAnalyticsStatusSkeleton, graphAnalyticsStatusQuery } from './GraphAnalyticsStatus';
import GraphClustersGrowthChart from '../../common/graph_analytics/GraphClustersGrowthChart';
import GraphRelativeTime from '../../common/graph_analytics/GraphRelativeTime';
import { formatGraphClusterLabel, GRAPH_CLUSTER_SOURCE_LABELS, GRAPH_CLUSTERS_PATH, trimLeadingEmptyPeriods } from '../../common/graph_analytics/graphAnalyticsUtils';
import type { GraphAnalyticsStatusQuery } from './__generated__/GraphAnalyticsStatusQuery.graphql';
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
        cluster_kind
        representatives {
          representative {
            main
          }
        }
      }
      data {
        date
        value
      }
    }
  }
`;

// Below this number of clusters, the growth chart is folded: one or two curves say less than the counters above it
const GROWTH_CHART_OPEN_FROM = 3;
// two chips fit the column at 1440 px; the other representatives are named in the tooltip of "and N more"
const REPRESENTATIVES_SHOWN = 2;

const ClustersSizeChart = ({ queryRef }: { queryRef: PreloadedQuery<GraphClustersSizeQuery> }) => {
  const { t_i18n } = useFormatter();
  const { graphClustersSizeTimeSeries } = usePreloadedQuery(clustersSizeQuery, queryRef);
  if (graphClustersSizeTimeSeries.length === 0) {
    return <Text variant="content-compact">{t_i18n('No cluster yet - clusters appear when an analytics pass finds entities sharing infrastructure')}</Text>;
  }
  const points = trimLeadingEmptyPeriods(graphClustersSizeTimeSeries.map((serie) => serie.data));
  return (
    <GraphClustersGrowthChart
      series={graphClustersSizeTimeSeries.map((serie, index) => ({
        name: formatGraphClusterLabel(t_i18n, serie.cluster),
        data: points[index].map((entry) => ({ x: new Date(entry.date), y: entry.value })),
      }))}
      interval="month"
    />
  );
};

interface ClustersOverviewProps {
  statusQueryRef: PreloadedQuery<GraphAnalyticsStatusQuery>;
  sizeQueryRef: PreloadedQuery<GraphClustersSizeQuery> | null | undefined;
  onFirstUse: (firstUse: boolean) => void;
}

const ClustersOverview = ({ statusQueryRef, sizeQueryRef, onFirstUse }: ClustersOverviewProps) => {
  const { t_i18n } = useFormatter();
  const { graphAnalyticsStatus: status } = usePreloadedQuery(graphAnalyticsStatusQuery, statusQueryRef);
  const clustersCount = status?.clusters_count ?? 0;
  useEffect(() => onFirstUse(clustersCount === 0), [clustersCount]);
  const [growthOpen, setGrowthOpen] = useState<boolean | null>(null);
  const showGrowth = growthOpen ?? clustersCount >= GROWTH_CHART_OPEN_FROM;
  return (
    <>
      <GraphAnalyticsStatus queryRef={statusQueryRef} />
      {clustersCount === 0 ? (
        <Hero data-testid="graph-clusters-first-use">
          <HeroBody separator={false}>
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1, textAlign: 'center', width: '100%' }}>
              <ItemIcon type="Infrastructure" />
              <Text variant="title-sm" as="h2">{t_i18n('No cluster yet')}</Text>
              <Text variant="content-base">
                {t_i18n('Clusters group the infrastructure sharing certificates, autonomous systems, registrars, name servers or hosting. They appear after the first full analytics pass of the knowledge graph.')}
              </Text>
              {status?.next_full_pass_at && (
                <Text variant="content-compact">
                  <GraphRelativeTime date={status.next_full_pass_at} template="Next full pass {time}" />
                </Text>
              )}
              <Box>
                <Button
                  variant="secondary"
                  href="https://docs.opencti.io/latest/usage/graph-analytics/"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {t_i18n('Read the documentation')}
                </Button>
              </Box>
            </Box>
          </HeroBody>
        </Hero>
      ) : (
        <Box component="section" sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} aria-labelledby="graph-clusters-growth-title">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Text variant="title-sm" as="h2" id="graph-clusters-growth-title">{t_i18n('Largest clusters over time')}</Text>
            <Button
              variant="tertiary"
              size="small"
              aria-expanded={showGrowth}
              aria-controls="graph-clusters-growth"
              onClick={() => setGrowthOpen(!showGrowth)}
              data-testid="graph-clusters-growth-toggle"
            >
              {showGrowth ? t_i18n('Hide the chart') : t_i18n('Show the chart')}
            </Button>
          </Box>
          {showGrowth && (
            <Box id="graph-clusters-growth" sx={{ height: 200 }} data-testid="graph-clusters-growth">
              {sizeQueryRef ? (
                <Suspense fallback={<Skeleton variant="rounded" height={200} />}>
                  <ClustersSizeChart queryRef={sizeQueryRef} />
                </Suspense>
              ) : <Skeleton variant="rounded" height={200} />}
            </Box>
          )}
        </Box>
      )}
    </>
  );
};

const LOCAL_STORAGE_KEY = 'GraphClusters';

/** Clusters of infrastructure, campaigns and tooling computed from the knowledge graph. */
const GraphClusters = () => {
  const { t_i18n } = useFormatter();
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
  const statusQueryRef = useQueryLoading<GraphAnalyticsStatusQuery>(graphAnalyticsStatusQuery, {});
  const sizeQueryRef = useQueryLoading<GraphClustersSizeQuery>(clustersSizeQuery, { startDate: monthsAgo(12), endDate: now() });
  const [firstUse, setFirstUse] = useState(false);

  const dataColumns: DataTableProps['dataColumns'] = {
    // the name states the kind of the cluster, which stays available as a filter
    name: {
      id: 'name',
      label: 'Name',
      percentWidth: 27,
      // the label is the first representative the reader can access, which the server cannot rank by
      isSortable: false,
      render: (cluster: GraphClusters_cluster$data) => (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{formatGraphClusterLabel(t_i18n, cluster)}</span>
          </TooltipTrigger>
          <TooltipContent>{cluster.name}</TooltipContent>
        </Tooltip>
      ),
    },
    members_count: {
      id: 'members_count',
      label: 'Members',
      percentWidth: 9,
      isSortable: true,
      render: ({ members_count }: GraphClusters_cluster$data) => t_i18n('{count, plural, one {# member} other {# members}}', { values: { count: members_count } }),
    },
    representatives: {
      id: 'representatives',
      label: 'Representative entities',
      percentWidth: 38,
      isSortable: false,
      render: ({ representatives }: GraphClusters_cluster$data) => {
        const shown = representatives.slice(0, REPRESENTATIVES_SHOWN);
        const hiddenNames = representatives.slice(REPRESENTATIVES_SHOWN).map((entity) => entity.representative.main);
        const more = hiddenNames.length;
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, minWidth: 0, overflow: 'hidden' }}>
            {shown.map((entity) => (
              <Chip key={entity.id} size="sm" label={entity.representative.main} startIcon={<ItemIcon type={entity.entity_type} size="small" />} />
            ))}
            {more > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span tabIndex={0} style={{ whiteSpace: 'nowrap' }}>
                    <Text variant="content-caption" as="span">{t_i18n('and {count} more', { values: { count: more } })}</Text>
                  </span>
                </TooltipTrigger>
                <TooltipContent>{hiddenNames.join(', ')}</TooltipContent>
              </Tooltip>
            )}
          </Box>
        );
      },
    },
    cluster_source: {
      id: 'cluster_source',
      label: 'Computed by',
      percentWidth: 9,
      isSortable: false,
      render: ({ cluster_source }: GraphClusters_cluster$data) => t_i18n(GRAPH_CLUSTER_SOURCE_LABELS[cluster_source] ?? cluster_source),
    },
    promoted: {
      id: 'promoted',
      label: 'Promoted',
      percentWidth: 9,
      isSortable: false,
      render: ({ promotedTo }: GraphClusters_cluster$data) => (promotedTo.length > 0
        ? t_i18n('{count, plural, one {# time} other {# times}}', { values: { count: promotedTo.length } })
        : t_i18n('Not promoted')),
    },
    last_computed_at: {
      id: 'last_computed_at',
      label: 'Computed',
      percentWidth: 8,
      isSortable: true,
      render: ({ last_computed_at }: GraphClusters_cluster$data) => (last_computed_at ? <GraphRelativeTime date={last_computed_at} /> : ''),
    },
  };

  return (
    <div data-testid="graph-clusters-page">
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Clusters'), current: true }]} />
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 2 }}>
        {statusQueryRef ? (
          <Suspense fallback={<GraphAnalyticsStatusSkeleton />}>
            <ClustersOverview statusQueryRef={statusQueryRef} sizeQueryRef={sizeQueryRef} onFirstUse={setFirstUse} />
          </Suspense>
        ) : <GraphAnalyticsStatusSkeleton />}
      </Box>
      {/* hidden, not unmounted, on first use: an empty list and its filters say less than the first-use state */}
      {queryRef && (
        <Box sx={{ display: firstUse ? 'none' : 'block' }}>
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
        </Box>
      )}
    </div>
  );
};

export default GraphClusters;
