import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import type { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { resolveLink } from '../../../../utils/Entity';
import type { GraphClusterMembersLinesPaginationQuery, GraphClusterMembersLinesPaginationQuery$variables } from './__generated__/GraphClusterMembersLinesPaginationQuery.graphql';
import type { GraphClusterMembersLines_data$data } from './__generated__/GraphClusterMembersLines_data.graphql';
import type { GraphClusterMembersLine_node$data } from './__generated__/GraphClusterMembersLine_node.graphql';
import useGraphMetricsPlatformView, { isGraphMetricsSortKey } from '../../common/graph_analytics/useGraphMetricsPlatformView';

const membersLinesQuery = graphql`
  query GraphClusterMembersLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...GraphClusterMembersLines_data
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

const membersLineFragment = graphql`
  fragment GraphClusterMembersLine_node on StixCoreObject {
    id
    entity_type
    created_at
    representative {
      main
    }
    createdBy {
      id
      entity_type
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    x_opencti_graph_metrics {
      degree
      betweenness_approx
    }
  }
`;

const membersLinesFragment = graphql`
  fragment GraphClusterMembersLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: graph_degree }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "GraphClusterMembersLinesRefetchQuery") {
    stixCoreObjects(
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
          entity_type
          ...GraphClusterMembersLine_node
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

interface GraphClusterMembersProps {
  clusterId: string;
}

/** Members of a cluster the user can access, most connected first for users reading every relationship. */
const GraphClusterMembers = ({ clusterId }: GraphClusterMembersProps) => {
  const navigate = useNavigate();
  const hasGraphMetricsPlatformView = useGraphMetricsPlatformView();
  const storageKey = `GraphClusterMembers-${clusterId}`;
  const initialValues = {
    searchTerm: '',
    sortBy: hasGraphMetricsPlatformView ? 'graph_degree' : 'created_at',
    orderAsc: false,
    filters: emptyFilterGroup,
    numberOfElements: { number: 0, symbol: '' },
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<GraphClusterMembersLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const userFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    ...(!hasGraphMetricsPlatformView && isGraphMetricsSortKey(paginationOptions.orderBy) ? { orderBy: 'created_at' } : {}),
    filters: {
      mode: 'and',
      filters: [{ key: ['graph_cluster_id'], values: [clusterId] }],
      filterGroups: userFilters ? [userFilters] : [],
    },
  } as unknown as GraphClusterMembersLinesPaginationQuery$variables;

  const dataColumns = {
    entity_type: { percentWidth: 13 },
    name: {
      percentWidth: 30,
      isSortable: false,
      render: ({ representative }: GraphClusterMembersLine_node$data) => representative.main,
    },
    graph_degree: {
      id: 'graph_degree',
      label: 'Graph degree',
      percentWidth: 10,
      isSortable: hasGraphMetricsPlatformView,
      render: ({ x_opencti_graph_metrics }: GraphClusterMembersLine_node$data) => x_opencti_graph_metrics?.degree ?? '-',
    },
    createdBy: { percentWidth: 15, isSortable: false },
    objectLabel: { percentWidth: 12 },
    objectMarking: { percentWidth: 10, isSortable: false },
    created_at: { percentWidth: 10 },
  };

  const queryRef = useQueryLoading(membersLinesQuery, queryPaginationOptions);
  const preloadedPaginationProps = {
    linesQuery: membersLinesQuery,
    linesFragment: membersLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<GraphClusterMembersLinesPaginationQuery>;

  return queryRef ? (
    <div data-testid="graph-cluster-members">
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: GraphClusterMembersLines_data$data) => data.stixCoreObjects?.edges?.map((e) => e?.node)}
        storageKey={storageKey}
        initialValues={initialValues}
        lineFragment={membersLineFragment}
        preloadedPaginationProps={preloadedPaginationProps}
        entityTypes={['Stix-Core-Object']}
        searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
        variant={DataTableVariant.inline}
        disableNavigation
        disableToolBar
        removeSelectAll
        disableLineSelection
        onLineClick={(row: GraphClusterMembersLine_node$data) => navigate(`${resolveLink(row.entity_type)}/${row.id}`)}
      />
    </div>
  ) : null;
};

export default GraphClusterMembers;
