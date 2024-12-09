import React, { useEffect } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { RelatedContainerNode } from '@components/common/containers/RelatedContainers';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { RelatedContainersDetailsLinesPaginationQuery } from '@components/common/containers/__generated__/RelatedContainersDetailsLinesPaginationQuery.graphql';
import { RelatedContainersDetailsLines_data$data } from '@components/common/containers/__generated__/RelatedContainersDetailsLines_data.graphql';
import { RelatedContainersDetailsQuery, RelatedContainersDetailsQuery$variables } from '@components/common/containers/__generated__/RelatedContainersDetailsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemMarkings from '../../../../components/ItemMarkings';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import DataTable from '../../../../components/dataGrid/DataTable';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'RelatedContainersDetailsStore';

export const relatedContainersDetailsQuery = graphql`
  query RelatedContainersDetailsQuery(
    $field: String!
    $operation: StatsOperation!
    $filters: FilterGroup!
  ) {
    stixCoreObjectsDistribution(
      field: $field
      operation: $operation
      filters: $filters
    ) {
      label
      value
    }
    stixCoreObjects(
      first: 10
      filters: $filters
    ) {
      edges {
        node {
          id
          ... on StixCyberObservable {
            observable_value
          }
          ... on Indicator {
            name
          }
          entity_type
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

const relatedContainersLinesQuery = graphql`
  query RelatedContainersDetailsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RelatedContainersDetailsLines_data
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

const relatedContainersLineFragment = graphql`
  fragment RelatedContainersDetailsLine_node on StixCoreObject {
    id
    entity_type
    created_at
    createdBy {
      id
      entity_type
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
    creators {
      id
      name
    }
    ... on Indicator {
      name
    }
    ... on StixCyberObservable {
      observable_value
    }
  }
`;

const relatedContainersLinesFragment = graphql`
  fragment RelatedContainersDetailsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreObjectsOrdering"
      defaultValue: entity_type
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "RelatedContainersDetailsLinesRefetchQuery") {
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
          ...RelatedContainersDetailsLine_node
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

const RelatedContainersDetailsDistribution: React.FC<{
  queryRef: PreloadedQuery<RelatedContainersDetailsQuery>;
}> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<RelatedContainersDetailsQuery>(
    relatedContainersDetailsQuery,
    queryRef,
  );

  const series = data?.stixCoreObjectsDistribution?.map((objectDistribution) => ({
    name: t_i18n(`entity_${objectDistribution?.label}`),
    data: [objectDistribution?.value],
  })) as ApexAxisChartSeries;

  return (<WidgetHorizontalBars
    series={series}
    distributed={false}
    stacked
    stackType='100%'
    legend={true}
          />);
};

interface RelatedContainersDetailsProps {
  containerId: string;
  relatedContainer: RelatedContainerNode;
}

const RelatedContainersDetails: React.FC<RelatedContainersDetailsProps> = ({ containerId, relatedContainer }) => {
  const { t_i18n, fldt } = useFormatter();

  const queryFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['Stix-Cyber-Observable', 'Indicator'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [
      {
        mode: 'and',
        filters: [
          {
            key: 'regardingOf',
            values: [
              { key: 'relationship_type', values: ['object'] },
              { key: 'id', values: [containerId] },
            ],
            operator: 'eq',
            mode: 'or',
          },
          {
            key: 'regardingOf',
            values: [
              { key: 'relationship_type', values: ['object'] },
              { key: 'id', values: [relatedContainer.id] },
            ],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      },
    ],
  };

  const [queryRefDistribution, loadQueryDistribution] = useQueryLoader<RelatedContainersDetailsQuery>(
    relatedContainersDetailsQuery,
  );

  useEffect(() => {
    if (!queryRefDistribution) {
      loadQueryDistribution({
        field: 'entity_type',
        operation: 'count',
        filters: queryFilters,
      } as unknown as RelatedContainersDetailsQuery$variables);
    }
  }, [loadQueryDistribution]);

  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<RelatedContainersDetailsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext(['Stix-Cyber-Observable', 'Indicator'], filters);
  console.log(contextFilters);
  const queryPaginationOptions = { ...paginationOptions, filters: queryFilters };

  const dataColumns = {
    entity_type: { percentWidth: 15 },
    name: { percentWidth: 25 },
    creator: { percentWidth: 15 },
    created_at: { percentWidth: 15 },
    objectLabel: { percentWidth: 15 },
    objectMarking: { percentWidth: 15 },
  };

  const queryRef = useQueryLoading(
    relatedContainersLinesQuery,
    { ...queryPaginationOptions, count: 25 },
  );

  const preloadedPaginationProps = { // creators: {},
    linesQuery: relatedContainersLinesQuery,
    linesFragment: relatedContainersLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<RelatedContainersDetailsLinesPaginationQuery>;

  return (
    <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
      <Grid item xs={6}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Description')}
        </Typography>
        <ExpandableMarkdown source={relatedContainer.description} limit={300} />
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Assignees')}
        </Typography>
        {/* <ItemAssignees assignees={relatedContainer.objectAssignee ?? []} stixDomainObjectId={relatedContainer.id}/> */}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Original creation date')}
        </Typography>
        {fldt(relatedContainer.modified)}
      </Grid>
      <Grid item xs={6}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Due Date')}
        </Typography>
        {/* <ItemDueDate due_date={relatedContainer.due_date} variant="inElement" /> */}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Processing status')}
        </Typography>
        {/* <ItemStatus status={relatedContainer.status} disabled={!relatedContainer.workflowEnabled} /> */}
        {relatedContainer.objectMarking && relatedContainer.objectMarking.length > 0 && (
        <>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Marking')}
          </Typography>
          <ItemMarkings markingDefinitions={relatedContainer.objectMarking}/>
        </>
        )}
      </Grid>
      <Grid item xs={12}>
        <Typography
          variant="h4"
          style={{ marginTop: 20 }}
        >
          {t_i18n('Correlated indicators and observables distribution')}
        </Typography>
        {queryRefDistribution && <RelatedContainersDetailsDistribution queryRef={queryRefDistribution} />}
        <Typography
          variant="h4"
          style={{ marginTop: 20 }}
        >
          {t_i18n('Correlated indicators and observables')}
        </Typography>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: RelatedContainersDetailsLines_data$data) => data.stixCoreObjects?.edges?.map((e) => e?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            lineFragment={relatedContainersLineFragment}
            preloadedPaginationProps={preloadedPaginationProps}
            entityTypes={['Stix-Cyber-Observable', 'Indicator']}
            searchContextFinal={{ entityTypes: ['Stix-Cyber-Observable', 'Indicator'] }}
            disableNavigation
            disableToolBar
            disableSelectAll
            canToggleLine={false}
          />
        )}
      </Grid>
    </Grid>
  );
};

export default RelatedContainersDetails;
