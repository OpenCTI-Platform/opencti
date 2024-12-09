import React from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { graphql } from 'react-relay';
import {
  RelatedContainersDetailsTableLinesPaginationQuery,
} from '@components/common/containers/related_containers/__generated__/RelatedContainersDetailsTableLinesPaginationQuery.graphql';
import { RelatedContainersDetailsTableLines_data$data } from '@components/common/containers/related_containers/__generated__/RelatedContainersDetailsTableLines_data.graphql';
import { useFormatter } from '../../../../../components/i18n';
import DataTable from '../../../../../components/dataGrid/DataTable';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';

const LOCAL_STORAGE_KEY = 'RelatedContainersDetailsTable';

const relatedContainersDetailsTableLinesQuery = graphql`
  query RelatedContainersDetailsTableLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RelatedContainersDetailsTableLines_data
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

const relatedContainersDetailsTableLineFragment = graphql`
  fragment RelatedContainersDetailsTableLine_node on StixCoreObject {
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

const relatedContainersDetailsTableLinesFragment = graphql`
  fragment RelatedContainersDetailsTableLines_data on Query
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
  @refetchable(queryName: "RelatedContainersDetailsTableLinesRefetchQuery") {
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
          ...RelatedContainersDetailsTableLine_node
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

interface RelatedContainersDetailsTableProps {
  filters: FilterGroup;
}

const RelatedContainersDetailsTable: React.FC<RelatedContainersDetailsTableProps> = ({ filters: queryFilters }) => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<RelatedContainersDetailsTableLinesPaginationQuery>(
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
    relatedContainersDetailsTableLinesQuery,
    { ...queryPaginationOptions, count: 25 },
  );

  const preloadedPaginationProps = { // creators: {},
    linesQuery: relatedContainersDetailsTableLinesQuery,
    linesFragment: relatedContainersDetailsTableLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<RelatedContainersDetailsTableLinesPaginationQuery>;

  return (
    <Grid item xs={12} >
      <Typography
        variant="h4"
        style={{ marginTop: 20 }}
      >
        {t_i18n('Correlated indicators and observables')}
      </Typography>
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: RelatedContainersDetailsTableLines_data$data) => data.stixCoreObjects?.edges?.map((e) => e?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        lineFragment={relatedContainersDetailsTableLineFragment}
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
  );
};

export default RelatedContainersDetailsTable;
