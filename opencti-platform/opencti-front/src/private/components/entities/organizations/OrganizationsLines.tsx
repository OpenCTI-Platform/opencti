import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  OrganizationsLinesPaginationQuery,
  OrganizationsLinesPaginationQuery$variables,
} from '@components/entities/organizations/__generated__/OrganizationsLinesPaginationQuery.graphql';
import { OrganizationsLines_data$key } from '@components/entities/organizations/__generated__/OrganizationsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { OrganizationLine, OrganizationLineDummy } from './OrganizationLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface OrganizationsLinesProps {
  queryRef: PreloadedQuery<OrganizationsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: OrganizationsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const organizationsLinesQuery = graphql`
  query OrganizationsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...OrganizationsLines_data
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

export const organizationsLinesFragment = graphql`
  fragment OrganizationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "OrganizationsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "OrganizationsLinesRefetchQuery") {
    organizations(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_organizations") {
      edges {
        node {
          id
          name
          description
          ...OrganizationLine_node
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

const OrganizationsLines: FunctionComponent<OrganizationsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  OrganizationsLinesPaginationQuery,
  OrganizationsLines_data$key
  >({
    linesQuery: organizationsLinesQuery,
    linesFragment: organizationsLinesFragment,
    queryRef,
    nodePath: ['organizations', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.organizations?.edges ?? []}
      globalCount={
        data?.organizations?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={OrganizationLine}
      DummyLineComponent={OrganizationLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default OrganizationsLines;
