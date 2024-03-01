import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { VulnerabilityLine, VulnerabilityLineDummy } from './VulnerabilityLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { VulnerabilitiesLinesPaginationQuery, VulnerabilitiesLinesPaginationQuery$variables } from './__generated__/VulnerabilitiesLinesPaginationQuery.graphql';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { VulnerabilitiesLines_data$key } from './__generated__/VulnerabilitiesLines_data.graphql';

const nbOfRowsToLoad = 50;

interface VulnerabilityLinesProps {
  queryRef: PreloadedQuery<VulnerabilitiesLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: VulnerabilitiesLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const vulnerabilitiesLinesQuery = graphql`
  query VulnerabilitiesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: VulnerabilitiesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...VulnerabilitiesLines_data
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

const vulnerabilitiesLinesFragment = graphql`
  fragment VulnerabilitiesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "VulnerabilitiesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "VulnerabilitiesLinesRefetchQuery") {
    vulnerabilities(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_vulnerabilities") {
      edges {
        node {
          id
          name
          description
          ...VulnerabilityLine_node
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

const VulnerabilitiesLines: FunctionComponent<VulnerabilityLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  VulnerabilitiesLinesPaginationQuery,
  VulnerabilitiesLines_data$key
  >({
    linesQuery: vulnerabilitiesLinesQuery,
    linesFragment: vulnerabilitiesLinesFragment,
    queryRef,
    nodePath: ['vulnerabilities', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.vulnerabilities?.edges ?? []}
      globalCount={
        data?.vulnerabilities?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={VulnerabilityLine}
      DummyLineComponent={VulnerabilityLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default VulnerabilitiesLines;
