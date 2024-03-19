import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import {
  SupportPackageLinesPaginationQuery,
  SupportPackageLinesPaginationQuery$variables,
} from '@components/settings/support/__generated__/SupportPackageLinesPaginationQuery.graphql';
import { SupportPackageLines_data$key } from '@components/settings/support/__generated__/SupportPackageLines_data.graphql';
import SupportPackageLine from '@components/settings/support/SupportPackageLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface SupportPackageLinesProps {
  queryRef: PreloadedQuery<SupportPackageLinesPaginationQuery>;
  paginationOptions: SupportPackageLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const supportPackageLinesQuery = graphql`
  query SupportPackageLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SupportPackageOrdering
    $orderMode: OrderingMode
  ) {
    ...SupportPackageLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor   
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const supportPackageLinesFragment = graphql`
  fragment SupportPackageLines_data on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "SupportPackageOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc } 
  ) @refetchable(queryName: "SupportPackageLinesRefetchQuery") {
    supportPackages(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_supportPackages") {
      edges {
        node {
          ...SupportPackageLine_node
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

const SupportPackageLines: FunctionComponent<SupportPackageLinesProps> = ({
  queryRef,
  setNumberOfElements,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  SupportPackageLinesPaginationQuery,
  SupportPackageLines_data$key
  >({
    linesQuery: supportPackageLinesQuery,
    linesFragment: supportPackageLinesFragment,
    queryRef,
    nodePath: ['supportPackages', 'edges'],
    setNumberOfElements,
  });
  return (
    <>
      <ListLinesContent
        initialLoading={!data}
        loadMore={loadMore}
        hasMore={hasMore}
        isLoading={isLoadingMore}
        dataList={data?.supportPackages?.edges ?? []}
        globalCount={
          data?.supportPackages?.pageInfo?.globalCount ?? nbOfRowsToLoad
        }
        LineComponent={SupportPackageLine}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    </>

  );
};

export default SupportPackageLines;
