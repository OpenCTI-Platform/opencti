import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import React, { FunctionComponent, useEffect } from 'react';
import {
  SupportPackageLinesPaginationQuery,
  SupportPackageLinesPaginationQuery$variables,
} from '@components/settings/support/__generated__/SupportPackageLinesPaginationQuery.graphql';
import { SupportPackageLines_data$key } from '@components/settings/support/__generated__/SupportPackageLines_data.graphql';
import SupportPackageLine from '@components/settings/support/SupportPackageLine';
import { interval } from 'rxjs';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { FIVE_SECONDS } from '../../../../utils/Time';

const nbOfRowsToLoad = 50;

interface SupportPackageLinesProps {
  dataColumns: DataColumns;
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
    orderBy: { type: "SupportPackageOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc } 
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
          id
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
  dataColumns,
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

  const queryData = usePreloadedQuery(supportPackageLinesQuery, queryRef);

  const [_, refetch] = useRefetchableFragment<
  SupportPackageLinesPaginationQuery,
  SupportPackageLines_data$key
  >(supportPackageLinesFragment, queryData);

  useEffect(() => {
    const subscription = interval(FIVE_SECONDS).subscribe(() => {
      refetch({}, { fetchPolicy: 'store-and-network' });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, [refetch]);

  return (
    <>
      <ListLinesContent
        initialLoading={!data}
        loadMore={loadMore}
        hasMore={hasMore}
        isLoading={isLoadingMore}
        dataColumns={dataColumns}
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
