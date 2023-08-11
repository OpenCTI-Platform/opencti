import { PreloadedQuery, graphql } from 'react-relay';
import { FunctionComponent } from 'react';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AccountLineComponent, AccountLineDummy } from './AccountLine';
import {
  AccountsLinesPaginationQuery,
  AccountsLinesPaginationQuery$variables,
} from './__generated__/AccountsLinesPaginationQuery.graphql';
import { AccountsLines_data$key } from './__generated__/AccountsLines_data.graphql';

const nbOfRowsToLoad = 50;

interface AccountsLinesProps {
  queryRef: PreloadedQuery<AccountsLinesPaginationQuery>,
  dataColumns: DataColumns,
  paginationOptions?: AccountsLinesPaginationQuery$variables,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'],
}

export const accountsLinesQuery = graphql`
  query AccountsLinesPaginationQuery (
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: FinancialAccountOrdering
    $orderMode: OrderingMode
    $filters: [FinancialAccountFiltering!]
  ) {
    ...AccountsLines_data @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const accountsLinesFragment = graphql`
  fragment AccountsLines_data on Query
    @argumentDefinitions(
      search: { type: "String" }
      count: { type: "Int", defaultValue: 25 }
      cursor: { type: "ID" }
      orderBy: { type: "FinancialAccountOrdering", defaultValue: name }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "[FinancialAccountFiltering!]" }
    ) @refetchable(queryName: "AccountsLinesRefetchQuery") {
    financialAccounts(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_financialAccounts") {
      edges {
        node {
          id
          name
          ...AccountLine_node
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

const AccountsLinesComponent: FunctionComponent<AccountsLinesProps> = ({ setNumberOfElements, queryRef, dataColumns, paginationOptions }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<AccountsLinesPaginationQuery, AccountsLines_data$key>({
    linesQuery: accountsLinesQuery,
    linesFragment: accountsLinesFragment,
    queryRef,
    nodePath: ['financialAccounts', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <div>
      <ListLinesContent
        initialLoading={!data}
        isLoading={isLoadingMore}
        loadMore={loadMore}
        hasMore={hasMore}
        dataList={data?.financialAccounts?.edges ?? []}
        globalCount={data?.financialAccounts?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={AccountLineComponent}
        DummyLineComponent={AccountLineDummy}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default AccountsLinesComponent;
