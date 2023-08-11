import { PreloadedQuery, graphql } from 'react-relay';
import { FunctionComponent } from 'react';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AssetLineComponent, AssetLineDummy } from './AssetLine';
import {
  AssetLinesPaginationQuery,
  AssetLinesPaginationQuery$variables,
} from './__generated__/AssetLinesPaginationQuery.graphql';
import { AssetLines_data$key } from './__generated__/AssetLines_data.graphql';

const nbOfRowsToLoad = 50;

interface AssetLinesProps {
  queryRef: PreloadedQuery<AssetLinesPaginationQuery>,
  dataColumns: DataColumns,
  paginationOptions?: AssetLinesPaginationQuery$variables,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'],
}

export const assetLinesQuery = graphql`
  query AssetLinesPaginationQuery (
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: FinancialAssetOrdering
    $orderMode: OrderingMode
    $filters: [FinancialAssetFiltering!]
  ) {
    ...AssetLines_data @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const assetLinesFragment = graphql`
  fragment AssetLines_data on Query
    @argumentDefinitions(
      search: { type: "String" }
      count: { type: "Int", defaultValue: 25 }
      cursor: { type: "ID" }
      orderBy: { type: "FinancialAssetOrdering", defaultValue: name }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "[FinancialAssetFiltering!]" }
    ) @refetchable(queryName: "AssetLinesRefetchQuery") {
    financialAssets(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_financialAssets") {
      edges {
        node {
          id
          name
          ...AssetLine_node
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

const AssetLinesComponent: FunctionComponent<AssetLinesProps> = ({ setNumberOfElements, queryRef, dataColumns, paginationOptions }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<AssetLinesPaginationQuery, AssetLines_data$key>({
    linesQuery: assetLinesQuery,
    linesFragment: assetLinesFragment,
    queryRef,
    nodePath: ['financialAssets', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <div>
      <ListLinesContent
        initialLoading={!data}
        isLoading={isLoadingMore}
        loadMore={loadMore}
        hasMore={hasMore}
        dataList={data?.financialAssets?.edges ?? []}
        globalCount={data?.financialAssets?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={AssetLineComponent}
        DummyLineComponent={AssetLineDummy}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default AssetLinesComponent;
