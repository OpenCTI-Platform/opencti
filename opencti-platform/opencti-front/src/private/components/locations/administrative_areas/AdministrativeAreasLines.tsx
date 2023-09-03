import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  AdministrativeAreaLine,
  AdministrativeAreaLineDummy,
} from './AdministrativeAreaLine';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  AdministrativeAreasLinesPaginationQuery,
  AdministrativeAreasLinesPaginationQuery$variables,
} from './__generated__/AdministrativeAreasLinesPaginationQuery.graphql';
import { AdministrativeAreasLines_data$key } from './__generated__/AdministrativeAreasLines_data.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface AdministrativeAreasLinesProps {
  paginationOptions?: AdministrativeAreasLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<AdministrativeAreasLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const administrativeAreasLinesQuery = graphql`
  query AdministrativeAreasLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: AdministrativeAreasOrdering
    $orderMode: OrderingMode
    $filters: [AdministrativeAreasFiltering!]
  ) {
    ...AdministrativeAreasLines_data
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

const administrativeAreasLinesFragment = graphql`
  fragment AdministrativeAreasLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "AdministrativeAreasOrdering" }
    orderMode: { type: "OrderingMode" }
    filters: { type: "[AdministrativeAreasFiltering!]" }
  )
  @refetchable(queryName: "AdministrativeAreasLinesRefetchQuery") {
    administrativeAreas(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_administrativeAreas") {
      edges {
        node {
          id
          name
          description
          ...AdministrativeAreaLine_node
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

const AdministrativeAreasLines: FunctionComponent<
AdministrativeAreasLinesProps
> = ({ setNumberOfElements, dataColumns, queryRef, paginationOptions }) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  AdministrativeAreasLinesPaginationQuery,
  AdministrativeAreasLines_data$key
  >({
    linesQuery: administrativeAreasLinesQuery,
    linesFragment: administrativeAreasLinesFragment,
    queryRef,
    nodePath: ['administrativeAreas', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.administrativeAreas?.edges ?? []}
      globalCount={
        data?.administrativeAreas?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={AdministrativeAreaLine}
      DummyLineComponent={AdministrativeAreaLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default AdministrativeAreasLines;
