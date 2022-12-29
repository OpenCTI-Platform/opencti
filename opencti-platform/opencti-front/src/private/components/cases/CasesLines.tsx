import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../components/list_lines';
import type { UseLocalStorage } from '../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import { CaseLine, CaseLineDummy } from './CaseLine';
import {
  CasesLinesPaginationQuery,
  CasesLinesPaginationQuery$variables,
} from './__generated__/CasesLinesPaginationQuery.graphql';
import { CasesLines_data$key } from './__generated__/CasesLines_data.graphql';

const nbOfRowsToLoad = 50;

interface CasesLinesProps {
  paginationOptions?: CasesLinesPaginationQuery$variables,
  dataColumns: DataColumns,
  queryRef: PreloadedQuery<CasesLinesPaginationQuery>,
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'],
}

export const casesLinesQuery = graphql`
  query CasesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CasesOrdering
    $orderMode: OrderingMode
    $filters: [CasesFiltering!]
  ) {
    ...CasesLines_data
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

const casesLinesFragment = graphql`
  fragment CasesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CasesOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CasesFiltering!]" }
  ) @refetchable(queryName: "CasesLinesRefetchQuery") {
    cases(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_cases") {
      edges {
        node {
          id
          name
          type
          description
          rating
          creator {
            id
            name
          }
          ...CaseLine_node
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

const CasesLines: FunctionComponent<CasesLinesProps> = ({ setNumberOfElements, dataColumns, queryRef, paginationOptions }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<CasesLinesPaginationQuery, CasesLines_data$key>({
    linesQuery: casesLinesQuery,
    linesFragment: casesLinesFragment,
    queryRef,
    nodePath: ['cases', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.cases?.edges ?? []}
      globalCount={data?.cases?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CaseLine}
      DummyLineComponent={CaseLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default CasesLines;
