import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { CaseRftLine, CaseRftLineDummy } from './CaseRftLine';
import { CaseRftLinesCases_data$key } from './__generated__/CaseRftLinesCases_data.graphql';
import {
  CaseRftLinesCasesPaginationQuery,
  CaseRftLinesCasesPaginationQuery$variables,
} from './__generated__/CaseRftLinesCasesPaginationQuery.graphql';
import { CaseRftLineCase_node$data } from './__generated__/CaseRftLineCase_node.graphql';

const nbOfRowsToLoad = 50;

interface CasesLinesProps {
  paginationOptions?: CaseRftLinesCasesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<CaseRftLinesCasesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, CaseRftLineCase_node$data>;
  deSelectedElements: Record<string, CaseRftLineCase_node$data>;
  onToggleEntity: (
    entity: CaseRftLineCase_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const caseRftsLinesQuery = graphql`
  query CaseRftLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseRftsOrdering
    $orderMode: OrderingMode
    $filters: [CaseRftsFiltering!]
  ) {
    ...CaseRftLinesCases_data
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

const caseRftsLinesFragment = graphql`
  fragment CaseRftLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseRftsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CaseRftsFiltering!]" }
  )
  @refetchable(queryName: "CaseRftCasesLinesRefetchQuery") {
    caseRfts(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_case_caseRfts") {
      edges {
        node {
          id
          ...CaseRftLineCase_node
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

const CaseRftsLines: FunctionComponent<CasesLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  CaseRftLinesCasesPaginationQuery,
  CaseRftLinesCases_data$key
  >({
    linesQuery: caseRftsLinesQuery,
    linesFragment: caseRftsLinesFragment,
    queryRef,
    nodePath: ['caseRfts', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.caseRfts?.edges ?? []}
      globalCount={data?.caseRfts?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CaseRftLine}
      DummyLineComponent={CaseRftLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default CaseRftsLines;
