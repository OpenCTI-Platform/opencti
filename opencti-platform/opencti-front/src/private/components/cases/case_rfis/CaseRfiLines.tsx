import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  CaseRfiLinesCasesPaginationQuery,
  CaseRfiLinesCasesPaginationQuery$variables,
} from './__generated__/CaseRfiLinesCasesPaginationQuery.graphql';
import { CaseRfiLineCase_node$data } from './__generated__/CaseRfiLineCase_node.graphql';
import { CaseRfiLinesCases_data$key } from './__generated__/CaseRfiLinesCases_data.graphql';
import { CaseRfiLine, CaseRfiLineDummy } from './CaseRfiLine';

const nbOfRowsToLoad = 50;

interface CasesLinesProps {
  paginationOptions?: CaseRfiLinesCasesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<CaseRfiLinesCasesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, CaseRfiLineCase_node$data>;
  deSelectedElements: Record<string, CaseRfiLineCase_node$data>;
  onToggleEntity: (
    entity: CaseRfiLineCase_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const caseRfisLinesQuery = graphql`
  query CaseRfiLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseRfisOrdering
    $orderMode: OrderingMode
    $filters: [CaseRfisFiltering!]
  ) {
    ...CaseRfiLinesCases_data
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

const caseRfisLinesFragment = graphql`
  fragment CaseRfiLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseRfisOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CaseRfisFiltering!]" }
  )
  @refetchable(queryName: "CaseRfiCasesLinesRefetchQuery") {
    caseRfis(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_case_caseRfis") {
      edges {
        node {
          id
          ...CaseRfiLineCase_node
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

const CaseRfisLines: FunctionComponent<CasesLinesProps> = ({
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
  CaseRfiLinesCasesPaginationQuery,
  CaseRfiLinesCases_data$key
  >({
    linesQuery: caseRfisLinesQuery,
    linesFragment: caseRfisLinesFragment,
    queryRef,
    nodePath: ['caseRfis', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.caseRfis?.edges ?? []}
      globalCount={data?.caseRfis?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CaseRfiLine}
      DummyLineComponent={CaseRfiLineDummy}
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

export default CaseRfisLines;
