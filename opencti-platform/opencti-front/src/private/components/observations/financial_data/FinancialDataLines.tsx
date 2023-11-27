import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from 'src/components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from 'src/utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from 'src/utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from 'src/components/list_lines/ListLinesContent';
import { FinancialDataLinesPaginationQuery, FinancialDataLinesPaginationQuery$variables } from './__generated__/FinancialDataLinesPaginationQuery.graphql';
import { FinancialDataLines_data$key } from './__generated__/FinancialDataLines_data.graphql';
import { FinancialDataLine, FinancialDataLineDummy } from './FinancialDataLine';
import { FinancialDataLine_node$data } from './__generated__/FinancialDataLine_node.graphql';

const nbOfRowsToLoad = 50;

export const financialDataLinesQuery = graphql`
  query FinancialDataLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...FinancialDataLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const financialDataLinesSearchQuery = graphql`
  query FinancialDataLinesSearchQuery(
    $types: [String]
    $search: String
    $filters: FilterGroup
    $count: Int
  ) {
    stixCyberObservables(
      types: $types
      search: $search
      filters: $filters
      first: $count
    ) {
      edges {
        node {
          id
          standard_id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    }
  }
`;

const financialDataLinesFragment = graphql`
  fragment FinancialDataLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCyberObservablesOrdering"
      defaultValue: created_at
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "FinancialDataLinesRefetchQuery") {
    stixCyberObservables(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCyberObservables") {
      edges {
        node {
          id
          entity_type
          observable_value
          created_at
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...FinancialDataLine_node
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

interface FinancialDataLinesProps {
  queryRef: PreloadedQuery<FinancialDataLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: FinancialDataLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, FinancialDataLine_node$data>;
  deSelectedElements: Record<string, FinancialDataLine_node$data>;
  onToggleEntity: (
    entity: FinancialDataLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const FinancialDataLines: FunctionComponent<FinancialDataLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
  queryRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  FinancialDataLinesPaginationQuery,
  FinancialDataLines_data$key
  >({
    linesQuery: financialDataLinesQuery,
    linesFragment: financialDataLinesFragment,
    queryRef,
    nodePath: ['stixCyberObservables', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const dataList = data?.stixCyberObservables?.edges;
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={dataList ?? []}
      globalCount={data?.stixCyberObservables?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={FinancialDataLine}
      DummyLineComponent={FinancialDataLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElement={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default FinancialDataLines;
