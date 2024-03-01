import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IndicatorLine, IndicatorLineDummyComponent } from './IndicatorLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import { IndicatorsLinesPaginationQuery, IndicatorsLinesPaginationQuery$variables } from './__generated__/IndicatorsLinesPaginationQuery.graphql';
import { IndicatorLine_node$data } from './__generated__/IndicatorLine_node.graphql';
import { IndicatorsLines_data$key } from './__generated__/IndicatorsLines_data.graphql';

const nbOfRowsToLoad = 50;

export const indicatorsLinesQuery = graphql`
  query IndicatorsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $filters: FilterGroup
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...IndicatorsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const indicatorsLinesFragment = graphql`
  fragment IndicatorsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    filters: { type: "FilterGroup" }
    orderBy: { type: "IndicatorsOrdering", defaultValue: valid_from }
    orderMode: { type: "OrderingMode", defaultValue: desc }
  )
  @refetchable(queryName: "IndicatorsLinesRefetchQuery") {
    indicators(
      search: $search
      first: $count
      after: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_indicators") {
      edges {
        node {
          id
          ...IndicatorLine_node
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

interface IndicatorsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: IndicatorsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<IndicatorsLinesPaginationQuery>;
  selectedElements: Record<string, IndicatorLine_node$data>;
  deSelectedElements: Record<string, IndicatorLine_node$data>;
  onToggleEntity: (
    entity: IndicatorLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const IndicatorsLines: FunctionComponent<IndicatorsLinesProps> = ({
  paginationOptions,
  queryRef,
  dataColumns,
  onLabelClick,
  setNumberOfElements,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IndicatorsLinesPaginationQuery,
  IndicatorsLines_data$key
  >({
    linesQuery: indicatorsLinesQuery,
    linesFragment: indicatorsLinesFragment,
    queryRef,
    nodePath: ['indicators', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.indicators?.edges ?? []}
      globalCount={data?.indicators?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={IndicatorLine}
      DummyLineComponent={IndicatorLineDummyComponent}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
      paginationOptions={paginationOptions}
    />
  );
};

export default IndicatorsLines;
