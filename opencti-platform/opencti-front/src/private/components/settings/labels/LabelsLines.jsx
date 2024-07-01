import React from 'react';
import { graphql } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { LabelLine, LabelLineDummy } from './LabelLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

export const labelsLinesQuery = graphql`
  query LabelsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: LabelsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...LabelsLines_data
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

const labelsLinesFragment = graphql`
  fragment LabelsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "LabelsOrdering", defaultValue: value }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "LabelsLinesPaginationRefetchQuery") {
    labels(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )@connection(key: "Pagination_labels") {
      edges {
        node {
          id
          entity_type
          ...LabelLine_node
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

const LabelsLines = ({
  dataColumns,
  paginationOptions,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  queryRef,
  setNumberOfElements,
}) => {
  const { data, isLoadingMore, hasMore, loadMore } = usePreloadedPaginationFragment({
    linesQuery: labelsLinesQuery,
    linesFragment: labelsLinesFragment,
    queryRef,
    nodePath: ['labels', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={pathOr([], ['labels', 'edges'], data)}
      globalCount={pathOr(
        nbOfRowsToLoad,
        ['labels', 'pageInfo', 'globalCount'],
        data,
      )}
      LineComponent={<LabelLine />}
      DummyLineComponent={<LabelLineDummy />}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default LabelsLines;
