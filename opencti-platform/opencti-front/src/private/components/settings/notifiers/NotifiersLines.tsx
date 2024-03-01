import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { NotifierLine, NotifierLineDummy } from './NotifierLine';
import { NotifierLine_node$data } from './__generated__/NotifierLine_node.graphql';
import { NotifiersLinesPaginationQuery, NotifiersLinesPaginationQuery$variables } from './__generated__/NotifiersLinesPaginationQuery.graphql';
import { NotifiersLines_data$key } from './__generated__/NotifiersLines_data.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

const NotifierLineFragment = graphql`
  fragment NotifiersLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotifierOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NotifiersLinesRefetchQuery") {
    notifiers(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_notifiers") {
      edges {
        node {
          ...NotifierLine_node
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

export const NotifiersLinesQuery = graphql`
  query NotifiersLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: NotifierOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NotifiersLines_data
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

interface NotifiersLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: NotifiersLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<NotifiersLinesPaginationQuery>;
  selectedElements: Record<string, NotifierLine_node$data>;
  deSelectedElements: Record<string, NotifierLine_node$data>;
  onToggleEntity: (entity: NotifierLine_node$data, event: React.SyntheticEvent) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const NotifiersLines: FunctionComponent<NotifiersLinesProps> = ({
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
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<NotifiersLinesPaginationQuery, NotifiersLines_data$key>({
    linesQuery: NotifiersLinesQuery,
    linesFragment: NotifierLineFragment,
    queryRef,
    nodePath: ['notifiers', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.notifiers?.edges ?? []}
      globalCount={data?.notifiers?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={NotifierLine}
      DummyLineComponent={NotifierLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default NotifiersLines;
