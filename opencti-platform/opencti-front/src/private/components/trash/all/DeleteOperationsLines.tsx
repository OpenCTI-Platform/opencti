import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DeleteOperationLine, DeleteOperationLineDummy } from '@components/trash/all/DeleteOperationLine';
import type { DeleteOperationsLines_data$key } from './__generated__/DeleteOperationsLines_data.graphql';
import type { DeleteOperationsLinesPaginationQuery, DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import { DeleteOperationLine_node$data } from './__generated__/DeleteOperationLine_node.graphql';

const nbOfRowsToLoad = 50;

interface DeleteOperationsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: DeleteOperationsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<DeleteOperationsLinesPaginationQuery>;
  selectedElements: Record<string, DeleteOperationLine_node$data>;
  deSelectedElements: Record<string, DeleteOperationLine_node$data>;
  onToggleEntity: (
    entity: DeleteOperationLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const deleteOperationsLinesQuery = graphql`
  query DeleteOperationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DeleteOperationOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DeleteOperationsLines_data
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

export const deleteOperationsLinesFragment = graphql`
  fragment DeleteOperationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DeleteOperationOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DeleteOperationsLinesRefetchQuery") {
    deleteOperations(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_deleteOperations") {
      edges {
        node {
          id
          ...DeleteOperationLine_node
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

const DeleteOperationsLines: FunctionComponent<DeleteOperationsLinesProps> = ({
  dataColumns,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  DeleteOperationsLinesPaginationQuery,
  DeleteOperationsLines_data$key
  >({
    linesQuery: deleteOperationsLinesQuery,
    linesFragment: deleteOperationsLinesFragment,
    queryRef,
    nodePath: ['deleteOperations', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.deleteOperations?.edges ?? []}
      globalCount={
        data?.deleteOperations?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={DeleteOperationLine}
      DummyLineComponent={DeleteOperationLineDummy}
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

export default DeleteOperationsLines;
