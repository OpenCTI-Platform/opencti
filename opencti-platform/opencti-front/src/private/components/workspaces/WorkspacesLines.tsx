import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { WorkspacesLinesPaginationQuery, WorkspacesLinesPaginationQuery$variables } from '@components/workspaces/__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspacesLines_data$key } from '@components/workspaces/__generated__/WorkspacesLines_data.graphql';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { WorkspaceLine, WorkspaceLineDummy } from './WorkspaceLine';
import { UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

export const workspacesLinesQuery = graphql`
  query WorkspacesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...WorkspacesLines_data
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

export const workspacesLineFragment = graphql`
  fragment WorkspacesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "WorkspacesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "WorkspacesLinesRefetchQuery") {
    workspaces(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_workspaces") {
      edges {
        node {
          id
          ...WorkspaceLine_node
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

interface WorkspacesLinesProps {
  dataColumns: DataColumns;
  paginationOptions: WorkspacesLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<WorkspacesLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}
const WorkspacesLines: FunctionComponent<WorkspacesLinesProps> = ({
  dataColumns,
  paginationOptions,
  queryRef,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  WorkspacesLinesPaginationQuery,
  WorkspacesLines_data$key
  >({
    linesQuery: workspacesLinesQuery,
    linesFragment: workspacesLineFragment,
    queryRef,
    nodePath: ['workspaces', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.workspaces?.edges ?? []}
      globalCount={data?.workspaces?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={WorkspaceLine}
      DummyLineComponent={WorkspaceLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default WorkspacesLines;
