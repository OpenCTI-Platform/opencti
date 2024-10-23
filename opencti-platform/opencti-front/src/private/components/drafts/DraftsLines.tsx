import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DraftLine, DraftLineDummy } from '@components/drafts/DraftLine';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { DraftsLines_data$key } from '@components/drafts/__generated__/DraftsLines_data.graphql';
import { UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface DraftsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: DraftsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<DraftsLinesPaginationQuery>;
}

export const draftsLinesQuery = graphql`
    query DraftsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftsLines_data
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

export const draftsLinesFragment = graphql`
    fragment DraftsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DraftWorkspacesOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftsLinesRefetchQuery") {
        draftWorkspaces(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaces") {
            edges {
                node {
                    id
                    ...DraftLine_node
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

const DraftLines: FunctionComponent<DraftsLinesProps> = ({
  dataColumns,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  DraftsLinesPaginationQuery,
  DraftsLines_data$key
  >({
    linesQuery: draftsLinesQuery,
    linesFragment: draftsLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaces', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.draftWorkspaces?.edges ?? []}
      globalCount={
        data?.draftWorkspaces?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={DraftLine}
      DummyLineComponent={DraftLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default DraftLines;
