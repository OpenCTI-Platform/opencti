import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UserLine, UserLineDummy } from './UserLine';
import { GroupUsersLinesQuery, GroupUsersLinesQuery$variables } from './__generated__/GroupUsersLinesQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { GroupUsersLines_data$key } from './__generated__/GroupUsersLines_data.graphql';

export const groupUsersLinesQuery = graphql`
  query GroupUsersLinesQuery(
    $id: String!
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
  ) {
    ...GroupUsersLines_data
      @arguments(
        id: $id
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const groupUsersLinesFragment = graphql`
  fragment GroupUsersLines_data on Query
  @argumentDefinitions(
    id: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "UsersOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "GroupUsersLinesRefetchQuery") {
    group(id: $id) {
      id
      name
      members(
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      ) @connection(key: "Pagination_group_members") {
        edges {
          node {
            ...UserLine_node            
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

interface GroupUsersLinesProps {
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<GroupUsersLinesQuery>;
  paginationOptions: GroupUsersLinesQuery$variables;
}

const nbOfRowsToLoad = 50;

const GroupUsersLines: FunctionComponent<GroupUsersLinesProps> = ({
  dataColumns,
  queryRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  GroupUsersLinesQuery,
  GroupUsersLines_data$key
  >({
    linesQuery: groupUsersLinesQuery,
    linesFragment: groupUsersLinesFragment,
    queryRef,
  });
  const membersData = data.group?.members;
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={membersData?.edges ?? []}
      globalCount={membersData?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={UserLine}
      DummyLineComponent={UserLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default GroupUsersLines;
