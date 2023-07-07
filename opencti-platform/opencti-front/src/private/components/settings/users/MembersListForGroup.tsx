import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UserLine, UserLineDummy } from './UserLine';
import {
  MembersListForGroupQuery,
  MembersListForGroupQuery$variables,
} from './__generated__/MembersListForGroupQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { MembersListForGroup_data$key } from './__generated__/MembersListForGroup_data.graphql';

export const membersListForGroupQuery = graphql`
    query MembersListForGroupQuery(
        $id: String!
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: UsersOrdering
        $orderMode: OrderingMode
    ) {
        ...MembersListForGroup_data
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

const membersListForGroupFragment = graphql`
    fragment MembersListForGroup_data on Query
    @argumentDefinitions(
        id: { type: "String!" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "UsersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
    )
    @refetchable(queryName: "MembersListForGroupRefetchQuery") {
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
                        id
                        user_email
                        name
                        firstname
                        lastname
                        external
                        created_at
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

interface MembersListProps {
  userColumns: DataColumns,
  queryRef: PreloadedQuery<MembersListForGroupQuery>;
  paginationOptions: MembersListForGroupQuery$variables;
}

const nbOfRowsToLoad = 50;

const MembersListForGroup: FunctionComponent<MembersListProps> = ({
  userColumns,
  queryRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  MembersListForGroupQuery,
  MembersListForGroup_data$key
  >({
    linesQuery: membersListForGroupQuery,
    linesFragment: membersListForGroupFragment,
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
      dataColumns={userColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default MembersListForGroup;
