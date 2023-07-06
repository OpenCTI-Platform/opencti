import React, { FunctionComponent, MutableRefObject } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UserLine, UserLineDummy } from './UserLine';
import {
  MembersListForGroupQuery,
  MembersListForGroupQuery$variables,
} from './__generated__/MembersListForGroupQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { MembersList_data$key } from './__generated__/MembersList_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

export const membersListForGroupQuery = graphql`
    query MembersListForGroupQuery(
        $id: String!
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: UsersOrdering
        $orderMode: OrderingMode
    ) {
        ...MembersList_data
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

const membersListFragment = graphql`
    fragment MembersList_data on Query
    @argumentDefinitions(
        id: { type: "String!" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "UsersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
    )
    @refetchable(queryName: "MembersListRefetchQuery") {
        group(id: $id) {
            id
            name
            members(
                search: $search
                first: $count
                after: $cursor
                orderBy: $orderBy
                orderMode: $orderMode
            ) @connection(key: "Pagination_members") {
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
  containerRef: MutableRefObject<null>;
  paginationOptions: MembersListForGroupQuery$variables;
}

const nbOfRowsToLoad = 50;

const MembersList: FunctionComponent<MembersListProps> = ({
  userColumns,
  queryRef,
  containerRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  MembersListForGroupQuery,
  MembersList_data$key
  >({
    linesQuery: membersListForGroupQuery,
    linesFragment: membersListFragment,
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
      containerRef={containerRef}
    />
  );
};

export default MembersList;
