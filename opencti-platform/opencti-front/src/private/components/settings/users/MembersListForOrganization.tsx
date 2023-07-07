import React, { FunctionComponent, MutableRefObject } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UserLine, UserLineDummy } from './UserLine';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  MembersListForOrganizationQuery,
  MembersListForOrganizationQuery$variables,
} from './__generated__/MembersListForOrganizationQuery.graphql';
import { MembersListForOrganization_data$key } from './__generated__/MembersListForOrganization_data.graphql';

export const membersListForOrganizationQuery = graphql`
    query MembersListForOrganizationQuery(
        $id: String!
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: UsersOrdering
        $orderMode: OrderingMode
    ) {
        ...MembersListForOrganization_data
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

const membersListForOrganizationFragment = graphql`
    fragment MembersListForOrganization_data on Query
    @argumentDefinitions(
        id: { type: "String!" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "UsersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
    )
    @refetchable(queryName: "MembersListForOrganizationRefetchQuery") {
        organization(id: $id) {
            id
            name
            members(
                search: $search
                first: $count
                after: $cursor
                orderBy: $orderBy
                orderMode: $orderMode
            ) @connection(key: "Pagination_organization_members") {
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
  queryRef: PreloadedQuery<MembersListForOrganizationQuery>;
  containerRef: MutableRefObject<null>;
  paginationOptions: MembersListForOrganizationQuery$variables;
}

const nbOfRowsToLoad = 50;

const MembersListForOrganization: FunctionComponent<MembersListProps> = ({
  userColumns,
  queryRef,
  containerRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  MembersListForOrganizationQuery,
  MembersListForOrganization_data$key
  >({
    linesQuery: membersListForOrganizationQuery,
    linesFragment: membersListForOrganizationFragment,
    queryRef,
  });
  const membersData = data.organization?.members;
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

export default MembersListForOrganization;
