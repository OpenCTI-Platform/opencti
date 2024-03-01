import React from 'react';
import { createPaginationContainer, graphql, RelayPaginationProp } from 'react-relay';
import { UsersLinesPaginationQuery$variables } from '@components/settings/users/__generated__/UsersLinesPaginationQuery.graphql';
import { UsersLines_data$data } from '@components/settings/users/__generated__/UsersLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UserLine, UserLineDummy } from './UserLine';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

export const usersLinesSearchQuery = graphql`
  query UsersLinesSearchQuery($search: String) {
    users(search: $search) {
      edges {
        node {
          id
          name
          user_email
        }
      }
    }
  }
`;

interface UsersLinesProps {
  initialLoading: boolean
  dataColumns: DataColumns
  relay: RelayPaginationProp,
  paginationOptions: UsersLinesPaginationQuery$variables
  data: UsersLines_data$data
}

const UsersLines: React.FC<UsersLinesProps> = (props) => {
  const { initialLoading, dataColumns, relay, paginationOptions, data } = props;
  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore.bind(this)}
      hasMore={relay.hasMore.bind(this)}
      isLoading={relay.isLoading.bind(this)}
      dataList={data?.users?.edges ?? []}
      globalCount={data?.users?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={UserLine}
      DummyLineComponent={UserLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export const usersLinesQuery = graphql`
  query UsersLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
  ) {
    ...UsersLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  UsersLines,
  {
    data: graphql`
      fragment UsersLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "UsersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        users(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_users") {
          edges {
            node {
              id
              name
              firstname
              lastname
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.users;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: usersLinesQuery,
  },
);
