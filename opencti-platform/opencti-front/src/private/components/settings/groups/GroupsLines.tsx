import React from 'react';
import { graphql, createPaginationContainer, RelayPaginationProp } from 'react-relay';
import { pathOr } from 'ramda';
import { GroupsLinesPaginationQuery$variables } from '@components/settings/groups/__generated__/GroupsLinesPaginationQuery.graphql';
import { GroupsLines_data$data } from '@components/settings/groups/__generated__/GroupsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { GroupLine, GroupLineDummy } from './GroupLine';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface GroupsLinesProps {
  initialLoading: boolean
  dataColumns: DataColumns
  relay: RelayPaginationProp,
  paginationOptions: GroupsLinesPaginationQuery$variables
  data: GroupsLines_data$data
}

const GroupsLines: React.FC<GroupsLinesProps> = (props) => {
  const { initialLoading, dataColumns, relay, paginationOptions, data } = props;
  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore.bind(this)}
      hasMore={relay.hasMore.bind(this)}
      isLoading={relay.isLoading.bind(this)}
      dataList={pathOr([], ['groups', 'edges'], data)}
      globalCount={pathOr(
        nbOfRowsToLoad,
        ['groups', 'pageInfo', 'globalCount'],
        data,
      )}
      LineComponent={GroupLine}
      DummyLineComponent={GroupLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export const groupsLinesQuery = graphql`
  query GroupsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: GroupsOrdering
    $orderMode: OrderingMode
  ) {
    ...GroupsLines_data
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
  GroupsLines,
  {
    data: graphql`
      fragment GroupsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "GroupsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        groups(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_groups") {
          edges {
            node {
              ...GroupLine_node
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
      return props.data && props.data.groups;
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
    query: groupsLinesQuery,
  },
);
