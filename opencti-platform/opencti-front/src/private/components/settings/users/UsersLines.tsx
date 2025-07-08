import React from 'react';
import { graphql, RelayPaginationProp } from 'react-relay';
import { UsersLinesPaginationQuery$variables } from '@components/settings/users/__generated__/UsersLinesPaginationQuery.graphql';
import { UsersLines_data$data } from '@components/settings/users/__generated__/UsersLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UserLine, UserLineDummy } from './UserLine';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

export const usersLinesSearchQuery = graphql`
  query UsersLinesSearchQuery(
      $first: Int, $search: String,
      $orderBy: UsersOrdering
      $orderMode: OrderingMode
  ) {
    users(first: $first, search: $search, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          entity_type
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
