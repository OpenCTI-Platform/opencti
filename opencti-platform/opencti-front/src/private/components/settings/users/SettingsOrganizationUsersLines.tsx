import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { SettingsOrganizationUserLine, SettingsOrganizationUserLineDummy } from '@components/settings/users/SettingsOrganizationUserLine';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { SettingsOrganizationUsersLinesQuery, SettingsOrganizationUsersLinesQuery$variables } from './__generated__/SettingsOrganizationUsersLinesQuery.graphql';
import { SettingsOrganizationUsersLines_data$key } from './__generated__/SettingsOrganizationUsersLines_data.graphql';

export const settingsOrganizationUsersLinesQuery = graphql`
  query SettingsOrganizationUsersLinesQuery(
    $id: String!
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
  ) {
    ...SettingsOrganizationUsersLines_data
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

const settingsOrganizationUsersLinesFragment = graphql`
  fragment SettingsOrganizationUsersLines_data on Query
  @argumentDefinitions(
    id: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "UsersOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "SettingsOrganizationUsersLinesRefetchQuery") {
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
            ...SettingsOrganizationUserLine_node
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

interface SettingsOrganizationUsersLinesProps {
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<SettingsOrganizationUsersLinesQuery>;
  paginationOptions: SettingsOrganizationUsersLinesQuery$variables;
}

const nbOfRowsToLoad = 50;

const SettingsOrganizationUsersLines: FunctionComponent<
SettingsOrganizationUsersLinesProps
> = ({ dataColumns, queryRef, paginationOptions }) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  SettingsOrganizationUsersLinesQuery,
  SettingsOrganizationUsersLines_data$key
  >({
    linesQuery: settingsOrganizationUsersLinesQuery,
    linesFragment: settingsOrganizationUsersLinesFragment,
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
      LineComponent={SettingsOrganizationUserLine}
      DummyLineComponent={SettingsOrganizationUserLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      entityId={data.organization?.id}
    />
  );
};

export default SettingsOrganizationUsersLines;
