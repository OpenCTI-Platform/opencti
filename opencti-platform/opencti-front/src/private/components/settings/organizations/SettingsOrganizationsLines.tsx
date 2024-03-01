import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { SettingsOrganizationsLines_data$key } from './__generated__/SettingsOrganizationsLines_data.graphql';
import { SettingsOrganizationsLinesPaginationQuery, SettingsOrganizationsLinesPaginationQuery$variables } from './__generated__/SettingsOrganizationsLinesPaginationQuery.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { SettingsOrganizationLine, SettingsOrganizationLineDummy } from './SettingsOrganizationLine';

const nbOfRowsToLoad = 50;

export interface SettingsOrganizationsLinesProps {
  paginationOptions: SettingsOrganizationsLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<SettingsOrganizationsLinesPaginationQuery>;
}

export const settingsOrganizationsLinesQuery = graphql`
  query SettingsOrganizationsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SettingsOrganizationsLines_data
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

export const settingsOrganizationsLinesFragment = graphql`
  fragment SettingsOrganizationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "OrganizationsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "SettingsOrganizationsLinesRefetchQuery") {
    organizations(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_organizations") {
      edges {
        node {
          id
          name
          description
          ...SettingsOrganizationLine_node
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

const SettingsOrganizationsLines: FunctionComponent<SettingsOrganizationsLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  SettingsOrganizationsLinesPaginationQuery,
  SettingsOrganizationsLines_data$key
  >({
    queryRef,
    linesQuery: settingsOrganizationsLinesQuery,
    linesFragment: settingsOrganizationsLinesFragment,
    nodePath: ['organizations', 'pageInfo', 'globalCount'],
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.organizations?.edges ?? []}
      globalCount={data?.organizations?.pageInfo?.globalCount}
      LineComponent={SettingsOrganizationLine}
      DummyLineComponent={SettingsOrganizationLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default SettingsOrganizationsLines;
