import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';

export interface OrganizationsLinesProps {
  // paginationOptions: SettingsOrganizationsLines_DataQuery$variables;
  dataColumns: DataColumns;
  // queryRef: PreloadedQuery<SettingsOrganizationsLinesPaginationQuery>;
}

export const organizationsLinesQuery = graphql`
  query SettingsOrganizationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: [OrganizationsFiltering]
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

export const organizationsLinesFragment = graphql`
  fragment SettingsOrganizationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "OrganizationsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[OrganizationsFiltering]" }
  ) {
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

const OrganizationsLines: FunctionComponent<OrganizationsLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  // const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  // SettingsOrganizationsLines_DataQuery,
  // SettingsOrganizationsLines_data$key
  // >({
  //   queryRef,
  //   linesQuery: organizationsLinesQuery,
  //   linesFragment: organizationsLinesFragment,
  //   nodePath: ['organizations', 'pageInfo', 'globalCount'],
  // });
  return (
    <div>
      OrganizationsLines
    </div>
  );
};

export default OrganizationsLines;
