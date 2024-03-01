import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RoleLine, RoleLineDummy } from './RoleLine';

const nbOfRowsToLoad = 50;

class RolesLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions, data } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={data?.roles?.edges ?? []}
        globalCount={data?.roles?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={<RoleLine />}
        DummyLineComponent={<RoleLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

RolesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  groups: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const rolesLinesQuery = graphql`
  query RolesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: RolesOrdering
    $orderMode: OrderingMode
  ) {
    ...RolesLines_data
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
  RolesLines,
  {
    data: graphql`
      fragment RolesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "RolesOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        roles(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_roles") {
          edges {
            node {
              ...RoleLine_node
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
    query: rolesLinesQuery,
  },
);
