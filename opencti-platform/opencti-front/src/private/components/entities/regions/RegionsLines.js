import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RegionLine, RegionLineDummy } from './RegionLine';

const nbOfRowsToLoad = 25;

class RegionsLines extends Component {
  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['regions', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['regions', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<RegionLine />}
        DummyLineComponent={<RegionLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

RegionsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  regions: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const regionsLinesQuery = graphql`
  query RegionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: RegionsOrdering
    $orderMode: OrderingMode
  ) {
    ...RegionsLines_data
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
  RegionsLines,
  {
    data: graphql`
      fragment RegionsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "RegionsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        regions(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_regions") {
          edges {
            node {
              id
              name
              description
              ...RegionLine_node
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.regions;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: regionsLinesQuery,
  },
);
