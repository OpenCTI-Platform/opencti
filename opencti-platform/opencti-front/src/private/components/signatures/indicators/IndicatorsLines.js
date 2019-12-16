import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IndicatorLine, IndicatorLineDummy } from './IndicatorLine';

const nbOfRowsToLoad = 25;

class IndicatorsLines extends Component {
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
        dataList={pathOr([], ['indicators', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['indicators', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<IndicatorLine />}
        DummyLineComponent={<IndicatorLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

IndicatorsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  indicators: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const indicatorsLinesQuery = graphql`
  query IndicatorsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...IndicatorsLines_data
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
  IndicatorsLines,
  {
    data: graphql`
      fragment IndicatorsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "IndicatorsOrdering", defaultValue: "valid_from" }
          orderMode: { type: "OrderingMode", defaultValue: "desc" }
        ) {
        indicators(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_indicators") {
          edges {
            node {
              id
              ...IndicatorLine_node
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
      return props.data && props.data.indicators;
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
    query: indicatorsLinesQuery,
  },
);
