import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { FeedLine, FeedLineDummy } from './FeedLine';

const nbOfRowsToLoad = 50;

class FeedLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['feeds', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['feeds', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<FeedLine />}
        DummyLineComponent={<FeedLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

FeedLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  killChainPhases: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const FeedLinesQuery = graphql`
  query FeedLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: FeedOrdering
    $orderMode: OrderingMode
  ) {
    ...FeedLines_data
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
  FeedLines,
  {
    data: graphql`
      fragment FeedLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "FeedOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        feeds(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_feeds") {
          edges {
            node {
              ...FeedLine_node
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
      return props.data && props.data.feeds;
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
    query: FeedLinesQuery,
  },
);
