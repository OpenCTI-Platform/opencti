import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import { interval } from 'rxjs';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IngestionRssLine, IngestionRssLineDummy } from './IngestionRssLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

const nbOfRowsToLoad = 50;

const interval$ = interval(FIVE_SECONDS);

class IngestionRssLines extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(200);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['ingestionRsss', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['ingestionRsss', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<IngestionRssLine />}
        DummyLineComponent={<IngestionRssLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

IngestionRssLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  refetchPaginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  killChainPhases: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const IngestionRssLinesQuery = graphql`
  query IngestionRssLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IngestionRssOrdering
    $orderMode: OrderingMode
  ) {
    ...IngestionRssLines_data
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
  IngestionRssLines,
  {
    data: graphql`
      fragment IngestionRssLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IngestionRssOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        ingestionRsss(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_ingestionRsss") {
          edges {
            node {
              ...IngestionRssLine_node
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
      return props.data && props.data.ingestionRsss;
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
    query: IngestionRssLinesQuery,
  },
);
