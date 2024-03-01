import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import { interval } from 'rxjs';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { SyncLine, SyncLineDummy } from './SyncLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

const nbOfRowsToLoad = 50;

const interval$ = interval(FIVE_SECONDS);

class SyncLines extends Component {
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
        dataList={pathOr([], ['synchronizers', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['synchronizers', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<SyncLine />}
        DummyLineComponent={<SyncLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

SyncLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  refetchPaginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  killChainPhases: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const SyncLinesQuery = graphql`
  query SyncLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: SynchronizersOrdering
    $orderMode: OrderingMode
  ) {
    ...SyncLines_data
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
  SyncLines,
  {
    data: graphql`
      fragment SyncLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "SynchronizersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        synchronizers(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_synchronizers") {
          edges {
            node {
              ...SyncLine_node
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
      return props.data && props.data.synchronizers;
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
    query: SyncLinesQuery,
  },
);
