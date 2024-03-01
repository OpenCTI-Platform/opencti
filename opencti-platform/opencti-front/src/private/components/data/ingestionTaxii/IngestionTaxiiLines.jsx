import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import { interval } from 'rxjs';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IngestionTaxiiLine, IngestionTaxiiLineDummy } from './IngestionTaxiiLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

const nbOfRowsToLoad = 50;

const interval$ = interval(FIVE_SECONDS);

class IngestionTaxiiLines extends Component {
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
        dataList={pathOr([], ['ingestionTaxiis', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['ingestionTaxiis', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<IngestionTaxiiLine />}
        DummyLineComponent={<IngestionTaxiiLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

IngestionTaxiiLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  refetchPaginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  killChainPhases: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const IngestionTaxiiLinesQuery = graphql`
  query IngestionTaxiiLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IngestionTaxiiOrdering
    $orderMode: OrderingMode
  ) {
    ...IngestionTaxiiLines_data
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
  IngestionTaxiiLines,
  {
    data: graphql`
      fragment IngestionTaxiiLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IngestionTaxiiOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        ingestionTaxiis(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_ingestionTaxiis") {
          edges {
            node {
              ...IngestionTaxiiLine_node
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
      return props.data && props.data.ingestionTaxiis;
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
    query: IngestionTaxiiLinesQuery,
  },
);
