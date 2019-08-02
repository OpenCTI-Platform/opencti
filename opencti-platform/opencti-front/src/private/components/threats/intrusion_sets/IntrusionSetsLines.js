import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IntrusionSetLine, IntrusionSetLineDummy } from './IntrusionSetLine';

const nbOfRowsToLoad = 25;

class IntrusionSetsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['intrusionSets', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['intrusionSets', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<IntrusionSetLine />}
        DummyLineComponent={<IntrusionSetLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

IntrusionSetsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  intrusionSets: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const intrusionSetsLinesQuery = graphql`
  query IntrusionSetsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
  ) {
    ...IntrusionSetsLines_data
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
  IntrusionSetsLines,
  {
    data: graphql`
      fragment IntrusionSetsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "IntrusionSetsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        intrusionSets(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_intrusionSets") {
          edges {
            node {
              id
              name
              description
              ...IntrusionSetLine_node
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.intrusionSets;
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
    query: intrusionSetsLinesQuery,
  },
);
