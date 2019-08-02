import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ThreatActorLine, ThreatActorLineDummy } from './ThreatActorLine';

const nbOfRowsToLoad = 25;

class ThreatActorsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['threatActors', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['threatActors', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<ThreatActorLine />}
        DummyLineComponent={<ThreatActorLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

ThreatActorsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  threatActors: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const threatActorsLinesQuery = graphql`
  query ThreatActorsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
  ) {
    ...ThreatActorsLines_data
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
  ThreatActorsLines,
  {
    data: graphql`
      fragment ThreatActorsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "ThreatActorsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        threatActors(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_threatActors") {
          edges {
            node {
              id
              name
              description
              ...ThreatActorLine_node
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.threatActors;
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
    query: threatActorsLinesQuery,
  },
);
