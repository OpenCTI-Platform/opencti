import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { KillChainPhaseLine, KillChainPhaseLineDummy } from './KillChainPhaseLine';

const nbOfRowsToLoad = 50;

export const killChainPhasesLinesSearchQuery = graphql`
  query KillChainPhasesLinesSearchQuery($search: String) {
    killChainPhases(search: $search) {
      edges {
        node {
          id
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
    }
  }
`;

class KillChainPhasesLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['killChainPhases', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['killChainPhases', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<KillChainPhaseLine />}
        DummyLineComponent={<KillChainPhaseLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

KillChainPhasesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  killChainPhases: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const killChainPhasesLinesQuery = graphql`
  query KillChainPhasesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: KillChainPhasesOrdering
    $orderMode: OrderingMode
  ) {
    ...KillChainPhasesLines_data
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
  KillChainPhasesLines,
  {
    data: graphql`
      fragment KillChainPhasesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "KillChainPhasesOrdering", defaultValue: phase_name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        killChainPhases(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_killChainPhases") {
          edges {
            node {
              ...KillChainPhaseLine_node
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
      return props.data && props.data.killChainPhases;
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
    query: killChainPhasesLinesQuery,
  },
);
