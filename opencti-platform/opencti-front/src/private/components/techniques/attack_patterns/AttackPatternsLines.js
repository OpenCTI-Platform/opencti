import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AttackPatternLine, AttackPatternLineDummy } from './AttackPatternLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 25;

class AttackPatternsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'attackPatterns',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading, dataColumns, relay, onTagClick,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['attackPatterns', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['attackPatterns', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<AttackPatternLine />}
        DummyLineComponent={<AttackPatternLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onTagClick={onTagClick.bind(this)}
      />
    );
  }
}

AttackPatternsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onTagClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const attackPatternsLinesQuery = graphql`
  query AttackPatternsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: [AttackPatternsFiltering]
  ) {
    ...AttackPatternsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export default createPaginationContainer(
  AttackPatternsLines,

  {
    data: graphql`
      fragment AttackPatternsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "AttackPatternsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[AttackPatternsFiltering]" }
        ) {
        attackPatterns(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_attackPatterns") {
          edges {
            node {
              name
              killChainPhases {
                edges {
                  node {
                    id
                    kill_chain_name
                    phase_name
                  }
                }
              }
              ...AttackPatternLine_node
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
      return props.data && props.data.attackPatterns;
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
        filters: fragmentVariables.filters,
      };
    },
    query: attackPatternsLinesQuery,
  },
);
