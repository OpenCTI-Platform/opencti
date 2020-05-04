import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  EntityStixSightingLine,
  EntityStixSightingLineDummy,
} from './EntityStixSightingLine';

const nbOfRowsToLoad = 50;

class EntityStixSightingsLines extends Component {
  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      entityLink,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['stixSightings', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixSightings', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<EntityStixSightingLine />}
        DummyLineComponent={<EntityStixSightingLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

EntityStixSightingsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixSightings: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
};

export const entityStixSightingsLinesQuery = graphql`
  query EntityStixSightingsLinesPaginationQuery(
    $fromId: String
    $toTypes: [String]
    $inferred: Boolean
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixSightingsOrdering
    $orderMode: OrderingMode
    $forceNatural: Boolean
  ) {
    ...EntityStixSightingsLines_data
      @arguments(
        fromId: $fromId
        toTypes: $toTypes
        inferred: $inferred
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        forceNatural: $forceNatural
      )
  }
`;

export default createPaginationContainer(
  EntityStixSightingsLines,
  {
    data: graphql`
      fragment EntityStixSightingsLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          toTypes: { type: "[String]" }
          inferred: { type: "Boolean" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixSightingsOrdering", defaultValue: "first_seen" }
          orderMode: { type: "OrderingMode", defaultValue: "desc" }
          forceNatural: { type: "Boolean", defaultValue: false }
        ) {
        stixSightings(
          fromId: $fromId
          toTypes: $toTypes
          inferred: $inferred
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          forceNatural: $forceNatural
        ) @connection(key: "Pagination_stixSightings") {
          edges {
            node {
              ...EntityStixSightingLine_node
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
      return props.data && props.data.stixSightings;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        fromId: fragmentVariables.fromId,
        toTypes: fragmentVariables.toTypes,
        inferred: fragmentVariables.inferred,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        forceNatural: fragmentVariables.forceNatural,
      };
    },
    query: entityStixSightingsLinesQuery,
  },
);
