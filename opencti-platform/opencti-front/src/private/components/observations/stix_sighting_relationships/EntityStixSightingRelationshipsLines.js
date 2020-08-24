import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  EntityStixSightingRelationshipLine,
  EntityStixSightingRelationshipLineDummy,
} from './EntityStixSightingRelationshipLine';

const nbOfRowsToLoad = 50;

class EntityStixSightingRelationshipsLines extends Component {
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
        dataList={pathOr(
          [],
          ['stixSightingRelationships', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixSightingRelationships', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<EntityStixSightingRelationshipLine />}
        DummyLineComponent={<EntityStixSightingRelationshipLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

EntityStixSightingRelationshipsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixSightingRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
};

export const entityStixSightingRelationshipsLinesQuery = graphql`
  query EntityStixSightingRelationshipsLinesPaginationQuery(
    $fromId: String
    $toTypes: [String]
    $inferred: Boolean
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixSightingRelationshipsLines_data
      @arguments(
        fromId: $fromId
        toTypes: $toTypes
        inferred: $inferred
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  EntityStixSightingRelationshipsLines,
  {
    data: graphql`
      fragment EntityStixSightingRelationshipsLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          toTypes: { type: "[String]" }
          inferred: { type: "Boolean" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: {
            type: "StixSightingRelationshipsOrdering"
            defaultValue: first_seen
          }
          orderMode: { type: "OrderingMode", defaultValue: desc }
        ) {
        stixSightingRelationships(
          fromId: $fromId
          toTypes: $toTypes
          inferred: $inferred
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixSightingRelationships") {
          edges {
            node {
              ...EntityStixSightingRelationshipLine_node
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
      return props.data && props.data.stixSightingRelationships;
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
      };
    },
    query: entityStixSightingRelationshipsLinesQuery,
  },
);
