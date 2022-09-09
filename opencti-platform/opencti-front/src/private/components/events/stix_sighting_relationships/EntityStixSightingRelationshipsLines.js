import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
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
      isTo,
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
        isTo={isTo}
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
  isTo: PropTypes.bool,
};

export const entityStixSightingRelationshipsLinesQuery = graphql`
  query EntityStixSightingRelationshipsLinesPaginationQuery(
    $fromId: StixRef
    $toId: StixRef
    $toTypes: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixSightingRelationshipsLines_data
      @arguments(
        fromId: $fromId
        toId: $toId
        toTypes: $toTypes
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
        fromId: { type: "StixRef" }
        toId: { type: "StixRef" }
        toTypes: { type: "[String]" }
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
          toId: $toId
          toTypes: $toTypes
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
        toId: fragmentVariables.toId,
        toTypes: fragmentVariables.toTypes,
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
