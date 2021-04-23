import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  EntityStixCoreRelationshipLineAll,
  EntityStixCoreRelationshipLineAllDummy,
} from './EntityStixCoreRelationshipLineAll';

const nbOfRowsToLoad = 50;

class EntityStixCoreRelationshipsLinesAll extends Component {
  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      entityLink,
      entityId,
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
          ['stixCoreRelationships', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixCoreRelationships', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<EntityStixCoreRelationshipLineAll />}
        DummyLineComponent={<EntityStixCoreRelationshipLineAllDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
        entityId={entityId}
      />
    );
  }
}

EntityStixCoreRelationshipsLinesAll.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  entityId: PropTypes.string,
};

export const entityStixCoreRelationshipsLinesAllQuery = graphql`
  query EntityStixCoreRelationshipsLinesAllPaginationQuery(
    $elementId: String
    $elementWithTargetTypes: [String]
    $relationship_type: String
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixCoreRelationshipsLinesAll_data
      @arguments(
        elementId: $elementId
        elementWithTargetTypes: $elementWithTargetTypes
        relationship_type: $relationship_type
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  EntityStixCoreRelationshipsLinesAll,
  {
    data: graphql`
      fragment EntityStixCoreRelationshipsLinesAll_data on Query
      @argumentDefinitions(
        elementId: { type: "String" }
        elementWithTargetTypes: { type: "[String]" }
        relationship_type: { type: "String" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCoreRelationshipsOrdering"
          defaultValue: start_time
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        stixCoreRelationships(
          elementId: $elementId
          elementWithTargetTypes: $elementWithTargetTypes
          relationship_type: $relationship_type
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              ...EntityStixCoreRelationshipLineAll_node
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
      return props.data && props.data.stixCoreRelationships;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        elementId: fragmentVariables.elementId,
        elementWithTargetTypes: fragmentVariables.elementWithTargetTypes,
        relationship_type: fragmentVariables.relationship_type,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: entityStixCoreRelationshipsLinesAllQuery,
  },
);
