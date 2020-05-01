import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  EntityStixRelationLine,
  EntityStixRelationLineDummy,
} from './EntityStixRelationLine';

const nbOfRowsToLoad = 25;

class EntityStixRelationsLines extends Component {
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
        dataList={pathOr([], ['stixRelations', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixRelations', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<EntityStixRelationLine />}
        DummyLineComponent={<EntityStixRelationLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

EntityStixRelationsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixRelations: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
};

export const entityStixRelationsLinesQuery = graphql`
  query EntityStixRelationsLinesPaginationQuery(
    $fromId: String
    $fromRole: String
    $toTypes: [String]
    $inferred: Boolean
    $relationType: String
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixRelationsOrdering
    $orderMode: OrderingMode
    $forceNatural: Boolean
  ) {
    ...EntityStixRelationsLines_data
      @arguments(
        fromId: $fromId
        fromRole: $fromRole
        toTypes: $toTypes
        inferred: $inferred
        relationType: $relationType
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
  EntityStixRelationsLines,
  {
    data: graphql`
      fragment EntityStixRelationsLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          fromRole: { type: "String" }
          toTypes: { type: "[String]" }
          inferred: { type: "Boolean" }
          relationType: { type: "String" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixRelationsOrdering", defaultValue: "first_seen" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          forceNatural: { type: "Boolean", defaultValue: false }
        ) {
        stixRelations(
          fromId: $fromId
          fromRole: $fromRole
          toTypes: $toTypes
          inferred: $inferred
          relationType: $relationType
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          forceNatural: $forceNatural
        ) @connection(key: "Pagination_stixRelations") {
          edges {
            node {
              ...EntityStixRelationLine_node
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
      return props.data && props.data.stixRelations;
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
        fromRole: fragmentVariables.fromRole,
        toTypes: fragmentVariables.toTypes,
        inferred: fragmentVariables.inferred,
        relationType: fragmentVariables.relationType,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        forceNatural: fragmentVariables.forceNatural,
      };
    },
    query: entityStixRelationsLinesQuery,
  },
);
