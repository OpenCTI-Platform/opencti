import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  EntityIndicatorLine,
  EntityIndicatorLineDummy,
} from './EntityIndicatorLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 25;

class EntityIndicatorsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixRelations',
      this.props.setNumberOfElements.bind(this),
    );
  }

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
        LineComponent={<EntityIndicatorLine />}
        DummyLineComponent={<EntityIndicatorLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

EntityIndicatorsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixRelations: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const entityIndicatorsLinesQuery = graphql`
  query EntityIndicatorsLinesPaginationQuery(
    $search: String
    $inferred: Boolean
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $firstSeenStart: DateTime
    $firstSeenStop: DateTime
    $lastSeenStart: DateTime
    $lastSeenStop: DateTime
    $weights: [Int]
    $count: Int!
    $cursor: ID
    $orderBy: StixRelationsOrdering
    $orderMode: OrderingMode
    $filters: [StixRelationsFiltering]
  ) {
    ...EntityIndicatorsLines_data
      @arguments(
        search: $search
        inferred: $inferred
        fromId: $fromId
        toTypes: $toTypes
        relationType: $relationType
        firstSeenStart: $firstSeenStart
        firstSeenStop: $firstSeenStop
        lastSeenStart: $lastSeenStart
        lastSeenStop: $lastSeenStop
        weights: $weights
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export default createPaginationContainer(
  EntityIndicatorsLines,
  {
    data: graphql`
      fragment EntityIndicatorsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          inferred: { type: "Boolean" }
          fromId: { type: "String" }
          toTypes: { type: "[String]" }
          relationType: { type: "String" }
          firstSeenStart: { type: "DateTime" }
          firstSeenStop: { type: "DateTime" }
          lastSeenStart: { type: "DateTime" }
          lastSeenStop: { type: "DateTime" }
          weights: { type: "[Int]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixRelationsOrdering", defaultValue: "first_seen" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixRelationsFiltering]" }
        ) {
        stixRelations(
          search: $search
          inferred: $inferred
          fromId: $fromId
          toTypes: $toTypes
          relationType: $relationType
          firstSeenStart: $firstSeenStart
          firstSeenStop: $firstSeenStop
          lastSeenStart: $lastSeenStart
          lastSeenStop: $lastSeenStop
          weights: $weights
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixRelations") {
          edges {
            node {
              ...EntityIndicatorLine_node
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
        search: fragmentVariables.search,
        inferred: fragmentVariables.inferred,
        fromId: fragmentVariables.fromId,
        toTypes: fragmentVariables.toTypes,
        relationType: fragmentVariables.relationType,
        firstSeenStart: fragmentVariables.firstSeenStart,
        firstSeenStop: fragmentVariables.firstSeenStop,
        lastSeenStart: fragmentVariables.lastSeenStart,
        lastSeenStop: fragmentVariables.lastSeenStop,
        weights: fragmentVariables.weights,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: entityIndicatorsLinesQuery,
  },
);
