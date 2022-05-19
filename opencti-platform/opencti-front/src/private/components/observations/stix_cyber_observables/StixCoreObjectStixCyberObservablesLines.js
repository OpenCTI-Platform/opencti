import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  StixCoreObjectStixCyberObservableLine,
  StixCoreObjectStixCyberObservableLineDummy,
} from './StixCoreObjectStixCyberObservableLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixCoreObjectStixCyberObservablesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCoreRelationships',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      stixCoreObjectLink,
      paginationOptions,
      isRelationReversed,
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
        LineComponent={<StixCoreObjectStixCyberObservableLine />}
        DummyLineComponent={<StixCoreObjectStixCyberObservableLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={stixCoreObjectLink}
        isTo={isRelationReversed}
      />
    );
  }
}

StixCoreObjectStixCyberObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  stixCoreObjectLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
};

export const stixCoreObjectStixCyberObservablesLinesQuery = graphql`
  query StixCoreObjectStixCyberObservablesLinesPaginationQuery(
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $relationship_type: [String]
    $startTimeStart: DateTime
    $startTimeStop: DateTime
    $stopTimeStart: DateTime
    $stopTimeStop: DateTime
    $confidences: [Int]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreRelationshipsFiltering]
  ) {
    ...StixCoreObjectStixCyberObservablesLines_data
      @arguments(
        fromId: $fromId
        toId: $toId
        fromTypes: $fromTypes
        toTypes: $toTypes
        relationship_type: $relationship_type
        startTimeStart: $startTimeStart
        startTimeStop: $startTimeStop
        stopTimeStart: $stopTimeStart
        stopTimeStop: $stopTimeStop
        confidences: $confidences
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
  StixCoreObjectStixCyberObservablesLines,
  {
    data: graphql`
      fragment StixCoreObjectStixCyberObservablesLines_data on Query
      @argumentDefinitions(
        fromId: { type: "[String]" }
        toId: { type: "[String]" }
        fromTypes: { type: "[String]" }
        toTypes: { type: "[String]" }
        relationship_type: { type: "[String]" }
        startTimeStart: { type: "DateTime" }
        startTimeStop: { type: "DateTime" }
        stopTimeStart: { type: "DateTime" }
        stopTimeStop: { type: "DateTime" }
        confidences: { type: "[Int]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCoreRelationshipsOrdering"
          defaultValue: start_time
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixCoreRelationshipsFiltering]" }
      ) {
        stixCoreRelationships(
          fromId: $fromId
          toId: $toId
          fromTypes: $fromTypes
          toTypes: $toTypes
          relationship_type: $relationship_type
          startTimeStart: $startTimeStart
          startTimeStop: $startTimeStop
          stopTimeStart: $stopTimeStart
          stopTimeStop: $stopTimeStop
          confidences: $confidences
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              ...StixCoreObjectStixCyberObservableLine_node
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
        fromId: fragmentVariables.fromId,
        toId: fragmentVariables.toId,
        fromTypes: fragmentVariables.fromTypes,
        toTypes: fragmentVariables.toTypes,
        search: fragmentVariables.search,
        relationship_type: fragmentVariables.relationship_type,
        startTimeStart: fragmentVariables.startTimeStart,
        startTimeStop: fragmentVariables.startTimeStop,
        stopTimeStart: fragmentVariables.stopTimeStart,
        stopTimeStop: fragmentVariables.stopTimeStop,
        confidences: fragmentVariables.confidences,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: stixCoreObjectStixCyberObservablesLinesQuery,
  },
);
