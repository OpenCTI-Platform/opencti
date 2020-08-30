import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  StixDomainObjectIndicatorLine,
  StixDomainObjectIndicatorLineDummy,
} from './StixDomainObjectIndicatorLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixDomainObjectIndicatorsLines extends Component {
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
          ['stixCoreRelationships', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixCoreRelationships', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<StixDomainObjectIndicatorLine />}
        DummyLineComponent={<StixDomainObjectIndicatorLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

StixDomainObjectIndicatorsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const stixDomainObjectIndicatorsLinesQuery = graphql`
  query StixDomainObjectIndicatorsLinesQuery(
    $search: String
    $inferred: Boolean
    $fromId: String
    $toTypes: [String]
    $relationship_type: String
    $startTimeStart: DateTime
    $startTimeStop: DateTime
    $stopTimeStart: DateTime
    $stopTimeStop: DateTime
    $confidences: [Int]
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreRelationshipsFiltering]
  ) {
    ...StixDomainObjectIndicatorsLines_data
    @arguments(
      search: $search
      inferred: $inferred
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
      startTimeStart: $startTimeStart
      startTimeStop: $startTimeStop
      stopTimeStart: $stopTimeStart
      stopTimeStop: $stopTimeStop
      confidences: $confidences
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export default createPaginationContainer(
  StixDomainObjectIndicatorsLines,
  {
    data: graphql`
      fragment StixDomainObjectIndicatorsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        inferred: { type: "Boolean" }
        fromId: { type: "String" }
        toTypes: { type: "[String]" }
        relationship_type: { type: "String" }
        startTimeStart: { type: "DateTime" }
        startTimeStop: { type: "DateTime" }
        stopTimeStart: { type: "DateTime" }
        stopTimeStop: { type: "DateTime" }
        confidences: { type: "[Int]" }
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
          search: $search
          inferred: $inferred
          fromId: $fromId
          toTypes: $toTypes
          relationship_type: $relationship_type
          startTimeStart: $startTimeStart
          startTimeStop: $startTimeStop
          stopTimeStart: $stopTimeStart
          stopTimeStop: $stopTimeStop
          confidences: $confidences
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              ...StixDomainObjectIndicatorLine_node
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
        search: fragmentVariables.search,
        inferred: fragmentVariables.inferred,
        fromId: fragmentVariables.fromId,
        toTypes: fragmentVariables.toTypes,
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
    query: stixDomainObjectIndicatorsLinesQuery,
  },
);
