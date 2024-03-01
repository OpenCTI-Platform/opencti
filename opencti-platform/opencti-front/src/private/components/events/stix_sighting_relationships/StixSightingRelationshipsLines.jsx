import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StixSightingRelationshipLine, StixSightingRelationshipLineDummy } from './StixSightingRelationshipLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixSightingRelationshipsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixSightingRelationships',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      onLabelClick,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
      data,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        paginationOptions={this.props.paginationOptions}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={data?.stixSightingRelationships?.edges ?? []}
        globalCount={
          data?.stixSightingRelationships?.pageInfo?.globalCount
          ?? nbOfRowsToLoad
        }
        LineComponent={<StixSightingRelationshipLine />}
        DummyLineComponent={<StixSightingRelationshipLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

StixSightingRelationshipsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixSightingRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const stixSightingRelationshipsLinesQuery = graphql`
  query StixSightingRelationshipsLinesPaginationQuery(
    $fromId: StixRef
    $toId: StixRef
    $toTypes: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixSightingRelationshipsLines_data
      @arguments(
        fromId: $fromId
        toId: $toId
        toTypes: $toTypes
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
  StixSightingRelationshipsLines,
  {
    data: graphql`
      fragment StixSightingRelationshipsLines_data on Query
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
        filters: { type: "FilterGroup" }
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
          filters: $filters
        ) @connection(key: "Pagination_stixSightingRelationships") {
          edges {
            node {
              id
              ...StixSightingRelationshipLine_node
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
        filters: fragmentVariables.filters,
      };
    },
    query: stixSightingRelationshipsLinesQuery,
  },
);
