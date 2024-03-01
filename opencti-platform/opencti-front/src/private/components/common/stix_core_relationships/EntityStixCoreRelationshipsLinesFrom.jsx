import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EntityStixCoreRelationshipLineFrom, EntityStixCoreRelationshipLineFromDummy } from './EntityStixCoreRelationshipLineFrom';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class EntityStixCoreRelationshipsLinesFrom extends Component {
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
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
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
        LineComponent={<EntityStixCoreRelationshipLineFrom />}
        DummyLineComponent={<EntityStixCoreRelationshipLineFromDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity}
      />
    );
  }
}

EntityStixCoreRelationshipsLinesFrom.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
};

export const entityStixCoreRelationshipsLinesFromQuery = graphql`
  query EntityStixCoreRelationshipsLinesFromPaginationQuery(
    $fromId: [String]
    $fromRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...EntityStixCoreRelationshipsLinesFrom_data
      @arguments(
        fromId: $fromId
        fromRole: $fromRole
        toTypes: $toTypes
        relationship_type: $relationship_type
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
  EntityStixCoreRelationshipsLinesFrom,
  {
    data: graphql`
      fragment EntityStixCoreRelationshipsLinesFrom_data on Query
      @argumentDefinitions(
        fromId: { type: "[String]" }
        fromRole: { type: "String" }
        toTypes: { type: "[String]" }
        relationship_type: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCoreRelationshipsOrdering"
          defaultValue: start_time
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
      ) {
        stixCoreRelationships(
          fromId: $fromId
          fromRole: $fromRole
          toTypes: $toTypes
          relationship_type: $relationship_type
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              id
              ...EntityStixCoreRelationshipLineFrom_node
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
        fromRole: fragmentVariables.fromRole,
        toTypes: fragmentVariables.toTypes,
        relationship_type: fragmentVariables.relationship_type,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: entityStixCoreRelationshipsLinesFromQuery,
  },
);
