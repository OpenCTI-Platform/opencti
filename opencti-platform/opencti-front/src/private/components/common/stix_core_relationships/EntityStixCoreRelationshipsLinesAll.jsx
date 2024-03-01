import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EntityStixCoreRelationshipLineAll, EntityStixCoreRelationshipLineAllDummy } from './EntityStixCoreRelationshipLineAll';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class EntityStixCoreRelationshipsLinesAll extends Component {
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
      entityId,
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
        LineComponent={<EntityStixCoreRelationshipLineAll />}
        DummyLineComponent={<EntityStixCoreRelationshipLineAllDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
        entityId={entityId}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity}
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
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $fromTypes: [String]
  ) {
    ...EntityStixCoreRelationshipsLinesAll_data
      @arguments(
        fromOrToId: $fromOrToId
        elementWithTargetTypes: $elementWithTargetTypes
        relationship_type: $relationship_type
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        fromTypes: $fromTypes
      )
  }
`;

export default createPaginationContainer(
  EntityStixCoreRelationshipsLinesAll,
  {
    data: graphql`
      fragment EntityStixCoreRelationshipsLinesAll_data on Query
      @argumentDefinitions(
        fromOrToId: { type: "[String]" }
        elementWithTargetTypes: { type: "[String]" }
        fromTypes: { type: "[String]" }
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
          fromOrToId: $fromOrToId
          elementWithTargetTypes: $elementWithTargetTypes
          relationship_type: $relationship_type
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          fromTypes: $fromTypes
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              id
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
        fromOrToId: fragmentVariables.fromOrToId,
        elementWithTargetTypes: fragmentVariables.elementWithTargetTypes,
        relationship_type: fragmentVariables.relationship_type,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: entityStixCoreRelationshipsLinesAllQuery,
  },
);
