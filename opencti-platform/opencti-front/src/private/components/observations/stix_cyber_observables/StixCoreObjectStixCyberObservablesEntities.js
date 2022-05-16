import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  StixCoreObjectStixCyberObservableEntity,
  StixCoreObjectStixCyberObservableEntityDummy,
} from './StixCoreObjectStixCyberObservableEntity';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixCoreObjectStixCyberObservablesEntities extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCyberObservables',
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
      onLabelClick,
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
          ['stixCyberObservables', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixCyberObservables', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<StixCoreObjectStixCyberObservableEntity />}
        DummyLineComponent={<StixCoreObjectStixCyberObservableEntityDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={stixCoreObjectLink}
        isTo={isRelationReversed}
        onLabelClick={onLabelClick.bind(this)}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

StixCoreObjectStixCyberObservablesEntities.propTypes = {
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

export const stixCoreObjectStixCyberObservablesEntitiesQuery = graphql`
  query StixCoreObjectStixCyberObservablesEntitiesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: [StixCyberObservablesFiltering]
  ) {
    ...StixCoreObjectStixCyberObservablesEntities_data
      @arguments(
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
  StixCoreObjectStixCyberObservablesEntities,
  {
    data: graphql`
      fragment StixCoreObjectStixCyberObservablesEntities_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCyberObservablesOrdering"
          defaultValue: created_at
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixCyberObservablesFiltering]" }
      ) {
        stixCyberObservables(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixCyberObservables") {
          edges {
            node {
              ...StixCoreObjectStixCyberObservableEntity_node
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
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: stixCoreObjectStixCyberObservablesEntitiesQuery,
  },
);
