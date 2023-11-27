import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StixCyberObservableLine, StixCyberObservableLineDummy } from './StixCyberObservableLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixCyberObservablesLines extends Component {
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
        LineComponent={<StixCyberObservableLine />}
        DummyLineComponent={<StixCyberObservableLineDummy />}
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

StixCyberObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCyberObservables: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const stixCyberObservablesLinesSubTypesQuery = graphql`
  query StixCyberObservablesLinesSubTypesQuery($type: String!, $search: String) {
    subTypes(type: $type, search: $search) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

export const stixCyberObservablesLinesAttributesQuery = graphql`
  query StixCyberObservablesLinesAttributesQuery($elementType: [String]!) {
    schemaAttributeNames(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

export const stixCyberObservablesLinesQuery = graphql`
  query StixCyberObservablesLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCyberObservablesLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export const stixCyberObservablesLinesSearchQuery = graphql`
  query StixCyberObservablesLinesSearchQuery(
    $types: [String]
    $search: String
    $filters: FilterGroup
    $count: Int
  ) {
    stixCyberObservables(
      types: $types
      search: $search
      filters: $filters
      first: $count
    ) {
      edges {
        node {
          id
          standard_id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    }
  }
`;

export default createPaginationContainer(
  StixCyberObservablesLines,
  {
    data: graphql`
      fragment StixCyberObservablesLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCyberObservablesOrdering"
          defaultValue: created_at
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
      ) {
        stixCyberObservables(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixCyberObservables") {
          edges {
            node {
              id
              standard_id
              entity_type
              observable_value
              created_at
              objectMarking {
                id
                definition
                x_opencti_order
                x_opencti_color
              }
              ...StixCyberObservableLine_node
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
      return props.data && props.data.stixCyberObservables;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        types: fragmentVariables.types,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: stixCyberObservablesLinesQuery,
  },
);
