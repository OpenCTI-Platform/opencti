import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StixCoreObjectOrStixCoreRelationshipContainerLine, StixCoreObjectOrStixCoreRelationshipContainerLineDummy } from './StixCoreObjectOrStixCoreRelationshipContainerLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixCoreObjectOrStixCoreRelationshipContainersLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'containers',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const { initialLoading, dataColumns, relay, onLabelClick } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['containers', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['containers', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<StixCoreObjectOrStixCoreRelationshipContainerLine />}
        DummyLineComponent={
          <StixCoreObjectOrStixCoreRelationshipContainerLineDummy />
        }
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
        redirectionMode={this.props.redirectionMode}
      />
    );
  }
}

StixCoreObjectOrStixCoreRelationshipContainersLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  containers: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  redirectionMode: PropTypes.string,
};

export const stixCoreObjectOrStixCoreRelationshipContainersLinesQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipContainersLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCoreObjectOrStixCoreRelationshipContainersLines_data
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
  StixCoreObjectOrStixCoreRelationshipContainersLines,
  {
    data: graphql`
      fragment StixCoreObjectOrStixCoreRelationshipContainersLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "ContainersOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
      ) {
        containers(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_containers") {
          edges {
            node {
              id
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
              ...StixCoreObjectOrStixCoreRelationshipContainerLine_node
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
      return props.data && props.data.containers;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        search: fragmentVariables.search,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: stixCoreObjectOrStixCoreRelationshipContainersLinesQuery,
  },
);
