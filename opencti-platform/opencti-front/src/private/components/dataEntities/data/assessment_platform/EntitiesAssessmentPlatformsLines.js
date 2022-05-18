/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import { EntityAssessmentPlatformLine, EntityAssessmentPlatformLineDummy } from './EntityAssessmentPlatformLine';
import { setNumberOfElements } from '../../../../../utils/Number';

const nbOfRowsToLoad = 50;

class EntitiesAssessmentPlatformsLines extends Component {
  constructor(props) {
    super(props);
    this.state = { offset: 0 };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'assessmentPlatforms',
      this.props.setNumberOfElements.bind(this),
    );
  }

  handleOffsetChange() {
    const incrementedOffset = this.state.offset += nbOfRowsToLoad;
    this.setState({ offset: incrementedOffset })
    this.props.relay.refetchConnection(nbOfRowsToLoad, null, {
      offset: this.state.offset,
    })
  }

  render() {
    const {
      relay,
      selectAll,
      dataColumns,
      onLabelClick,
      initialLoading,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        handleOffsetChange={this.handleOffsetChange.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['assessmentPlatforms', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['assessmentPlatforms', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        offset={this.state.offset}
        LineComponent={<EntityAssessmentPlatformLine />}
        DummyLineComponent={<EntityAssessmentPlatformLineDummy />}
        selectAll={selectAll}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={selectedElements}
        onLabelClick={onLabelClick.bind(this)}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

EntitiesAssessmentPlatformsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  threatActors: PropTypes.object,
  computingDeviceAssetList: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const entitiesAssessmentPlatformsLinesQuery = graphql`
  query EntitiesAssessmentPlatformsLinesPaginationQuery(
    $search: String
    $first: Int!
    $offset: Int!
    $cursor: ID
    $orderedBy: AssessmentPlatformOrdering
    $orderMode: OrderingMode
    $filters: [AssessmentPlatformFiltering]
    $filterMode: FilterMode
  ) {
    ...EntitiesAssessmentPlatformsLines_data
      @arguments(
        search: $search
        first: $first
        offset: $offset
        cursor: $cursor
        orderedBy: $orderedBy
        orderMode: $orderMode
        filters: $filters
        filterMode: $filterMode
      )
  }
`;

export default createPaginationContainer(
  EntitiesAssessmentPlatformsLines,
  {
    data: graphql`
      fragment EntitiesAssessmentPlatformsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        first: { type: "Int", defaultValue: 50 }
        offset: { type: "Int", defaultValue: 0 }
        cursor: { type: "ID" }
        orderedBy: { type: "AssessmentPlatformOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[AssessmentPlatformFiltering]" }
        filterMode: { type: "FilterMode" }
      ) {
        assessmentPlatforms(
          search: $search
          first: $first
          offset: $offset
          orderedBy: $orderedBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
        ) @connection(key: "Pagination_assessmentPlatforms") {
          edges {
            node {
              id
              name
              description
              ...EntityAssessmentPlatformLine_node
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
      return props.data && props.data.assessmentPlatforms;
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
        first: fragmentVariables.first,
        offset: fragmentVariables.offset,
        count,
        cursor,
        orderedBy: fragmentVariables.orderedBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
        filterMode: fragmentVariables.filterMode,
      };
    },
    query: entitiesAssessmentPlatformsLinesQuery,
  },
);
