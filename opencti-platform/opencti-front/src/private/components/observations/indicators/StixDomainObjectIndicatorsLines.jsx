import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StixDomainObjectIndicatorLine, StixDomainObjectIndicatorLineDummy } from './StixDomainObjectIndicatorLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class StixDomainObjectIndicatorsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'indicators',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
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
        dataList={this.props.data?.indicators?.edges ?? []}
        globalCount={
          this.props.data?.indicators?.pageInfo?.globalCount ?? nbOfRowsToLoad
        }
        LineComponent={StixDomainObjectIndicatorLine}
        DummyLineComponent={StixDomainObjectIndicatorLineDummy}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityId={entityId}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity.bind(this)}
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
  entityId: PropTypes.string,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const stixDomainObjectIndicatorsLinesQuery = graphql`
  query StixDomainObjectIndicatorsLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixDomainObjectIndicatorsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        filters: $filters
        orderBy: $orderBy
        orderMode: $orderMode
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
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        filters: { type: "FilterGroup" }
        orderBy: { type: "IndicatorsOrdering", defaultValue: valid_from }
        orderMode: { type: "OrderingMode", defaultValue: desc }
      ) {
        indicators(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_indicators") {
          edges {
            node {
              id
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
      return props.data && props.data.indicators;
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
    query: stixDomainObjectIndicatorsLinesQuery,
  },
);
