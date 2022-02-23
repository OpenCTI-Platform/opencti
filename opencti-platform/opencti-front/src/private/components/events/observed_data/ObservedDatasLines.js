import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ObservedDataLine, ObservedDataLineDummy } from './ObservedDataLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class ObservedDatasLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'observedDatas',
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
        dataList={pathOr([], ['observedDatas', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['observedDatas', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<ObservedDataLine />}
        DummyLineComponent={<ObservedDataLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
      />
    );
  }
}

ObservedDatasLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  observedDatas: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const observedDatasLinesQuery = graphql`
  query ObservedDatasLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ObservedDatasOrdering
    $orderMode: OrderingMode
    $filters: [ObservedDatasFiltering]
  ) {
    ...ObservedDatasLines_data
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
  ObservedDatasLines,
  {
    data: graphql`
      fragment ObservedDatasLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "ObservedDatasOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "[ObservedDatasFiltering]" }
      ) {
        observedDatas(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_observedDatas") {
          edges {
            node {
              id
              created
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ...ObservedDataLine_node
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
      return props.data && props.data.observedDatas;
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
    query: observedDatasLinesQuery,
  },
);
