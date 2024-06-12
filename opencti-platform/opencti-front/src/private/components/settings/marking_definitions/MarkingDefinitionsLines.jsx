import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { MarkingDefinitionLine, MarkingDefinitionLineDummy } from './MarkingDefinitionLine';

const nbOfRowsToLoad = 50;

export const markingDefinitionsLinesSearchQuery = graphql`
  query MarkingDefinitionsLinesSearchQuery($search: String) {
    markingDefinitions(search: $search) {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_color
          x_opencti_order
        }
      }
    }
  }
`;

class MarkingDefinitionsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['markingDefinitions', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['markingDefinitions', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<MarkingDefinitionLine />}
        DummyLineComponent={<MarkingDefinitionLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

MarkingDefinitionsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  markingDefinitions: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const markingDefinitionsLinesQuery = graphql`
  query MarkingDefinitionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: MarkingDefinitionsOrdering
    $orderMode: OrderingMode
  ) {
    ...MarkingDefinitionsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  MarkingDefinitionsLines,
  {
    data: graphql`
      fragment MarkingDefinitionsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "MarkingDefinitionsOrdering"
          defaultValue: definition
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        markingDefinitions(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_markingDefinitions") {
          edges {
            node {
              ...MarkingDefinitionLine_node
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
      return props.data && props.data.markingDefinitions;
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
      };
    },
    query: markingDefinitionsLinesQuery,
  },
);
