import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AttributeLine, AttributeLineDummy } from './AttributeLine';

const nbOfRowsToLoad = 25;

class AttributesLines extends Component {
  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['attributes', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['attributes', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<AttributeLine />}
        DummyLineComponent={<AttributeLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

AttributesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  attributes: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const attributesQuery = graphql`
  query AttributesLinesAttributesQuery($type: String!) {
    attributes(type: $type) {
      edges {
        node {
          id
          type
          value
        }
      }
    }
  }
`;

export const attributesLinesQuery = graphql`
  query AttributesLinesPaginationQuery(
    $type: String!
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: AttributesOrdering
    $orderMode: OrderingMode
  ) {
    ...AttributesLines_data
      @arguments(
        type: $type
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  AttributesLines,
  {
    data: graphql`
      fragment AttributesLines_data on Query
        @argumentDefinitions(
          type: { type: "String!" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "AttributesOrdering", defaultValue: "value" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        attributes(
          type: $type
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_attributes") {
          edges {
            node {
              ...AttributeLine_node
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
      return props.data && props.data.attributes;
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
    query: attributesLinesQuery,
  },
);
