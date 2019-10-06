import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { TagLine, TagLineDummy } from './TagLine';

const nbOfRowsToLoad = 25;

class TagsLines extends Component {
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
        dataList={pathOr([], ['tags', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['tags', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<TagLine />}
        DummyLineComponent={<TagLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

TagsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  tags: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const tagsLinesQuery = graphql`
  query TagsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: TagsOrdering
    $orderMode: OrderingMode
  ) {
    ...TagsLines_data
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
  TagsLines,
  {
    data: graphql`
      fragment TagsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "TagsOrdering", defaultValue: "value" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        tags(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_tags") {
          edges {
            node {
              ...TagLine_node
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
      return props.data && props.data.tags;
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
    query: tagsLinesQuery,
  },
);
