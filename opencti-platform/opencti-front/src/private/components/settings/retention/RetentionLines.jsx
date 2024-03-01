import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RetentionLine, RetentionLineDummy } from './RetentionLine';

const nbOfRowsToLoad = 50;

class RetentionLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['retentionRules', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['retentionRules', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<RetentionLine />}
        DummyLineComponent={<RetentionLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

RetentionLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const RetentionLinesQuery = graphql`
  query RetentionLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...RetentionLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export default createPaginationContainer(
  RetentionLines,
  {
    data: graphql`
      fragment RetentionLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        retentionRules(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_retentionRules") {
          edges {
            node {
              ...RetentionLine_node
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
      return props.data && props.data.retentionRules;
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
      };
    },
    query: RetentionLinesQuery,
  },
);
