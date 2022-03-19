import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { LabelLine, LabelLineDummy } from './LabelLine';

const nbOfRowsToLoad = 50;

class LabelsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['labels', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['labels', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<LabelLine />}
        DummyLineComponent={<LabelLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

LabelsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  labels: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const labelsLinesQuery = graphql`
  query LabelsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: LabelsOrdering
    $orderMode: OrderingMode
  ) {
    ...LabelsLines_data
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
  LabelsLines,
  {
    data: graphql`
      fragment LabelsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "LabelsOrdering", defaultValue: value }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        labels(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_labels") {
          edges {
            node {
              ...LabelLine_node
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
      return props.data && props.data.labels;
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
    query: labelsLinesQuery,
  },
);
