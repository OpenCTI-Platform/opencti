import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { ReportLine, ReportLineDummy } from './ReportLine';

const nbOfRowsToLoad = 25;

class ReportsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['reports', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['reports', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<ReportLine />}
        DummyLineComponent={<ReportLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

ReportsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  reports: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const reportsLinesQuery = graphql`
  query ReportsLinesPaginationQuery(
    $objectId: String
    $authorId: String
    $reportClass: String
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
  ) {
    ...ReportsLines_data
      @arguments(
        objectId: $objectId
        authorId: $authorId
        reportClass: $reportClass
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  ReportsLines,
  {
    data: graphql`
      fragment ReportsLines_data on Query
        @argumentDefinitions(
          objectId: { type: "String" }
          authorId: { type: "String" }
          reportClass: { type: "String" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "ReportsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        reports(
          objectId: $objectId
          authorId: $authorId
          reportClass: $reportClass
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_reports") {
          edges {
            node {
              id
              name
              published
              createdByRef {
                node {
                  name
                }
              }
              markingDefinitions {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ...ReportLine_node
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
      return props.data && props.data.reports;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        objectId: fragmentVariables.objectId,
        authorId: fragmentVariables.authorId,
        reportClass: fragmentVariables.reportClass,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: reportsLinesQuery,
  },
);
