import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr, propOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import {
  ReportObservableLine,
  ReportObservableLineDummy,
} from './ReportObservableLine';
import { setNumberOfElements } from '../../../utils/Number';

const nbOfRowsToLoad = 25;

class ReportObservablesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'observableRefs',
      this.props.setNumberOfElements.bind(this),
      'report',
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      report,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['observableRefs', 'edges'], report)}
        paginationOptions={paginationOptions}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['observableRefs', 'pageInfo', 'globalCount'],
          report,
        )}
        LineComponent={
          <ReportObservableLine reportId={propOr(null, 'id', report)} />
        }
        DummyLineComponent={<ReportObservableLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

ReportObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  report: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const reportObservablesLinesQuery = graphql`
  query ReportObservablesLinesQuery(
    $id: String!
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
    $filters: [StixObservablesFiltering]
  ) {
    report(id: $id) {
      ...ReportObservablesLines_report
        @arguments(
          types: $types
          search: $search
          count: $count
          cursor: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        )
    }
  }
`;

export default createPaginationContainer(
  ReportObservablesLines,
  {
    report: graphql`
      fragment ReportObservablesLines_report on Report
        @argumentDefinitions(
          types: { type: "[String]" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixObservablesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixObservablesFiltering]" }
        ) {
        id
        observableRefs(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_observableRefs") {
          edges {
            node {
              ...ReportObservableLine_node
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
      return props.report && props.report.observableRefs;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        id: fragmentVariables.id,
        count,
        cursor,
        types: fragmentVariables.types,
        search: fragmentVariables.search,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: reportObservablesLinesQuery,
  },
);
