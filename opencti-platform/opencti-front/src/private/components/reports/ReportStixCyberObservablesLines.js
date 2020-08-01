import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr, propOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import {
  ReportStixCyberObservableLine,
  ReportStixCyberObservableLineDummy,
} from './ReportStixCyberObservableLine';
import { setNumberOfElements } from '../../../utils/Number';

const nbOfRowsToLoad = 50;

class ReportStixCyberObservablesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'objects',
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
        dataList={pathOr([], ['objects', 'edges'], report)}
        paginationOptions={paginationOptions}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['objects', 'pageInfo', 'globalCount'],
          report,
        )}
        LineComponent={
          <ReportStixCyberObservableLine
            reportId={propOr(null, 'id', report)}
          />
        }
        DummyLineComponent={<ReportStixCyberObservableLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

ReportStixCyberObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  report: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const reportStixCyberObservablesLinesQuery = graphql`
  query ReportStixCyberObservablesLinesQuery(
    $id: String!
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixObjectOrStixRelationshipsFiltering]
  ) {
    report(id: $id) {
      ...ReportStixCyberObservablesLines_report
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
  ReportStixCyberObservablesLines,
  {
    report: graphql`
      fragment ReportStixCyberObservablesLines_report on Report
        @argumentDefinitions(
          types: { type: "[String]" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixObjectOrStixRelationshipsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixObjectOrStixRelationshipsFiltering]" }
        ) {
        id
        objects(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_objects") {
          edges {
            node {
              ...ReportStixCyberObservableLine_node
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
      return props.report && props.report.objects;
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
    query: reportStixCyberObservablesLinesQuery,
  },
);
