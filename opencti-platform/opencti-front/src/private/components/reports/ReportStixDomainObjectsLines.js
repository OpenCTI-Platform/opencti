import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr, propOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import {
  ReportStixDomainObjectLine,
  ReportStixDomainObjectLineDummy,
} from './ReportStixDomainObjectLine';
import { setNumberOfElements } from '../../../utils/Number';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import ReportAddObjects from './ReportAddObjects';

const nbOfRowsToLoad = 50;

class ReportStixDomainObjectsLines extends Component {
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
      <div>
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
            <ReportStixDomainObjectLine reportId={propOr(null, 'id', report)} />
          }
          DummyLineComponent={<ReportStixDomainObjectLineDummy />}
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ReportAddObjects
            reportId={propOr(null, 'id', report)}
            reportObjectRefs={pathOr([], ['objects', 'edges'], report)}
            paginationOptions={paginationOptions}
            withPadding={true}
          />
        </Security>
      </div>
    );
  }
}

ReportStixDomainObjectsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  report: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const ReportStixDomainObjectsLinesQuery = graphql`
  query ReportStixDomainObjectsLinesQuery(
    $id: String!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainObjectsFiltering]
  ) {
    report(id: $id) {
      ...ReportStixDomainObjectsLines_report
        @arguments(
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
  ReportStixDomainObjectsLines,
  {
    report: graphql`
      fragment ReportStixDomainObjectsLines_report on Report
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixCoreObjectsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixCoreObjectsFiltering]" }
        ) {
        id
        objects(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_objects") {
          edges {
            node {
              ... on BasicObject {
                id
              }
              ...ReportStixDomainObjectLine_node
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
        search: fragmentVariables.search,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: ReportStixDomainObjectsLinesQuery,
  },
);
