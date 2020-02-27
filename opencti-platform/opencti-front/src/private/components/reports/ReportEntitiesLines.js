import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr, propOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { ReportEntityLine, ReportEntityLineDummy } from './ReportEntityLine';
import { setNumberOfElements } from '../../../utils/Number';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import ReportAddObjectRefs from './ReportAddObjectRefs';

const nbOfRowsToLoad = 25;

class ReportEntitiesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'objectRefs',
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
          dataList={pathOr([], ['objectRefs', 'edges'], report)}
          paginationOptions={paginationOptions}
          globalCount={pathOr(
            nbOfRowsToLoad,
            ['objectRefs', 'pageInfo', 'globalCount'],
            report,
          )}
          LineComponent={
            <ReportEntityLine reportId={propOr(null, 'id', report)} />
          }
          DummyLineComponent={<ReportEntityLineDummy />}
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ReportAddObjectRefs
            reportId={propOr(null, 'id', report)}
            reportObjectRefs={pathOr([], ['objectRefs', 'edges'], report)}
            paginationOptions={paginationOptions}
            withPadding={true}
          />
        </Security>
      </div>
    );
  }
}

ReportEntitiesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  report: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const ReportEntitiesLinesQuery = graphql`
  query ReportEntitiesLinesQuery(
    $id: String!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainEntitiesOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainEntitiesFiltering]
  ) {
    report(id: $id) {
      ...ReportEntitiesLines_report
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
  ReportEntitiesLines,
  {
    report: graphql`
      fragment ReportEntitiesLines_report on Report
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixDomainEntitiesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixDomainEntitiesFiltering]" }
        ) {
        id
        objectRefs(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_objectRefs") {
          edges {
            node {
              id
              ...ReportEntityLine_node
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
      return props.report && props.report.objectRefs;
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
    query: ReportEntitiesLinesQuery,
  },
);
