import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  XOpenctiXOpenctiIncidentLine,
  XOpenctiIncidentLineDummy,
} from './XOpenctiXOpenctiIncidentLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class XOpenctiXOpenctiIncidentsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'xOpenctiIncidents',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading, dataColumns, relay, onLabelClick,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['xOpenctiIncidents', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['xOpenctiIncidents', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<XOpenctiXOpenctiIncidentLine />}
        DummyLineComponent={<XOpenctiIncidentLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
      />
    );
  }
}

XOpenctiXOpenctiIncidentsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const xOpenctiIncidentsLinesQuery = graphql`
  query XOpenctiIncidentsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: XOpenctiIncidentsOrdering
    $orderMode: OrderingMode
    $filters: [XOpenctiIncidentsFiltering]
  ) {
    ...XOpenctiIncidentsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export default createPaginationContainer(
  XOpenctiXOpenctiIncidentsLines,
  {
    data: graphql`
      fragment XOpenctiIncidentsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "XOpenctiIncidentsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[XOpenctiIncidentsFiltering]" }
        ) {
        xOpenctiIncidents(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_xOpenctiIncidents") {
          edges {
            node {
              id
              name
              description
              ...XOpenctiIncidentLine_node
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
      return props.data && props.data.xOpenctiIncidents;
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
        filters: fragmentVariables.filters,
      };
    },
    query: xOpenctiIncidentsLinesQuery,
  },
);
