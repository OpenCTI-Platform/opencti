import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  CourseOfActionLine,
  CourseOfActionLineDummy,
} from './CourseOfActionLine';

const nbOfRowsToLoad = 25;

class CoursesOfActionLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['coursesOfAction', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['coursesOfAction', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<CourseOfActionLine />}
        DummyLineComponent={<CourseOfActionLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
      />
    );
  }
}

CoursesOfActionLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  coursesOfAction: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const coursesOfActionLinesQuery = graphql`
  query CoursesOfActionLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CoursesOfActionOrdering
    $orderMode: OrderingMode
  ) {
    ...CoursesOfActionLines_data
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
  CoursesOfActionLines,

  {
    data: graphql`
      fragment CoursesOfActionLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "CoursesOfActionOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        coursesOfAction(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_coursesOfAction") {
          edges {
            node {
              name
              ...CourseOfActionLine_node
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.coursesOfAction;
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
    query: coursesOfActionLinesQuery,
  },
);
