import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { NoteLine, NoteLineDummy } from './NoteLine';

const nbOfRowsToLoad = 50;

class NotesLines extends Component {
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
        dataList={pathOr([], ['notes', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['notes', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<NoteLine />}
        DummyLineComponent={<NoteLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

NotesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  notes: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const notesLinesQuery = graphql`
  query NotesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
  ) {
    ...NotesLines_data
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
  NotesLines,
  {
    data: graphql`
      fragment NotesLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "NotesOrdering", defaultValue: created }
          orderMode: { type: "OrderingMode", defaultValue: desc }
        ) {
        notes(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_notes") {
          edges {
            node {
              ...NoteLine_node
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
      return props.data && props.data.notes;
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
    query: notesLinesQuery,
  },
);
