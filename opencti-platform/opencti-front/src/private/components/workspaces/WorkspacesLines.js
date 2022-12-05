import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { WorkspaceLine, WorkspaceLineDummy } from './WorkspaceLine';
import { setNumberOfElements } from '../../../utils/Number';

const nbOfRowsToLoad = 50;

class WorkspacesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'workspaces',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      relay,
      selectAll,
      dataColumns,
      initialLoading,
      onToggleEntity,
      selectedElements,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['workspaces', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['workspaces', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<WorkspaceLine />}
        DummyLineComponent={<WorkspaceLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectAll={selectAll}
        paginationOptions={paginationOptions}
        selectedElements={selectedElements}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

WorkspacesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const workspacesLinesQuery = graphql`
  query WorkspacesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: [WorkspacesFiltering]
  ) {
    ...WorkspacesLines_data
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
  WorkspacesLines,
  {
    data: graphql`
      fragment WorkspacesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "WorkspacesOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[WorkspacesFiltering]" }
      ) {
        workspaces(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_workspaces") {
          edges {
            node {
              id
              ...WorkspaceLine_node
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
      return props.data && props.data.workspaces;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: workspacesLinesQuery,
  },
);
