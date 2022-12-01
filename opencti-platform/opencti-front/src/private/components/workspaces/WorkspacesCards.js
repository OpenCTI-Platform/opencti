import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import CyioListCardsContent from '../../../components/list_cards/CyioListCardsContent';
import { WorkspaceCard, WorkspaceCardDummy } from './WorkspaceCard';
import { setNumberOfElements } from '../../../utils/Number';

const nbOfCardsToLoad = 50;

class WorkspacesCards extends Component {
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
      initialLoading,
      relay,
      selectAll,
      onToggleEntity,
      selectedElements,
      paginationOptions,
    } = this.props;
    return (
      <CyioListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['workspaces', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['workspaces', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<WorkspaceCard />}
        DummyCardComponent={<WorkspaceCardDummy />}
        selectAll={selectAll}
        selectedElements={selectedElements}
        nbOfCardsToLoad={nbOfCardsToLoad}
        paginationOptions={paginationOptions}
        onToggleEntity={onToggleEntity.bind(this)}

      />
    );
  }
}

WorkspacesCards.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const workspacesCardsQuery = graphql`
  query WorkspacesCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: [WorkspacesFiltering]
  ) {
    ...WorkspacesCards_data
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
  WorkspacesCards,
  {
    data: graphql`
      fragment WorkspacesCards_data on Query
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
              ...WorkspaceCard_node
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
    query: workspacesCardsQuery,
  },
);
