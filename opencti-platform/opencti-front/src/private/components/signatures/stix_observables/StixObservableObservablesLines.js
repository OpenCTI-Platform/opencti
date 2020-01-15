import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { interval } from 'rxjs';
import { pathOr } from 'ramda';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  StixObservableObservableLine,
  StixObservableObservableLineDummy,
} from './StixObservableObservableLine';
import { TEN_SECONDS } from '../../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const nbOfRowsToLoad = 25;

class StixObservableObservablesLines extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(25);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      entityLink,
      paginationOptions,
      displayRelation,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr(
          [],
          ['stixObservableRelations', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixObservableRelations', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={
          <StixObservableObservableLine displayRelation={displayRelation} />
        }
        DummyLineComponent={
          <StixObservableObservableLineDummy
            displayRelation={displayRelation}
          />
        }
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
      />
    );
  }
}

StixObservableObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixRelations: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  displayRelation: PropTypes.bool,
};

export const stixObservableObservablesLinesQuery = graphql`
  query StixObservableObservablesLinesPaginationQuery(
    $fromId: String
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixObservableRelationsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixObservableObservablesLines_data
      @arguments(
        fromId: $fromId
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  StixObservableObservablesLines,
  {
    data: graphql`
      fragment StixObservableObservablesLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixObservableRelationsOrdering" }
          orderMode: { type: "OrderingMode" }
        ) {
        stixObservableRelations(
          fromId: $fromId
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixObservableRelations") {
          edges {
            node {
              ...StixObservableObservableLine_node
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
      return props.data && props.data.stixObservableRelations;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        fromId: fragmentVariables.fromId,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixObservableObservablesLinesQuery,
  },
);
