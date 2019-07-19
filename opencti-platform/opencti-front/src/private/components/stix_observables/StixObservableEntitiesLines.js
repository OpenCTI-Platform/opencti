/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  InfiniteLoader,
  List,
  WindowScroller,
} from 'react-virtualized';
import {
  StixObservableEntityLine,
  StixObservableEntityLineDummy,
} from './StixObservableEntityLine';

const styles = () => ({
  windowScrollerWrapper: {
    flex: '1 1 auto',
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
    marginTop: '-10px',
  },
});

class StixObservableEntitysLines extends Component {
  constructor(props) {
    super(props);
    this._isRowLoaded = this._isRowLoaded.bind(this);
    this._loadMore = this._loadMore.bind(this);
    this._rowRenderer = this._rowRenderer.bind(this);
    this._setRef = this._setRef.bind(this);
    this.state = {
      scrollToIndex: -1,
      showHeaderText: true,
    };
  }

  _setRef(windowScroller) {
    // noinspection JSUnusedGlobalSymbols
    this._windowScroller = windowScroller;
  }

  _loadMore() {
    if (!this.props.relay.hasMore() || this.props.relay.isLoading()) {
      return;
    }
    this.props.relay.loadMore(25);
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = pathOr([], ['stixRelations', 'edges'], this.props.data);
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <StixObservableEntityLineDummy />
        </div>
      );
    }

    const list = pathOr([], ['stixRelations', 'edges'], this.props.data);
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <StixObservableEntityLineDummy />
        </div>
      );
    }
    const stixRelationNode = list[index];
    if (!stixRelationNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const stixRelation = stixRelationNode.node;
    const stixObservable = stixRelationNode.node.from;
    const stixDomainEntity = stixRelationNode.node.to;
    return (
      <div key={key} style={style}>
        <StixObservableEntityLine
          key={stixRelation.id}
          stixRelation={stixRelation}
          stixDomainEntity={stixDomainEntity}
          stixObservable={stixObservable}
          entityId={this.props.entityId}
          paginationOptions={this.props.paginationOptions}
        />
      </div>
    );
  }

  render() {
    const { dummy } = this.props;
    const { scrollToIndex } = this.state;
    const list = dummy
      ? []
      : pathOr([], ['stixRelations', 'edges'], this.props.data);
    const rowCount = dummy
      ? 20
      : this.props.relay.isLoading()
        ? list.length + 25
        : list.length;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
          <div className={styles.windowScrollerWrapper}>
            <InfiniteLoader
              isRowLoaded={this._isRowLoaded}
              loadMoreRows={this._loadMore}
              rowCount={Number.MAX_SAFE_INTEGER}
            >
              {({ onRowsRendered }) => (
                <AutoSizer disableHeight>
                  {({ width }) => (
                    <List
                      ref={(el) => {
                        window.listEl = el;
                      }}
                      autoHeight
                      height={height}
                      onRowsRendered={onRowsRendered}
                      isScrolling={isScrolling}
                      onScroll={onChildScroll}
                      overscanRowCount={2}
                      rowCount={rowCount}
                      rowHeight={50}
                      rowRenderer={this._rowRenderer}
                      scrollToIndex={scrollToIndex}
                      scrollTop={scrollTop}
                      width={width}
                    />
                  )}
                </AutoSizer>
              )}
            </InfiniteLoader>
          </div>
        )}
      </WindowScroller>
    );
  }
}

StixObservableEntitysLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  entityId: PropTypes.string,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixRelations: PropTypes.object,
  dummy: PropTypes.bool,
};

export const stixObservableEntitiesLinesQuery = graphql`
  query StixObservableEntitiesLinesPaginationQuery(
    $fromId: String
    $inferred: Boolean
    $relationType: String
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $firstSeenStart: DateTime
    $firstSeenStop: DateTime
    $lastSeenStart: DateTime
    $lastSeenStop: DateTime
    $weights: [Int]
    $count: Int!
    $cursor: ID
    $orderBy: StixRelationsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixObservableEntitiesLines_data
      @arguments(
        fromId: $fromId
        inferred: $inferred
        relationType: $relationType
        resolveInferences: $resolveInferences
        resolveRelationType: $resolveRelationType
        resolveRelationRole: $resolveRelationRole
        resolveRelationToTypes: $resolveRelationToTypes
        resolveViaTypes: $resolveViaTypes
        firstSeenStart: $firstSeenStart
        firstSeenStop: $firstSeenStop
        lastSeenStart: $lastSeenStart
        lastSeenStop: $lastSeenStop
        weights: $weights
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    StixObservableEntitysLines,
    {
      data: graphql`
        fragment StixObservableEntitiesLines_data on Query
          @argumentDefinitions(
            fromId: { type: "String" }
            inferred: { type: "Boolean" }
            relationType: { type: "String" }
            resolveInferences: { type: "Boolean" }
            resolveRelationType: { type: "String" }
            resolveRelationRole: { type: "String" }
            resolveRelationToTypes: { type: "[String]" }
            resolveViaTypes: { type: "[EntityRelation]" }
            firstSeenStart: { type: "DateTime" }
            firstSeenStop: { type: "DateTime" }
            lastSeenStart: { type: "DateTime" }
            lastSeenStop: { type: "DateTime" }
            weights: { type: "[Int]" }
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: {
              type: "StixRelationsOrdering"
              defaultValue: "first_seen"
            }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          stixRelations(
            fromId: $fromId
            inferred: $inferred
            relationType: $relationType
            resolveInferences: $resolveInferences
            resolveRelationType: $resolveRelationType
            resolveRelationRole: $resolveRelationRole
            resolveRelationToTypes: $resolveRelationToTypes
            resolveViaTypes: $resolveViaTypes
            firstSeenStart: $firstSeenStart
            firstSeenStop: $firstSeenStop
            lastSeenStart: $lastSeenStart
            lastSeenStop: $lastSeenStop
            weights: $weights
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_stixRelations") {
            edges {
              node {
                ...StixObservableEntityLine_stixRelation
                from {
                  ...StixObservableEntityLine_stixObservable
                }
                to {
                  ...StixObservableEntityLine_stixDomainEntity
                }
              }
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.stixRelations;
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
          toTypes: fragmentVariables.toTypes,
          inferred: fragmentVariables.inferred,
          relationType: fragmentVariables.relationType,
          resolveInferences: fragmentVariables.resolveInferences,
          resolveRelationType: fragmentVariables.resolveRelationType,
          resolveRelationRole: fragmentVariables.resolveRelationRole,
          resolveRelationToTypes: fragmentVariables.resolveRelationToTypes,
          resolveViaTypes: fragmentVariables.resolveViaTypes,
          firstSeenStart: fragmentVariables.firstSeenStart,
          firstSeenStop: fragmentVariables.firstSeenStop,
          lastSeenStart: fragmentVariables.lastSeenStart,
          lastSeenStop: fragmentVariables.lastSeenStop,
          weights: fragmentVariables.weights,
          count,
          cursor,
          orderBy: fragmentVariables.orderBy,
          orderMode: fragmentVariables.orderMode,
        };
      },
      query: stixObservableEntitiesLinesQuery,
    },
  ),
);
