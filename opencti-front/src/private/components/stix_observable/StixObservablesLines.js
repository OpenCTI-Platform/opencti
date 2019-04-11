/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  assoc, filter, join, map, pathOr, pipe, propOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  InfiniteLoader,
  List,
  WindowScroller,
} from 'react-virtualized';
import {
  StixObservableLine,
  StixObservableLineDummy,
} from './StixObservableLine';

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

class StixObservablesLines extends Component {
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

  componentDidUpdate(prevProps) {
    if (this.props.searchTerm !== prevProps.searchTerm) {
      this._loadMore();
    }
  }

  filterList(list) {
    const searchTerm = propOr('', 'searchTerm', this.props);
    const filterByKeyword = n => searchTerm === ''
      || n.node.entity_type.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.observable_value
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    if (searchTerm.length > 0) {
      return pipe(
        map(n => n.node),
        map(n => assoc(
          'markingDefinitions_inline',
          join(
            ', ',
            map(
              k => k.node.definition_name,
              pathOr([], ['markingDefinitions_inline', 'edges'], n),
            ),
          ),
        )(n)),
        map(n => ({ node: n })),
        filter(filterByKeyword),
      )(list);
    }
    return list;
  }

  _setRef(windowScroller) {
    // noinspection JSUnusedGlobalSymbols
    this._windowScroller = windowScroller;
  }

  _loadMore() {
    if (!this.props.relay.hasMore() || this.props.relay.isLoading()) {
      return;
    }
    this.props.relay.loadMore(
      this.props.searchTerm.length > 0 ? 100000 : 25,
    );
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = this.filterList(
      pathOr([], ['stixObservables', 'edges'], this.props.data),
    );
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <StixObservableLineDummy />
        </div>
      );
    }

    const list = this.filterList(
      pathOr([], ['stixObservables', 'edges'], this.props.data),
    );
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <StixObservableLineDummy />
        </div>
      );
    }
    const stixObservableNode = list[index];
    if (!stixObservableNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const stixObservable = stixObservableNode.node;
    return (
      <div key={key} style={style}>
        <StixObservableLine
          key={stixObservable.id}
          stixObservable={stixObservable}
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
      : this.filterList(
        pathOr([], ['stixObservables', 'edges'], this.props.data),
      );
    const rowCount = dummy
      ? 20
      : this.props.relay.isLoading()
        ? list.length + 25
        : list.length;
    return (
      <WindowScroller
        ref={this._setRef}
        scrollElement={window}
        key={this.props.searchTerm}
      >
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

StixObservablesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixObservables: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const stixObservablesLinesQuery = graphql`
  query StixObservablesLinesPaginationQuery(
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixObservablesLines_data
      @arguments(
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const stixObservablesLinesSearchQuery = graphql`
  query StixObservablesLinesSearchQuery($search: String) {
    stixObservables(search: $search) {
      edges {
        node {
          id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    }
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    StixObservablesLines,
    {
      data: graphql`
        fragment StixObservablesLines_data on Query
          @argumentDefinitions(
            types: { type: "[String]" }
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "StixObservablesOrdering", defaultValue: ID }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          stixObservables(
            types: $types
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_stixObservables") {
            edges {
              node {
                id
                entity_type
                observable_value
                created_at
                markingDefinitions {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
                }
                ...StixObservableLine_stixObservable
              }
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.stixObservables;
      },
      getFragmentVariables(prevVars, totalCount) {
        return {
          ...prevVars,
          count: totalCount,
        };
      },
      getVariables(props, { count, cursor }, fragmentVariables) {
        return {
          types: fragmentVariables.types,
          count,
          cursor,
          orderBy: fragmentVariables.orderBy,
          orderMode: fragmentVariables.orderMode,
        };
      },
      query: stixObservablesLinesQuery,
    },
  ),
);
