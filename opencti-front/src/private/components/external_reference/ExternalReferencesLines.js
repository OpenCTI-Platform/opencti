/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { filter, pathOr, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  InfiniteLoader,
  List,
  WindowScroller,
} from 'react-virtualized';
import {
  ExternalReferenceLine,
  ExternalReferenceLineDummy,
} from './ExternalReferenceLine';

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

class ExternalReferencesLines extends Component {
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
      || n.node.source_name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    if (searchTerm.length > 0) {
      return filter(filterByKeyword, list);
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
      this.props.searchTerm.length > 0 ? 90000 : 25,
    );
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = this.filterList(pathOr([], ['externalReferences', 'edges'], this.props.data));
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <ExternalReferenceLineDummy />
        </div>
      );
    }

    const list = this.filterList(pathOr([], ['externalReferences', 'edges'], this.props.data));
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <ExternalReferenceLineDummy />
        </div>
      );
    }
    const externalReferenceNode = list[index];
    if (!externalReferenceNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const externalReference = externalReferenceNode.node;
    return (
      <div key={key} style={style}>
        <ExternalReferenceLine
          key={externalReference.id}
          externalReference={externalReference}
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
      : this.filterList(pathOr([], ['externalReferences', 'edges'], this.props.data));
    const rowCount = dummy
      ? 25
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

ExternalReferencesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  externalReferences: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const externalReferencesLinesQuery = graphql`
  query ExternalReferencesLinesPaginationQuery(
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
  ) {
    ...ExternalReferencesLines_data
      @arguments(
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const externalReferencesLinesSearchQuery = graphql`
  query ExternalReferencesLinesSearchQuery($search: String, $first: Int) {
    externalReferences(search: $search, first: $first) {
      edges {
        node {
          id
          source_name
          description
          url
          hash
          external_id
        }
      }
    }
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    ExternalReferencesLines,
    {
      data: graphql`
        fragment ExternalReferencesLines_data on Query
          @argumentDefinitions(
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "ExternalReferencesOrdering", defaultValue: ID }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          externalReferences(
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_externalReferences") {
            edges {
              node {
                ...ExternalReferenceLine_externalReference
              }
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.externalReferences;
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
        };
      },
      query: externalReferencesLinesQuery,
    },
  ),
);
