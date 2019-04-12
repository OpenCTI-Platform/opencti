/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import PropTypes from 'prop-types';
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
import { SectorLine, SectorLineDummy } from './SectorLine';

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

class SectorsLines extends Component {
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
      || n.node.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
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
    const list = this.filterList(
      pathOr([], ['sectors', 'edges'], this.props.data),
    );
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <SectorLineDummy />
        </div>
      );
    }

    const list = this.filterList(
      pathOr([], ['sectors', 'edges'], this.props.data),
    );
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <SectorLineDummy />
        </div>
      );
    }
    const sectorNode = list[index];
    if (!sectorNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const sector = sectorNode.node;
    return (
      <div key={key} style={style}>
        <SectorLine key={sector.id} sector={sector} />
      </div>
    );
  }

  render() {
    const { dummy } = this.props;
    const { scrollToIndex } = this.state;
    const list = dummy
      ? []
      : this.filterList(pathOr([], ['sectors', 'edges'], this.props.data));
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

SectorsLines.propTypes = {
  classes: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  sectors: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const sectorsLinesQuery = graphql`
  query SectorsLinesPaginationQuery(
    $count: Int!
    $cursor: ID
    $orderBy: SectorsOrdering
    $orderMode: OrderingMode
  ) {
    ...SectorsLines_data
      @arguments(
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const sectorsLinesSearchQuery = graphql`
  query SectorsLinesSearchQuery($search: String) {
    sectors(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    SectorsLines,
    {
      data: graphql`
        fragment SectorsLines_data on Query
          @argumentDefinitions(
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "SectorsOrdering", defaultValue: ID }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          sectors(
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_sectors") {
            edges {
              node {
                id
                name
                description
                ...SectorLine_sector
              }
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.sectors;
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
      query: sectorsLinesQuery,
    },
  ),
);
