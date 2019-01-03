/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer, InfiniteLoader, List, WindowScroller,
} from 'react-virtualized';
import { ReportLine, ReportLineDummy } from './ReportLine';

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

class ReportsLines extends Component {
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

    // Fetch the next 10 feed items
    this.props.relay.loadMore(25, () => {
      // console.log(error);
    });
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = pathOr([], ['reports', 'edges'], this.props.data);
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return <div key={key} style={style}><ReportLineDummy/></div>;
    }

    const list = pathOr([], ['reports', 'edges'], this.props.data);
    if (!this._isRowLoaded({ index })) {
      return <div key={key} style={style}><ReportLineDummy/></div>;
    }
    const reportNode = list[index];
    if (!reportNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const report = reportNode.node;
    return <div key={key} style={style}>
        <ReportLine key={report.id} report={report} paginationOptions={this.props.paginationOptions}/>
    </div>;
  }

  render() {
    const { dummy } = this.props;
    const { scrollToIndex } = this.state;
    const list = dummy ? [] : pathOr([], ['reports', 'edges'], this.props.data);
    const rowCount = dummy ? 20 : this.props.relay.isLoading() ? list.length + 25 : list.length;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
          <div className={styles.windowScrollerWrapper}>
            <InfiniteLoader isRowLoaded={this._isRowLoaded}
                            loadMoreRows={this._loadMore} rowCount={Number.MAX_SAFE_INTEGER}>
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

ReportsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  reports: PropTypes.object,
  dummy: PropTypes.bool,
};

export const reportsLinesQuery = graphql`
    query ReportsLinesPaginationQuery($count: Int!, $cursor: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode) {
        ...ReportsLines_data @arguments(count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode)
    }
`;

export const reportsLinesSearchQuery = graphql`
    query ReportsLinesSearchQuery($search: String) {
        reports(search: $search) {
            edges {
                node {
                    id
                    name
                    createdByRef {
                        name
                    }
                    published
                    created_at
                    updated_at
                }
            }
        }
    }
`;

export default withStyles(styles)(createPaginationContainer(
  ReportsLines,
  {
    data: graphql`
        fragment ReportsLines_data on Query @argumentDefinitions(
            count: {type: "Int", defaultValue: 25}
            cursor: {type: "ID"}
            orderBy: {type: "ReportsOrdering", defaultValue: ID}
            orderMode: {type: "OrderingMode", defaultValue: "asc"}
        ) {
            reports(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) @connection(key: "Pagination_reports") {
                edges {
                    node {
                        ...ReportLine_report
                    }
                }
            }
        }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.reports;
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
    query: reportsLinesQuery,
  },
));
