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
import { dateFormat } from '../../../utils/Time';
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

  componentDidUpdate(prevProps) {
    if (this.props.searchTerm !== prevProps.searchTerm) {
      this._loadMore();
    }
  }

  filterList(list) {
    const searchTerm = propOr('', 'searchTerm', this.props);
    const filterByKeyword = n => searchTerm === ''
      || n.node.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || dateFormat(n.node.published)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.createdByRef_inline
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.markingDefinitions_inline
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    if (searchTerm.length > 0) {
      return pipe(
        map(n => n.node),
        map(n => assoc(
          'createdByRef_inline',
          pathOr('-', ['createdByRef', 'node', 'name'], n),
        )(n)),
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
    this.props.relay.loadMore(this.props.searchTerm.length > 0 ? 90000 : 25);
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = this.filterList(
      pathOr([], ['reports', 'edges'], this.props.data),
    );
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <ReportLineDummy />
        </div>
      );
    }

    const list = this.filterList(
      pathOr([], ['reports', 'edges'], this.props.data),
    );
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <ReportLineDummy />
        </div>
      );
    }
    const reportNode = list[index];
    if (!reportNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const report = reportNode.node;
    return (
      <div key={key} style={style}>
        <ReportLine
          key={report.id}
          report={report}
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
      : this.filterList(pathOr([], ['reports', 'edges'], this.props.data));
    const listLength = this.props.relay.isLoading()
      ? list.length + 25
      : list.length;
    const rowCount = dummy
      ? listLength > 0
        ? listLength - 1
        : 24
      : listLength;
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

ReportsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  reports: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const reportsLinesQuery = graphql`
  query ReportsLinesPaginationQuery(
    $objectId: String
    $reportClass: String
    $count: Int!
    $cursor: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
  ) {
    ...ReportsLines_data
      @arguments(
        objectId: $objectId
        reportClass: $reportClass
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
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
            node {
              name
            }
          }
          published
          created_at
          updated_at
        }
      }
    }
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    ReportsLines,
    {
      data: graphql`
        fragment ReportsLines_data on Query
          @argumentDefinitions(
            objectId: { type: "String" }
            reportClass: { type: "String" }
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "ReportsOrdering", defaultValue: "name" }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          reports(
            objectId: $objectId
            reportClass: $reportClass
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_reports") {
            edges {
              node {
                id
                name
                published
                createdByRef {
                  node {
                    name
                  }
                }
                markingDefinitions {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
                }
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
          objectId: fragmentVariables.objectId,
          reportClass: fragmentVariables.reportClass,
          count,
          cursor,
          orderBy: fragmentVariables.orderBy,
          orderMode: fragmentVariables.orderMode,
        };
      },
      query: reportsLinesQuery,
    },
  ),
);
