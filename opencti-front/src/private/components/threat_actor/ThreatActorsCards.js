/* eslint-disable no-underscore-dangle */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { filter, pathOr, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  ColumnSizer,
  InfiniteLoader,
  Grid,
  WindowScroller,
} from 'react-virtualized';
import { ThreatActorCard, ThreatActorCardDummy } from './ThreatActorCard';

const styles = () => ({
  windowScrollerWrapper: {
    marginTop: 5,
    flex: '1 1 auto',
  },
  bottomPad: {
    padding: '0 0 30px 0',
  },
  rightPad: {
    padding: '0 30px 30px 0',
  },
  leftPad: {
    padding: '0 0 30px 30px',
  },
});
const nbCardsPerLine = 4;
// We can't have the exact number of expected lines. InfiniteLoader requirement
const nbDummyRowsInit = 5;
export const nbCardsToLoad = nbCardsPerLine * (nbDummyRowsInit + 1);

class ThreatActorsCards extends Component {
  constructor(props) {
    super(props);
    this._isCellLoaded = this._isCellLoaded.bind(this);
    this._loadMore = this._loadMore.bind(this);
    this._onSectionRendered = this._onSectionRendered.bind(this);
    this._cellRenderer = this._cellRenderer.bind(this);
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
      this.props.searchTerm.length > 0 ? 90000 : nbCardsToLoad,
    );
  }

  _onSectionRendered({
    columnStartIndex,
    columnStopIndex,
    rowStartIndex,
    rowStopIndex,
  }) {
    const startIndex = rowStartIndex * nbCardsPerLine + columnStartIndex;
    const stopIndex = rowStopIndex * nbCardsPerLine + columnStopIndex;
    this._onRowsRendered({
      startIndex,
      stopIndex,
    });
  }

  _isCellLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = this.filterList(
      pathOr([], ['threatActors', 'edges'], this.props.data),
    );
    return !this.props.relay.hasMore() || index < list.length;
  }

  _cellRenderer({
    columnIndex, key, rowIndex, style,
  }) {
    const { classes, dummy, data } = this.props;
    const index = rowIndex * nbCardsPerLine + columnIndex;
    let className = classes.bottomPad;
    switch (columnIndex) {
      case 0:
      case 1:
        className = classes.rightPad;
        break;
      case 3:
        className = classes.leftPad;
        break;
      default:
    }
    if (dummy) {
      return (
        <div className={className} key={key} style={style}>
          <ThreatActorCardDummy />
        </div>
      );
    }

    const list = this.filterList(pathOr([], ['threatActors', 'edges'], data));
    if (!this._isCellLoaded({ index })) {
      return (
        <div className={className} key={key} style={style}>
          <ThreatActorCardDummy />
        </div>
      );
    }
    const threatActorNode = list[index];
    if (!threatActorNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const threatActor = threatActorNode.node;
    return (
      <div className={className} key={key} style={style}>
        <ThreatActorCard key={threatActor.id} threatActor={threatActor} />
      </div>
    );
  }

  render() {
    const { classes, dummy, data } = this.props;
    const list = dummy
      ? []
      : this.filterList(pathOr([], ['threatActors', 'edges'], data));
    // const globalCount = dummy ? 0 : data.threatActors.pageInfo.globalCount;
    // If init screen aka dummy
    let rowCount;
    if (dummy) {
      // If dummy, we load the default number of dummy lines.
      rowCount = nbDummyRowsInit;
    } else {
      // Else we load the lines for the result + dummy if loading in progress
      const nbLineForCards = Math.ceil(list.length / nbCardsPerLine);
      rowCount = this.props.relay.isLoading()
        ? nbLineForCards + nbDummyRowsInit
        : nbLineForCards;
    }

    const { scrollToIndex } = this.state;
    // console.log(`globalCount: ${rowCount}/${Math.ceil(globalCount / nbCardsPerLine)}`);

    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
          <div className={classes.windowScrollerWrapper}>
            <InfiniteLoader
              isRowLoaded={this._isCellLoaded}
              loadMoreRows={this._loadMore}
              rowCount={Number.MAX_SAFE_INTEGER}
            >
              {({ onRowsRendered }) => {
                this._onRowsRendered = onRowsRendered;
                return (
                  <AutoSizer disableHeight>
                    {({ width }) => (
                      <ColumnSizer
                        columnMaxWidth={440}
                        columnMinWidth={150}
                        columnCount={4}
                        width={width}
                      >
                        {({ adjustedWidth, columnWidth }) => (
                          <Grid
                            ref={(el) => {
                              window.listEl = el;
                            }}
                            autoHeight
                            height={height}
                            onRowsRendered={onRowsRendered}
                            isScrolling={isScrolling}
                            onScroll={onChildScroll}
                            columnWidth={columnWidth}
                            columnCount={4}
                            rowHeight={195}
                            overscanColumnCount={4}
                            overscanRowCount={2}
                            rowCount={rowCount}
                            cellRenderer={this._cellRenderer}
                            onSectionRendered={this._onSectionRendered}
                            scrollToIndex={scrollToIndex}
                            scrollTop={scrollTop}
                            width={adjustedWidth}
                          />
                        )}
                      </ColumnSizer>
                    )}
                  </AutoSizer>
                );
              }}
            </InfiniteLoader>
          </div>
        )}
      </WindowScroller>
    );
  }
}

ThreatActorsCards.propTypes = {
  classes: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  threatActors: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const threatActorsCardsQuery = graphql`
  query ThreatActorsCardsPaginationQuery(
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
  ) {
    ...ThreatActorsCards_data
      @arguments(
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    ThreatActorsCards,
    {
      data: graphql`
        fragment ThreatActorsCards_data on Query
          @argumentDefinitions(
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "ThreatActorsOrdering", defaultValue: "name" }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
          ) {
          threatActors(
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_threatActors") {
            edges {
              node {
                id
                name
                description
                ...ThreatActorCard_threatActor
              }
            }
            pageInfo {
              globalCount
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.threatActors;
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
      query: threatActorsCardsQuery,
    },
  ),
);
