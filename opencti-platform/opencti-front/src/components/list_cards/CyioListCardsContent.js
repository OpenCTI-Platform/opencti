/* eslint-disable no-underscore-dangle */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  ColumnSizer,
  InfiniteLoader,
  Grid,
  WindowScroller,
} from 'react-virtualized';
import inject18n from '../i18n';

const numberOfCardsPerLine = 3;

const styles = () => ({
  windowScrollerWrapper: {
    flex: '1 1 auto',
  },
  defaultCard: {
    padding: '0 15px 30px 15px',
  },
});

class CyioListCardsContent extends Component {
  constructor(props) {
    super(props);
    this._isCellLoaded = this._isCellLoaded.bind(this);
    this._loadMoreRows = this._loadMoreRows.bind(this);
    this._onSectionRendered = this._onSectionRendered.bind(this);
    this._cellRenderer = this._cellRenderer.bind(this);
    this._setRef = this._setRef.bind(this);
    this._resetLoadingCardCount = this._resetLoadingCardCount.bind(this);
    this.gridRef = React.createRef();
    this.state = {
      loadingCardCount: 0,
    };
  }

  componentDidUpdate(prevProps) {
    const diff = R.symmetricDifferenceWith(
      (x, y) => x.node.id === y.node.id,
      this.props.dataList,
      prevProps.dataList,
    );
    const diffBookmark = R.symmetricDifferenceWith(
      (x, y) => x.node.id === y.node.id,
      this.props.bookmarkList || [],
      prevProps.bookmarkList || [],
    );
    let selection = false;
    if (
      Object.keys(this.props.selectedElements || {}).length
      !== Object.keys(prevProps.selectedElements || {}).length
    ) {
      selection = true;
    }
    if (this.props.selectAll !== prevProps.selectAll) {
      selection = true;
    }
    if (diff.length > 0 || diffBookmark.length > 0 || selection) {
      this.gridRef.forceUpdate();
    }
  }

  _setRef(windowScroller) {
    // noinspection JSUnusedGlobalSymbols
    this._windowScroller = windowScroller;
  }

  _resetLoadingCardCount() {
    this.setState({ loadingCardCount: 0 });
  }

  _loadMoreRows() {
    const {
      loadMore,
      hasMore,
      isLoading,
      dataList,
      globalCount,
      nbOfCardsToLoad,
    } = this.props;
    if (!hasMore() || isLoading()) {
      return;
    }
    const difference = globalCount - dataList.length;
    this.setState({
      loadingCardCount:
        difference >= nbOfCardsToLoad ? nbOfCardsToLoad : difference,
    });
    loadMore(nbOfCardsToLoad, this._resetLoadingCardCount);
  }

  _onSectionRendered({
    columnStartIndex,
    columnStopIndex,
    rowStartIndex,
    rowStopIndex,
  }) {
    const startIndex = rowStartIndex * numberOfCardsPerLine + columnStartIndex;
    const stopIndex = rowStopIndex * numberOfCardsPerLine + columnStopIndex;
    this._onRowsRendered({
      startIndex,
      stopIndex,
    });
  }

  _isCellLoaded({ index }) {
    return !this.props.hasMore() || index < this.props.dataList.length;
  }

  _cellRenderer({
    columnIndex, key, rowIndex, style,
  }) {
    const {
      classes,
      dataList,
      selectAll,
      bookmarkList,
      CardComponent,
      onToggleEntity,
      selectedElements,
      DummyCardComponent,
      initialLoading,
      onLabelClick,
    } = this.props;
    const bookmarksIds = R.map((n) => n.node.id, bookmarkList || []);
    const index = rowIndex * numberOfCardsPerLine + columnIndex;
    const className = classes.defaultCard;
    if (initialLoading || !this._isCellLoaded({ index })) {
      return (
        <div className={className} key={key} style={style}>
          {React.cloneElement(DummyCardComponent)}
        </div>
      );
    }
    const edge = dataList[index];
    if (!edge) {
      return (
        <div key={key} style={style}>
          &nbsp;
        </div>
      );
    }
    const { node } = edge;
    return (
      <div className={className} key={key} style={style}>
        {React.cloneElement(CardComponent, {
          node,
          selectAll,
          bookmarksIds,
          onLabelClick,
          onToggleEntity,
          selectedElements,
        })}
      </div>
    );
  }

  render() {
    const {
      dataList,
      globalCount,
      initialLoading,
      isLoading,
      nbOfCardsToLoad,
      rowHeight,
    } = this.props;
    const nbLineForCards = Math.ceil(dataList.length / numberOfCardsPerLine);
    const nbOfLinesToLoad = Math.ceil(nbOfCardsToLoad / numberOfCardsPerLine);
    const nbLinesWithLoading = isLoading()
      ? nbLineForCards + this.state.loadingCardCount
      : nbLineForCards;
    const rowCount = initialLoading ? nbOfLinesToLoad : nbLinesWithLoading;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
          <div className={styles.windowScrollerWrapper}>
            <InfiniteLoader
              isRowLoaded={this._isCellLoaded}
              loadMoreRows={this._loadMoreRows}
              rowCount={globalCount}
            >
              {({ onRowsRendered, registerChild }) => {
                this._onRowsRendered = onRowsRendered;
                return (
                  <AutoSizer disableHeight>
                    {({ width }) => (
                      <ColumnSizer
                        columnCount={numberOfCardsPerLine}
                        width={width}
                      >
                        {({ adjustedWidth, getColumnWidth }) => {
                          const columnWidth = getColumnWidth();
                          return (
                            <Grid
                              ref={(ref) => {
                                this.gridRef = ref;
                                registerChild(ref);
                              }}
                              autoHeight={true}
                              height={height}
                              onRowsRendered={onRowsRendered}
                              isScrolling={isScrolling}
                              onScroll={onChildScroll}
                              columnWidth={columnWidth}
                              columnCount={numberOfCardsPerLine}
                              rowHeight={rowHeight || 345}
                              overscanColumnCount={numberOfCardsPerLine}
                              overscanRowCount={2}
                              rowCount={rowCount}
                              cellRenderer={this._cellRenderer}
                              onSectionRendered={this._onSectionRendered}
                              scrollToIndex={-1}
                              scrollTop={scrollTop}
                              width={adjustedWidth}
                            />
                          );
                        }}
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

CyioListCardsContent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  initialLoading: PropTypes.bool,
  loadMore: PropTypes.func,
  hasMore: PropTypes.func,
  isLoading: PropTypes.func,
  dataList: PropTypes.array,
  bookmarkList: PropTypes.array,
  globalCount: PropTypes.number,
  CardComponent: PropTypes.object,
  onToggleEntity: PropTypes.func,
  DummyCardComponent: PropTypes.object,
  selectedElements: PropTypes.object,
  nbOfCardsToLoad: PropTypes.number,
  selectAll: PropTypes.bool,
  width: PropTypes.number,
  rowHeight: PropTypes.number,
  onLabelClick: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(CyioListCardsContent);
