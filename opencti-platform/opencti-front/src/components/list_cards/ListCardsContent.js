/* eslint-disable no-underscore-dangle */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import windowDimensions from 'react-window-dimensions';
import { compose, differenceWith } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  ColumnSizer,
  InfiniteLoader,
  Grid,
  WindowScroller,
} from 'react-virtualized';
import inject18n from '../i18n';

const styles = () => ({
  windowScrollerWrapper: {
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

class ListCardsContent extends Component {
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
    const diff = differenceWith(
      (x, y) => x.node.id === y.node.id,
      this.props.dataList,
      prevProps.dataList,
    );
    if (diff.length > 0) {
      this.gridRef.forceUpdate();
    }
  }

  numberOfCardsPerLine() {
    if (this.props.width < 576) {
      return 1;
    }
    if (this.props.width < 900) {
      return 2;
    }
    if (this.props.width < 1200) {
      return 3;
    }
    return 4;
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
    const startIndex = rowStartIndex * this.numberOfCardsPerLine() + columnStartIndex;
    const stopIndex = rowStopIndex * this.numberOfCardsPerLine() + columnStopIndex;
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
      CardComponent,
      DummyCardComponent,
      initialLoading,
      onTagClick,
    } = this.props;
    const index = rowIndex * this.numberOfCardsPerLine() + columnIndex;
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
          onTagClick,
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
    } = this.props;
    const nbLineForCards = Math.ceil(
      dataList.length / this.numberOfCardsPerLine(),
    );
    const nbOfLinesToLoad = Math.ceil(
      nbOfCardsToLoad / this.numberOfCardsPerLine(),
    );
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
                        columnMaxWidth={440}
                        columnMinWidth={150}
                        columnCount={this.numberOfCardsPerLine()}
                        width={width}
                      >
                        {({ adjustedWidth, columnWidth }) => (
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
                            columnCount={this.numberOfCardsPerLine()}
                            rowHeight={195}
                            overscanColumnCount={this.numberOfCardsPerLine()}
                            overscanRowCount={2}
                            rowCount={rowCount}
                            cellRenderer={this._cellRenderer}
                            onSectionRendered={this._onSectionRendered}
                            scrollToIndex={-1}
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

ListCardsContent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  initialLoading: PropTypes.bool,
  loadMore: PropTypes.func,
  hasMore: PropTypes.func,
  isLoading: PropTypes.func,
  dataList: PropTypes.array,
  globalCount: PropTypes.number,
  CardComponent: PropTypes.object,
  DummyCardComponent: PropTypes.object,
  nbOfCardsToLoad: PropTypes.number,
  width: PropTypes.number,
  onTagClick: PropTypes.func,
};

export default compose(
  windowDimensions(),
  inject18n,
  withStyles(styles),
)(ListCardsContent);
