/* eslint-disable no-underscore-dangle */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import {
  AutoSizer,
  InfiniteLoader,
  List,
  WindowScroller,
} from 'react-virtualized';
import inject18n from '../i18n';

const styles = () => ({
  windowScrollerWrapper: {
    flex: '1 1 auto',
  },
});

class ListLinesContent extends Component {
  constructor(props) {
    super(props);
    this._isRowLoaded = this._isRowLoaded.bind(this);
    this._loadMoreRows = this._loadMoreRows.bind(this);
    this._rowRenderer = this._rowRenderer.bind(this);
    this._setRef = this._setRef.bind(this);
    this._resetLoadingRowCount = this._resetLoadingRowCount.bind(this);
    this.listRef = React.createRef();
    this.state = {
      loadingRowCount: 0,
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
    if (
      Object.keys(this.props.deSelectedElements || {}).length
      !== Object.keys(prevProps.deSelectedElements || {}).length
    ) {
      selection = true;
    }
    if (this.props.selectAll !== prevProps.selectAll) {
      selection = true;
    }
    if (diff.length > 0 || diffBookmark.length > 0 || selection) {
      this.listRef.forceUpdateGrid();
    }
  }

  _setRef(windowScroller) {
    // noinspection JSUnusedGlobalSymbols
    this._windowScroller = windowScroller;
  }

  _resetLoadingRowCount() {
    this.setState({ loadingRowCount: 0 });
  }

  _loadMoreRows() {
    const {
      loadMore,
      hasMore,
      isLoading,
      dataList,
      globalCount,
      nbOfRowsToLoad,
    } = this.props;
    if (!hasMore() || isLoading()) {
      return;
    }
    const difference = globalCount - dataList.length;
    this.setState({
      loadingRowCount:
        difference >= nbOfRowsToLoad ? nbOfRowsToLoad : difference,
    });
    loadMore(nbOfRowsToLoad, this._resetLoadingRowCount);
  }

  _isRowLoaded({ index }) {
    return !this.props.hasMore() || index < this.props.dataList.length;
  }

  _rowRenderer({ index, key, style }) {
    const {
      dataColumns,
      dataList,
      LineComponent,
      DummyLineComponent,
      paginationOptions,
      entityLink,
      entityId,
      me,
      refetch,
      onLabelClick,
      selectedElements,
      deSelectedElements,
      selectAll,
      onToggleEntity,
      connectionKey,
      isTo,
    } = this.props;
    const edge = dataList[index];
    if (!edge) {
      return (
        <div key={key} style={style}>
          {React.cloneElement(DummyLineComponent, {
            dataColumns,
          })}
        </div>
      );
    }
    const { node } = edge;
    return (
      <div key={key} style={style}>
        {React.cloneElement(LineComponent, {
          dataColumns,
          node,
          paginationOptions,
          entityId,
          entityLink,
          refetch,
          me,
          onLabelClick,
          selectedElements,
          deSelectedElements,
          selectAll,
          onToggleEntity,
          connectionKey,
          isTo,
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
      nbOfRowsToLoad,
      classes,
    } = this.props;
    const countWithLoading = isLoading()
      ? dataList.length + this.state.loadingRowCount
      : dataList.length;
    const rowCount = initialLoading ? nbOfRowsToLoad : countWithLoading;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({ height, isScrolling, onChildScroll, scrollTop }) => (
          <div className={classes.windowScrollerWrapper}>
            <InfiniteLoader
              isRowLoaded={this._isRowLoaded}
              loadMoreRows={this._loadMoreRows}
              rowCount={globalCount}
            >
              {({ onRowsRendered, registerChild }) => (
                <AutoSizer disableHeight>
                  {({ width }) => (
                    <List
                      ref={(ref) => {
                        this.listRef = ref;
                        registerChild(ref);
                      }}
                      autoHeight={true}
                      height={height}
                      onRowsRendered={onRowsRendered}
                      isScrolling={isScrolling}
                      onScroll={onChildScroll}
                      overscanRowCount={nbOfRowsToLoad}
                      rowCount={rowCount}
                      rowHeight={50}
                      rowRenderer={this._rowRenderer}
                      scrollToIndex={-1}
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

ListLinesContent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  initialLoading: PropTypes.bool,
  loadMore: PropTypes.func,
  hasMore: PropTypes.func,
  refetch: PropTypes.func,
  isLoading: PropTypes.func,
  dataList: PropTypes.array,
  me: PropTypes.object,
  globalCount: PropTypes.number,
  LineComponent: PropTypes.object,
  DummyLineComponent: PropTypes.object,
  nbOfRowsToLoad: PropTypes.number,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  onLabelClick: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  onToggleEntity: PropTypes.func,
  selectAll: PropTypes.bool,
  connectionKey: PropTypes.string,
  isTo: PropTypes.bool,
};

export default R.compose(inject18n, withStyles(styles))(ListLinesContent);
