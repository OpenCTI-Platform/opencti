/* eslint-disable no-underscore-dangle */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
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
      scrollValue: 0,
      loadedData: 0,
      loadingRowCount: 0,
      newDataList: [],
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
    const {
      dataList,
      offset,
      selectAll,
      selectedElements,
      globalCount,
      handleDecrementedOffsetChange,
    } = this.props;
    const {
      loadedData,
      newDataList,
      loadingRowCount,
    } = this.state;
    if (
      Object.keys(selectedElements || {}).length
      !== Object.keys(prevProps.selectedElements || {}).length
    ) {
      selection = true;
    }
    if (selectAll !== prevProps.selectAll) {
      selection = true;
    }
    if (diff.length > 0 || diffBookmark.length > 0 || selection) {
      this.listRef.forceUpdateGrid();
    }
    const checker = (arr, target) => target.every((v) => arr.includes(v));
    if (!checker(newDataList, dataList)
      && (loadingRowCount === 0 || offset !== 0)) {
      this.setState({
        newDataList: [...dataList, ...newDataList],
        loadedData: loadedData - dataList.length,
      });
    }
    if (window.pageYOffset < 40 && newDataList.length > 50
      && offset >= 0) {
      if (offset !== 0) {
        window.scrollTo(0, 2500);
        handleDecrementedOffsetChange();
      }
      this.setState({ newDataList: newDataList.slice(-dataList.length) });
    }
    if (loadedData !== (dataList.length + offset)
      && ((globalCount - loadedData) > 0)
      && (loadingRowCount !== 0 || offset === 0)) {
      if (dataList.length === 0) {
        this.setState({ newDataList: [] });
        this.listRef.forceUpdateGrid();
      }
      if (!checker(newDataList, dataList)) {
        this.setState({
          newDataList: [...newDataList, ...dataList],
          loadedData: loadedData + dataList.length,
        });
      }
    }
  }

  componentDidMount() {
    window.addEventListener('scroll', this.handleScroll.bind(this));
  }

  componentWillUnmount() {
    window.removeEventListener('scroll', this.handleScroll.bind(this));
  }

  handleScroll() {
    this.setState({ scrollValue: window.pageYOffset });
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
      globalCount,
      handleIncrementedOffsetChange,
      nbOfRowsToLoad,
    } = this.props;
    const { loadedData, newDataList } = this.state;
    if (!hasMore() || isLoading()) {
      return;
    }
    if (hasMore() && globalCount !== loadedData) {
      const difference = globalCount - loadedData;
      this.setState({
        loadingRowCount:
          difference >= nbOfRowsToLoad ? nbOfRowsToLoad : difference,
      });
      handleIncrementedOffsetChange();
      loadMore(nbOfRowsToLoad, this._resetLoadingRowCount);
      if (newDataList.length > 50 && difference > 0) {
        setTimeout(() => {
          this.setState({ newDataList: newDataList.slice(50) });
          window.scrollTo(0, 1500);
        }, 500);
      }
    }
  }

  _isRowLoaded({ index }) {
    return !this.props.hasMore() || index < this.state.newDataList.length;
  }

  _rowRenderer({ index, key, style }) {
    const {
      dataColumns,
      LineComponent,
      DummyLineComponent,
      paginationOptions,
      entityLink,
      entityId,
      me,
      onLabelClick,
      selectedElements,
      selectAll,
      onToggleEntity,
      connectionKey,
      isTo,
    } = this.props;
    const edge = this.state.newDataList[index];
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
          me,
          onLabelClick,
          selectedElements,
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
      globalCount,
      initialLoading,
      isLoading,
      nbOfRowsToLoad,
      classes,
    } = this.props;
    const countWithLoading = isLoading()
      ? this.state.newDataList.length + this.state.loadingRowCount
      : this.state.newDataList.length;
    const rowCount = initialLoading ? nbOfRowsToLoad : countWithLoading;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
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
  isLoading: PropTypes.func,
  handleIncrementedOffsetChange: PropTypes.func,
  handleDecrementedOffsetChange: PropTypes.func,
  offset: PropTypes.number,
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
  onToggleEntity: PropTypes.func,
  selectAll: PropTypes.bool,
  connectionKey: PropTypes.string,
  isTo: PropTypes.bool,
};

export default R.compose(inject18n, withStyles(styles))(ListLinesContent);
