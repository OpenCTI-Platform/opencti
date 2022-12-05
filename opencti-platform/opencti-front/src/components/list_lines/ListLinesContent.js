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
      this.listRef.forceUpdateGrid();
    }
    const checker = (arr, target) => target.every((v) => arr.includes(v));
    if (!checker(this.state.newDataList, this.props.dataList)
      && (this.state.loadingRowCount === 0 || this.props.offset !== 0)) {
      this.setState({
        newDataList: [...this.props.dataList, ...this.state.newDataList],
        loadedData: this.state.loadedData - this.props.dataList.length,
      });
    }
    if (window.pageYOffset < 40 && this.state.newDataList.length > 50
      && this.props.offset >= 0) {
      if (this.props.offset !== 0) {
        window.scrollTo(0, 2500);
        this.props.handleDecrementedOffsetChange();
      }
      this.setState({ newDataList: this.state.newDataList.slice(-this.props.dataList.length) });
    }
    if (this.state.loadedData !== (this.props.dataList.length + this.props.offset)
      && ((this.props.globalCount - this.state.loadedData) > 0)
      && (this.state.loadingRowCount !== 0 || this.props.offset === 0)) {
      if (this.props.dataList.length === 0) {
        this.setState({ newDataList: [] });
        this.listRef.forceUpdateGrid();
      }
      if (!checker(this.state.newDataList, this.props.dataList)) {
        this.setState({
          newDataList: [...this.state.newDataList, ...this.props.dataList],
          loadedData: this.state.loadedData + this.props.dataList.length,
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
    if (!hasMore() || isLoading()) {
      return;
    }
    const difference = globalCount - this.state.loadedData;
    this.setState({
      loadingRowCount:
        difference >= nbOfRowsToLoad ? nbOfRowsToLoad : difference,
    });
    handleIncrementedOffsetChange();
    loadMore(nbOfRowsToLoad, this._resetLoadingRowCount);
    if (this.state.newDataList.length > 50 && difference > 0) {
      setTimeout(() => {
        this.setState({ newDataList: this.state.newDataList.slice(50) });
        window.scrollTo(0, 1500);
      }, 500);
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
