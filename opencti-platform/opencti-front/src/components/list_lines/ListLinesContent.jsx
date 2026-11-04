import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { InfiniteLoader, List } from 'react-virtualized';
import { AutoSizer } from 'react-virtualized-auto-sizer';
import inject18n from '../i18n';
import { ExportContext } from '../../utils/ExportContextProvider';
import { isEmptyField } from '../../utils/utils';

class ListLinesContent extends Component {
  constructor(props) {
    super(props);
    this.containerRef = React.createRef();
    this._isRowLoaded = this._isRowLoaded.bind(this);
    this._loadMoreRows = this._loadMoreRows.bind(this);
    this._rowRenderer = this._rowRenderer.bind(this);
    this._resetLoadingRowCount = this._resetLoadingRowCount.bind(this);
    this.listRef = null;
    this.state = {
      loadingRowCount: 0,
      computedScrollElement: null,
      isScrollElementResolved: false,
    };
  }

  componentDidMount() {
    this.updateScrollElement();
  }

  updateScrollElement() {
    if (!this.props.height && !this.props.containerRef && this.containerRef.current) {
      let node = this.containerRef.current.parentNode;
      while (node && node !== document.body && node !== document.documentElement) {
        if (node instanceof HTMLElement) {
          const { overflowY } = window.getComputedStyle(node);
          if (overflowY === 'auto' || overflowY === 'scroll') {
            this.setState({ computedScrollElement: node, isScrollElementResolved: true });
            return;
          }
        }
        node = node.parentNode;
      }
      this.setState({ isScrollElementResolved: true });
    }
  }

  componentDidUpdate(prevProps) {
    if (!this.state.isScrollElementResolved) {
      this.updateScrollElement();
    }
    const diff = !R.equals(this.props.dataList, prevProps.dataList)
      || !R.equals(this.props.bookmarkList, prevProps.bookmarkList);
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
    if (diff || selection) {
      this.listRef?.forceUpdateGrid();
    }
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

  _onRowShiftClick(currentIndex, currentEntity, event = null) {
    const { dataList, onToggleEntity, selectedElements } = this.props;
    if (selectedElements && !R.isEmpty(selectedElements)) {
      // Find the indexes of the first and last selected entities
      let firstIndex = R.findIndex(
        (n) => n.node.id === R.head(R.values(selectedElements)).id,
        dataList,
      );
      if (currentIndex > firstIndex) {
        let entities = [];
        while (firstIndex <= currentIndex) {
          entities = [...entities, dataList[firstIndex].node];

          firstIndex++;
        }
        const forcedRemove = R.values(selectedElements).filter(
          (n) => !entities.map((o) => o.id).includes(n.id),
        );
        return onToggleEntity(entities, event, forcedRemove);
      }
      let entities = [];
      while (firstIndex >= currentIndex) {
        entities = [...entities, dataList[firstIndex].node];

        firstIndex--;
      }
      const forcedRemove = R.values(selectedElements).filter(
        (n) => !entities.map((o) => o.id).includes(n.id),
      );
      return onToggleEntity(entities, event, forcedRemove);
    }
    return onToggleEntity(currentEntity, event);
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
      addedElements,
      connectionKey,
      isTo,
      redirectionMode,
      handleRemoveSuggestedMappingLine,
      contentMappingCount,
      contentMappingData,
      bypassEditionRestriction,
      enableReferences,
      isCoverage,
    } = this.props;
    const edge = dataList[index];
    if (!edge) {
      return (
        <div key={`${index}-${key}`} style={style}>
          {/* TODO remove this when all components are pure function without compose() */}
          {!React.isValidElement(DummyLineComponent) ? (
            <DummyLineComponent dataColumns={dataColumns} />
          ) : (
            React.cloneElement(DummyLineComponent, { dataColumns })
          )}
        </div>
      );
    }
    const { node, types } = edge;
    return (
      <div key={`${index}-${key}-${node.__id}`} style={style}>
        {/* TODO remove this when all components are pure function without compose() */}
        {!React.isValidElement(LineComponent) ? (
          <LineComponent
            dataColumns={dataColumns}
            node={node}
            types={types}
            paginationOptions={paginationOptions}
            entityId={entityId}
            entityLink={entityLink}
            refetch={refetch}
            me={me}
            onLabelClick={onLabelClick}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            addedElements={addedElements}
            selectAll={selectAll}
            onToggleEntity={onToggleEntity}
            connectionKey={connectionKey}
            isTo={isTo}
            onToggleShiftEntity={this._onRowShiftClick.bind(this)}
            index={index}
            redirectionMode={redirectionMode}
            handleRemoveSuggestedMappingLine={handleRemoveSuggestedMappingLine}
            contentMappingCount={contentMappingCount}
            contentMappingData={contentMappingData}
            bypassEditionRestriction={bypassEditionRestriction}
            enableReferences={enableReferences}
            isCoverage={isCoverage}
          />
        ) : (
          React.cloneElement(LineComponent, {
            dataColumns,
            node,
            types,
            paginationOptions,
            entityId,
            entityLink,
            refetch,
            me,
            onLabelClick,
            selectedElements,
            deSelectedElements,
            addedElements,
            selectAll,
            onToggleEntity,
            connectionKey,
            isTo,
            onToggleShiftEntity: this._onRowShiftClick.bind(this),
            index,
            redirectionMode,
            contentMappingCount,
            contentMappingData,
            bypassEditionRestriction,
            enableReferences,
            isCoverage,
          })
        )}
      </div>
    );
  }

  renderContent() {
    const {
      dataList,
      globalCount,
      initialLoading,
      isLoading,
      nbOfRowsToLoad,
      height: propHeight,
      width: propWidth,
      containerRef: propContainerRef,
    } = this.props;
    const countWithLoading = isLoading()
      ? dataList.length + this.state.loadingRowCount
      : dataList.length;
    const rowCount = initialLoading ? nbOfRowsToLoad : countWithLoading;
    let scrollElement = 'window';
    if (propHeight && this.containerRef && this.containerRef.current) {
      scrollElement = this.containerRef.current;
    } else if (propContainerRef && propContainerRef.current) {
      scrollElement = propContainerRef.current;
    } else if (this.state.computedScrollElement) {
      scrollElement = this.state.computedScrollElement;
    }
    return (
      <div
        style={{
          height: propHeight || 'auto',
          maxHeight: propHeight || 'auto',
          width: propWidth || 'auto',
          maxWidth: propWidth || 'auto',
          overflowY: propHeight ? 'auto' : 'hidden',
          overflowX: propWidth ? 'auto' : 'hidden',
          listStyleType: 'none',
        }}
        ref={this.containerRef}
      >
        <div>
          <InfiniteLoader
            isRowLoaded={this._isRowLoaded}
            loadMoreRows={this._loadMoreRows}
            rowCount={globalCount}
          >
            {({ onRowsRendered, registerChild }) => (
              <AutoSizer
                style={{ overflow: 'visible', width: 0 }}
                renderProp={({ width }) => (width ? (
                  <List
                    ref={(ref) => {
                      this.listRef = ref;
                      registerChild(ref);
                    }}
                    role="grid"
                    scrollElement={scrollElement}
                    onRowsRendered={onRowsRendered}
                    overscanRowCount={nbOfRowsToLoad}
                    rowCount={rowCount}
                    rowHeight={50}
                    rowRenderer={this._rowRenderer.bind(this)}
                    width={width}
                  />
                ) : null)}
              />
            )}
          </InfiniteLoader>
        </div>
      </div>
    );
  }

  render() {
    const { dataList, selectedElements, deSelectedElements, disableExport } = this.props;
    if (disableExport) {
      return this.renderContent();
    }
    return (
      <ExportContext.Consumer>
        {({ selectedIds, setSelectedIds }) => {
          // selectedIds: ids of elements that are selected via checkboxes AND respect the filtering conditions
          let newSelectedIds = [];
          if (!isEmptyField(deSelectedElements)) {
            newSelectedIds = dataList
              .map((o) => o.node.id)
              .filter((id) => !Object.keys(deSelectedElements).includes(id));
          } else if (!isEmptyField(selectedElements)) {
            newSelectedIds = dataList
              .map((o) => o.node.id)
              .filter((id) => Object.keys(selectedElements).includes(id));
          }
          if (!R.equals(selectedIds, newSelectedIds)) {
            setSelectedIds(newSelectedIds);
          }
          return this.renderContent();
        }}
      </ExportContext.Consumer>
    );
  }
}

ListLinesContent.propTypes = {
  t: PropTypes.func,
  initialLoading: PropTypes.bool,
  loadMore: PropTypes.func,
  hasMore: PropTypes.func,
  refetch: PropTypes.func,
  isLoading: PropTypes.func,
  dataList: PropTypes.array,
  me: PropTypes.object,
  globalCount: PropTypes.number,
  LineComponent: PropTypes.oneOfType([PropTypes.object, PropTypes.func]),
  DummyLineComponent: PropTypes.oneOfType([PropTypes.object, PropTypes.func]),
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
  redirectionMode: PropTypes.string,
  addedElements: PropTypes.object,
  containerRef: PropTypes.object,
  contentMappingCount: PropTypes.object,
  contentMappingData: PropTypes.object,
  handleRemoveSuggestedMappingLine: PropTypes.func,
  bypassEditionRestriction: PropTypes.bool,
  enableReferences: PropTypes.bool,
  isCoverage: PropTypes.bool,
};

export default R.compose(inject18n)(ListLinesContent);
