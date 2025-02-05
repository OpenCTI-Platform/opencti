import React, { CSSProperties, useEffect, useLayoutEffect, useMemo, useState } from 'react';
import * as R from 'ramda';
import DataTableHeaders from './DataTableHeaders';
import { DataTableBodyProps, DataTableLineProps, DataTableVariant } from '../dataTableTypes';
import DataTableLine, { DataTableLinesDummy } from './DataTableLine';
import { useDataTableContext } from './DataTableContext';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import callbackResizeObserver from '../../../utils/resizeObservers';

const DataTableBody = ({
  settingsMessagesBannerHeight = 0,
  hasFilterComponent,
  dataTableToolBarComponent,
  pageStart,
  pageSize,
  hideHeaders = false,
  tableRef,
}: DataTableBodyProps) => {
  const {
    rootRef,
    variant,
    resolvePath,
    tableWidthState: [tableWidth, setTableWidth],
    startsWithAction,
    endsWithAction,
    actions,
    columns,
    useDataTable: {
      data: queryData,
      isLoading,
      loadMore,
      hasMore,
    },
    useDataTableToggle: {
      selectedElements,
      onToggleEntity,
    },
    useDataTablePaginationLocalStorage: {
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const resolvedData = useMemo(() => {
    if (!queryData) {
      return [];
    }
    return resolvePath(queryData).slice(pageStart, pageStart + pageSize);
  }, [queryData, pageStart, pageSize]);

  useEffect(() => {
    if (resolvePath(queryData).length < pageStart + pageSize && hasMore?.()) {
      loadMore?.(pageSize);
    }
  }, [resolvedData]);

  // Keep table width up to date.
  useLayoutEffect(() => {
    let observer: ResizeObserver;
    if (tableRef.current) {
      const resize = (el: Element) => {
        let offset = 10;
        if (startsWithAction) offset += SELECT_COLUMN_SIZE;
        if (endsWithAction) offset += SELECT_COLUMN_SIZE;
        if ((el.clientWidth - offset) !== tableWidth) {
          setTableWidth(el.clientWidth - offset);
        }
      };
      resize(tableRef.current);
      observer = callbackResizeObserver(tableRef.current, resize);
    }
    return () => { observer?.disconnect(); };
  }, [tableRef.current, tableWidth, startsWithAction, endsWithAction]);

  const onToggleShiftEntity: DataTableLineProps['onToggleShiftEntity'] = (currentIndex, currentEntity, event) => {
    if (selectedElements && !R.isEmpty(selectedElements)) {
      // Find the indexes of the first and last selected entities
      let firstIndex = R.findIndex(
        (n: { id: string }) => n.id === R.head(R.values(selectedElements))?.id,
        resolvedData,
      );
      if (currentIndex > firstIndex) {
        let entities: { id: string }[] = [];
        while (firstIndex <= currentIndex) {
          entities = [...entities, resolvedData[firstIndex]];
          firstIndex += 1;
        }
        const forcedRemove = R.values(selectedElements).filter(
          (n) => !entities.map((o) => o.id).includes(n.id),
        );
        return onToggleEntity(entities, event, forcedRemove);
      }
      let entities: { id: string }[] = [];
      while (firstIndex >= currentIndex) {
        entities = [...entities, resolvedData[firstIndex]];
        firstIndex -= 1;
      }
      const forcedRemove = R.values(selectedElements).filter(
        (n) => !entities.map((o) => o.id).includes(n.id),
      );
      return onToggleEntity(entities, event, forcedRemove);
    }
    return onToggleEntity(currentEntity, event);
  };

  const [tableHeight, setTableHeight] = useState(0);
  useLayoutEffect(() => {
    if (variant === DataTableVariant.widget && !rootRef) {
      throw Error('Invalid configuration for widget list');
    }

    const hasFilters = (filters?.filters ?? []).length > 0;
    let filtersHeight = hasFilterComponent ? 54 : 0;
    if (hasFilterComponent && hasFilters) filtersHeight += 48;

    // TODO: this computation should be avoided because too many risk of changes.
    // Instead use the rootRef props. Example in:
    // - StixCoreRelationshipCreationFromEntity.tsx
    // - IndicatorObservables.jsx
    const defaultComputation = () => {
      const rootHeight = (document.getElementById('root')?.offsetHeight ?? 0) - settingsMessagesBannerHeight;
      const headerHeight = 64;
      const breadcrumbHeight = document.getElementById('page-breadcrumb') ? 38 : 0;
      const mainPadding = 40;
      const tabsHeight = document.getElementById('tabs-container')?.children.length ? 72 : 0;
      setTableHeight(rootHeight - headerHeight - breadcrumbHeight - mainPadding - filtersHeight - tabsHeight);
    };

    // Take the height of the given parent.
    let observer: ResizeObserver;
    const rootComputation = () => {
      if (rootRef) {
        setTableHeight(rootRef.offsetHeight - filtersHeight);
      }
    };

    if (rootRef) {
      rootComputation();
      observer = callbackResizeObserver(rootRef, rootComputation);
    } else {
      defaultComputation();
    }

    return () => { observer?.disconnect(); };
  }, [settingsMessagesBannerHeight, rootRef, filters]);

  const rowWidth = useMemo(() => (
    Math.floor(columns.reduce((acc, col) => {
      const width = col.percentWidth
        ? tableWidth * (col.percentWidth / 100)
        : SELECT_COLUMN_SIZE;
      return acc + width;
    }, actions ? SELECT_COLUMN_SIZE + 9 : 9)) // 9 is for scrollbar.
  ), [columns, tableWidth]);

  const containerLinesStyle: CSSProperties = {
    overflow: 'hidden auto',
    maxHeight: `calc(${tableHeight}px - ${hideHeaders ? 0 : SELECT_COLUMN_SIZE}px)`,
    width: rowWidth,
  };

  if (!tableWidth) {
    return null;
  }

  return (
    <>
      <div style={{ width: rowWidth }}>
        {!hideHeaders && (
          <DataTableHeaders dataTableToolBarComponent={dataTableToolBarComponent} />
        )}
      </div>

      <div style={containerLinesStyle}>
        {/* If we have perf issues we should find a way to memoize this */}
        {resolvedData.map((row: { id: string }, index: number) => {
          return (
            <DataTableLine
              key={row.id}
              row={row}
              index={index}
              onToggleShiftEntity={onToggleShiftEntity}
            />
          );
        })}
        {isLoading && <DataTableLinesDummy number={Math.max(pageSize, 10)} />}
      </div>
    </>
  );
};

export default DataTableBody;
