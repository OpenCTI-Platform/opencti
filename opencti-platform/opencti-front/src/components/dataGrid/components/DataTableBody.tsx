import React, { CSSProperties, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as R from 'ramda';
import DataTableHeaders from './DataTableHeaders';
import { DataTableBodyProps, DataTableLineProps, DataTableVariant } from '../dataTableTypes';
import DataTableLine, { DataTableLinesDummy } from './DataTableLine';
import { useDataTableContext } from './DataTableContext';

const DataTableBody = ({
  settingsMessagesBannerHeight = 0,
  hasFilterComponent,
  dataTableToolBarComponent,
  pageStart,
  pageSize,
  hideHeaders = false,
}: DataTableBodyProps) => {
  const {
    rootRef,
    variant,
    resolvePath,
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

  // TABLE HANDLING
  const containerRef = useRef<HTMLDivElement | null>(null);

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
    const hasFilters = (filters?.filters ?? []).length > 0;
    let filtersHeight = hasFilterComponent ? 54 : 0;
    if (hasFilterComponent && hasFilters) filtersHeight += 48;

    if (variant === DataTableVariant.widget) {
      if (!rootRef) throw Error('Invalid configuration for widget list');
      setTableHeight(rootRef.offsetHeight);
    } else if (rootRef) {
      setTableHeight(rootRef.offsetHeight - filtersHeight);
    } else {
      // TODO: this computation should be avoided because too many risk of changes.
      // Instead use the rootRef props. Example in:
      // - StixCoreRelationshipCreationFromEntity.tsx
      // - IndicatorObservables.jsx
      const rootHeight = (document.getElementById('root')?.offsetHeight ?? 0) - settingsMessagesBannerHeight;
      const headerHeight = 64;
      const breadcrumbHeight = document.getElementById('page-breadcrumb') ? 38 : 0;
      const mainPadding = 24;
      const tabsHeight = document.getElementById('tabs-container')?.children.length ? 72 : 0;
      setTableHeight(rootHeight - headerHeight - breadcrumbHeight - mainPadding - filtersHeight - tabsHeight);
    }
  }, [setTableHeight, settingsMessagesBannerHeight, rootRef, filters]);

  const containerStyle: CSSProperties = {
    overflow: 'auto',
    maxHeight: `${tableHeight}px`,
  };

  const containerLinesStyle: CSSProperties = {
    position: 'relative',
  };

  return (
    <div style={containerStyle} ref={containerRef}>
      <div style={containerLinesStyle}>
        {!hideHeaders && (
          <DataTableHeaders dataTableToolBarComponent={dataTableToolBarComponent} />
        )}

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
        {isLoading && <DataTableLinesDummy number={Math.max(pageSize, 25)} />}
      </div>
    </div>
  );
};

export default DataTableBody;
