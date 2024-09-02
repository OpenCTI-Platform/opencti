import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { Theme as MuiTheme } from '@mui/material/styles/createTheme';
import * as R from 'ramda';
import DataTableHeaders from './DataTableHeaders';
import { useDataTableContext } from '../dataTableUtils';
import { ColumnSizeVars, DataTableBodyProps, DataTableLineProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableLine, { DataTableLinesDummy } from './DataTableLine';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import { useDataTableToggle } from '../dataTableHooks';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<MuiTheme, { columnSizeVars: ColumnSizeVars }>(() => createStyles({
  tableContainer: ({ columnSizeVars }) => ({
    ...columnSizeVars,
    height: 'calc(var(--table-height) * 1px)',
    overflowY: 'visible',
  }),
  linesContainer: {
    height: 'calc(var(--table-height, 100%) * 1px - 50px)',
    width: 'calc(var(--col-table-size, 100%) * 1px + 10px)', // 10px is approx. the scrollbar size to prevent alignment issues
    overflowY: 'auto',
    overflowX: 'hidden',
  },
}));

const DataTableBody = ({
  columns,
  redirectionMode,
  storageHelpers,
  settingsMessagesBannerHeight = 0,
  hasFilterComponent,
  sortBy,
  orderAsc,
  dataTableToolBarComponent,
  dataQueryArgs,
  pageStart,
  pageSize,
}: DataTableBodyProps) => {
  const {
    rootRef,
    storageKey,
    setColumns,
    useDataTableLocalStorage,
    variant,
    useDataTable,
    resolvePath,
  } = useDataTableContext();

  const { data: queryData, isLoading, loadMore, hasMore } = useDataTable(dataQueryArgs);

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
  const [resize, setResize] = useState(false);
  const [computeState, setComputeState] = useState<HTMLDivElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [localStorageColumns, setLocalStorageColumns] = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true);

  const startsWithSelect = columns.at(0)?.id === 'select';
  const endsWithNavigate = columns.at(-1)?.id === 'navigate';

  let storedSize = SELECT_COLUMN_SIZE;
  if (startsWithSelect) {
    storedSize += SELECT_COLUMN_SIZE;
  }

  // This is intended to improve performance by memoizing the column sizes
  const columnSizeVars: ColumnSizeVars = React.useMemo(() => {
    const localColumns: LocalStorageColumns = {};
    const colSizes: { [key: string]: number } = {
      '--header-select-size': SELECT_COLUMN_SIZE,
      '--col-select-size': SELECT_COLUMN_SIZE,
      '--header-navigate-size': SELECT_COLUMN_SIZE,
      '--col-navigate-size': SELECT_COLUMN_SIZE,
    };
    const currentRefContainer = containerRef.current;
    if (!computeState && !currentRefContainer) {
      return colSizes;
    }
    // From there, currentRefContainer is not null
    /* eslint-disable @typescript-eslint/no-non-null-assertion */
    const clientWidth = currentRefContainer!.clientWidth - storedSize - 12; // Scrollbar size to prevent alignment issues
    for (let i = startsWithSelect ? 1 : 0; i < columns.length - (endsWithNavigate ? 1 : 0); i += 1) {
      const column = { ...columns[i], ...localStorageColumns[columns[i].id] };
      const shouldCompute = (!column.size || resize || !localStorageColumns[columns[i].id]?.size) && (column.percentWidth && Boolean(computeState));
      let size = column.size ?? 200;

      // We must compute px size for columns
      if (shouldCompute) {
        size = column.percentWidth * (clientWidth / 100);
        column.size = size;
      }
      localColumns[column.id] = { size };
      colSizes[`--header-${column.id}-size`] = size;
      colSizes[`--col-${column.id}-size`] = size;
    }
    if (Object.keys(localColumns).length > 0) {
      setResize(false);
    }
    if (Object.entries(localColumns).some(([id, { size }]) => localStorageColumns[id]?.size !== size)) {
      setLocalStorageColumns(localColumns);
      setColumns((curr) => {
        return curr.map((col) => {
          if (localColumns[col.id]) {
            return { ...col, size: localColumns[col.id].size };
          }
          return col;
        });
      });
    }
    const columnsSize = Object.values(localColumns).reduce((acc, { size }) => acc + size, 0);
    const tableSize = columnsSize + storedSize;
    if (columnsSize > clientWidth) {
      currentRefContainer!.style.overflowX = 'auto';
      currentRefContainer!.style.overflowY = 'hidden';
    } else {
      currentRefContainer!.style.overflow = 'hidden';
    }
    colSizes['--header-table-size'] = tableSize; // 50 is almost the scrollbar size
    colSizes['--col-table-size'] = tableSize;
    if (variant === DataTableVariant.widget) {
      if (!rootRef) {
        throw Error('Invalid configuration for widget list');
      }
      colSizes['--table-height'] = rootRef.offsetHeight + 50;
    } else if (rootRef) {
      colSizes['--table-height'] = rootRef.offsetHeight - 42; // SIZE OF CONTAINER - Nb Elements - Line Size
    } else {
      const rootSize = (document.getElementById('root')?.offsetHeight ?? 0) - settingsMessagesBannerHeight;
      const filterRemoval = (hasFilterComponent && document.getElementById('filter-container')?.children.length) ? 260 : 220;
      const tabsRemoval = document.getElementById('tabs-container')?.children.length ? 50 : 0;
      colSizes['--table-height'] = rootSize - filterRemoval - tabsRemoval;
    }
    /* eslint-enable @typescript-eslint/no-non-null-assertion */

    return colSizes;
  }, [
    resize,
    computeState,
    columns,
    localStorageColumns,
    document.getElementById('filter-container'),
    rootRef,
  ]);
  const classes = useStyles({ columnSizeVars });

  const {
    selectedElements,
    onToggleEntity,
  } = useDataTableToggle(storageKey);
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

  useLayoutEffect(() => {
    const handleResize = () => setResize(true);
    const handleStorage = ({ key }: StorageEvent) => setTimeout(() => {
      if (key === 'navOpen') {
        setResize(true);
      }
    }, 200);

    let observer: MutationObserver | undefined;
    if (hasFilterComponent) {
      window.addEventListener('resize', handleResize);
      window.addEventListener('storage', handleStorage);
      observer = new MutationObserver(() => setResize(true));
      const elementToObserve = document.getElementById('filter-container');
      if (elementToObserve) {
        observer.observe(elementToObserve, { childList: true });
      }
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('storage', handleStorage);
      if (hasFilterComponent && observer) {
        observer.disconnect();
      }
    };
  }, []);
  const effectiveColumns = useMemo(() => columns
    .map((col) => ({ ...col, size: localStorageColumns[col.id]?.size })), [columns, localStorageColumns]);

  return (
    <div
      ref={containerRef}
      className={classes.tableContainer}
      style={{ ...columnSizeVars }}
    >
      {variant !== DataTableVariant.widget && (
        <DataTableHeaders
          containerRef={containerRef}
          effectiveColumns={effectiveColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataTableToolBarComponent={dataTableToolBarComponent}
        />
      )}
      <div
        ref={(node) => setComputeState(node)}
        className={classes.linesContainer}
      >
        {computeState && (
          <>
            {/* If we have perf issues we should find a way to memoize this */}
            {resolvedData.map((row: { id: string }, index: number) => {
              return (
                <DataTableLine
                  key={row.id}
                  row={row}
                  redirectionMode={redirectionMode}
                  storageHelpers={storageHelpers}
                  effectiveColumns={effectiveColumns}
                  index={index}
                  onToggleShiftEntity={onToggleShiftEntity}
                />
              );
            })}
            {isLoading && <DataTableLinesDummy number={pageSize} />}
          </>
        )}
      </div>
    </div>
  );
};

export default DataTableBody;
