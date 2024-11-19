import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { Theme as MuiTheme } from '@mui/material/styles/createTheme';
import * as R from 'ramda';
import DataTableHeaders from './DataTableHeaders';
import { ColumnSizeVars, DataTableBodyProps, DataTableLineProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableLine, { DataTableLinesDummy } from './DataTableLine';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import { throttle } from '../../../utils/utils';
import { useDataTableContext } from './DataTableContext';

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
    width: 'calc(var(--col-table-size, 100%) * 1px)', // 10px is approx. the scrollbar size to prevent alignment issues
    overflowY: 'auto',
    overflowX: 'hidden',
  },
}));

const DataTableBody = ({
  columns,
  settingsMessagesBannerHeight = 0,
  hasFilterComponent,
  dataTableToolBarComponent,
  pageStart,
  pageSize,
  setReset,
  reset = false,
  hideHeaders = false,
}: DataTableBodyProps) => {
  const {
    rootRef,
    setColumns,
    useDataTableColumnsLocalStorage,
    variant,
    useDataTable,
    resolvePath,
    useDataTableToggle,
    actions,
  } = useDataTableContext();

  const { data: queryData, isLoading, loadMore, hasMore } = useDataTable;

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
  const resizeObserver = useRef(new ResizeObserver(throttle(() => {
    setResize(true);
  }, 200)));
  const [computeState, setComputeState] = useState<HTMLDivElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [localStorageColumns, setLocalStorageColumns] = useDataTableColumnsLocalStorage;

  const startsWithSelect = columns.at(0)?.id === 'select';
  const endsWithNavigate = columns.at(-1)?.id === 'navigate';

  let storedSize = (endsWithNavigate || actions) ? SELECT_COLUMN_SIZE : 0;
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
    const clientWidth = currentRefContainer!.clientWidth - storedSize - 10; // Scrollbar size to prevent alignment issues
    for (let i = startsWithSelect ? 1 : 0; i < columns.length - (endsWithNavigate ? 1 : 0); i += 1) {
      const column = reset ? columns[i] : { ...columns[i], ...localStorageColumns[columns[i].id] };
      const shouldCompute = (!column.size || resize || !localStorageColumns[columns[i].id]?.size) && (column.percentWidth && Boolean(computeState));
      let size = column.size ?? 200;

      // We must compute px size for columns
      if (shouldCompute || reset) {
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

    // Dirty fix for tables with mismatch size
    // Will be remove when rework by Landry
    if (tableSize < clientWidth) {
      setResize(true);
    }

    if (columnsSize > clientWidth) {
      currentRefContainer!.style.overflowX = 'auto';
      currentRefContainer!.style.overflowY = 'hidden';
    } else {
      currentRefContainer!.style.overflow = 'hidden';
    }
    colSizes['--header-table-size'] = tableSize + 10;
    colSizes['--col-table-size'] = tableSize + 10;
    if (variant === DataTableVariant.widget) {
      if (!rootRef) {
        throw Error('Invalid configuration for widget list');
      }
      colSizes['--table-height'] = rootRef.offsetHeight;
    } else if (rootRef) {
      colSizes['--table-height'] = rootRef.offsetHeight - 42; // SIZE OF CONTAINER - Nb Elements - Line Size
    } else {
      const rootSize = (document.getElementById('root')?.offsetHeight ?? 0) - settingsMessagesBannerHeight;
      const filterRemoval = (hasFilterComponent && document.getElementById('filter-container')?.children.length) ? 230 : 200;
      const tabsRemoval = document.getElementById('tabs-container')?.children.length ? 50 : 0;
      colSizes['--table-height'] = rootSize - filterRemoval - tabsRemoval;
    }
    /* eslint-enable @typescript-eslint/no-non-null-assertion */

    setReset(false);
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
  } = useDataTableToggle;
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

    window.addEventListener('resize', handleResize);
    window.addEventListener('storage', handleStorage);
    if (rootRef) resizeObserver.current.observe(rootRef);
    let observer: MutationObserver | undefined;
    const elementToObserve = document.getElementById('filter-container');
    if (elementToObserve) {
      observer = new MutationObserver(() => setResize(true));
      observer.observe(elementToObserve, { childList: true });
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('storage', handleStorage);
      resizeObserver.current.disconnect();
      if (hasFilterComponent && observer) {
        observer.disconnect();
      }
    };
  }, []);
  const effectiveColumns = useMemo(() => columns
    .map((col) => ({ ...col, size: localStorageColumns[col.id]?.size })), [columns, localStorageColumns, reset]);

  return (
    <div
      ref={containerRef}
      className={classes.tableContainer}
      style={{ ...columnSizeVars }}
    >
      {!hideHeaders && (
        <DataTableHeaders
          containerRef={containerRef}
          effectiveColumns={effectiveColumns}
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
                  effectiveColumns={effectiveColumns}
                  index={index}
                  onToggleShiftEntity={onToggleShiftEntity}
                />
              );
            })}
            {isLoading && <DataTableLinesDummy number={Math.max(pageSize, 25)} />}
          </>
        )}
      </div>
    </div>
  );
};

export default DataTableBody;
