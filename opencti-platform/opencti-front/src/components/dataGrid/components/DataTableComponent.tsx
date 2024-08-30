import React, { useMemo, useState } from 'react';
import * as R from 'ramda';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { DataTableContext, defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableColumns, DataTableContextProps, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeaders from './DataTableHeaders';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import DataTablePagination from '../DataTablePagination';

const DataTableComponent = ({
  dataColumns,
  resolvePath,
  storageKey,
  initialValues,
  availableFilterKeys,
  toolbarFilters,
  dataQueryArgs,
  redirectionModeEnabled = false,
  useLineData,
  useDataTable,
  useDataCellHelpers,
  useDataTableToggle,
  useComputeLink,
  useDataTableLocalStorage,
  formatter,
  settingsMessagesBannerHeight,
  storageHelpers,
  filtersComponent,
  redirectionMode,
  numberOfElements,
  onAddFilter,
  onSort,
  sortBy,
  orderAsc,
  dataTableToolBarComponent,
  variant = DataTableVariant.default,
  rootRef,
  actions,
  createButton,
  pageSize,
  disableNavigation,
  onLineClick,
}: DataTableProps) => {
  const localStorageColumns = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true)[0];
  const toggleHelper = useDataTableToggle(storageKey);

  const columnsInitialState = [
    ...(toggleHelper.onToggleEntity ? [{ id: 'select', visible: true } as DataTableColumn] : []),
    ...Object.entries(dataColumns).map(([key, column], index) => {
      const currentColumn = localStorageColumns?.[key];
      return R.mergeDeepRight(defaultColumnsMap.get(key) as DataTableColumn, {
        ...column,
        order: currentColumn?.index ?? index,
        visible: currentColumn?.visible ?? true,
        ...(currentColumn?.size ? { size: currentColumn?.size } : {}),
      });
    }),
    ...(actions ? [] : [{ id: 'navigate', visible: true } as DataTableColumn]),
  ];

  const [columns, setColumns] = useState<DataTableColumns>(columnsInitialState);

  const clientWidth = document.getElementsByTagName('main')[0].clientWidth - 46;

  const temporaryColumnsSize: { [key: string]: number } = {
    '--header-select-size': SELECT_COLUMN_SIZE,
    '--col-select-size': SELECT_COLUMN_SIZE,
    '--header-navigate-size': SELECT_COLUMN_SIZE,
    '--col-navigate-size': SELECT_COLUMN_SIZE,
    '--header-table-size': clientWidth,
    '--col-table-size': clientWidth,
  };
  columns.forEach((col) => {
    if (col.visible && col.percentWidth) {
      const size = col.percentWidth * (clientWidth / 100);
      temporaryColumnsSize[`--header-${col.id}-size`] = size;
      temporaryColumnsSize[`--col-${col.id}-size`] = size;
    }
  });

  // QUERY PART
  const [page, setPage] = useState<number>(1);
  const currentPageSize = pageSize ? Number.parseInt(pageSize, 10) : 25;
  const pageStart = useMemo(() => {
    return page ? (page - 1) * currentPageSize : 0;
  }, [page, currentPageSize]);

  return (
    <DataTableContext.Provider
      value={{
        storageKey,
        columns,
        availableFilterKeys,
        effectiveColumns: columns.filter(({ visible }) => visible).sort((a, b) => a.order - b.order),
        initialValues,
        setColumns,
        resetColumns: () => setColumns(columnsInitialState),
        resolvePath,
        redirectionModeEnabled,
        toolbarFilters,
        useLineData,
        useDataTable,
        useDataCellHelpers,
        useDataTableToggle,
        useComputeLink,
        useDataTableLocalStorage,
        onAddFilter,
        onSort,
        formatter,
        variant,
        rootRef,
        actions,
        createButton,
        disableNavigation,
        onLineClick,
      } as DataTableContextProps}
    >
      {filtersComponent ?? (variant === DataTableVariant.inline && (
        <div
          style={{
            width: '100%',
            textAlign: 'right',
            marginBottom: 10,
          }}
        >
          <strong>{`${numberOfElements?.number}${numberOfElements?.symbol}`}</strong>{' '}
          {formatter.t_i18n('entitie(s)')}
        </div>
      ))}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {(variant === DataTableVariant.default) && (
          <DataTablePagination
            page={page}
            setPage={setPage}
            numberOfElements={numberOfElements}
          />
        )}
        <React.Suspense
          fallback={(
            <div style={{ ...temporaryColumnsSize, width: '100%' }}>
              <DataTableHeaders
                effectiveColumns={columns}
                sortBy={sortBy}
                orderAsc={orderAsc}
                dataTableToolBarComponent={dataTableToolBarComponent}
              />
              {<DataTableLinesDummy number={currentPageSize} />}
            </div>
          )}
        >
          <DataTableBody
            dataQueryArgs={dataQueryArgs}
            columns={columns.filter(({ visible }) => visible)}
            redirectionMode={redirectionMode}
            storageHelpers={storageHelpers}
            settingsMessagesBannerHeight={settingsMessagesBannerHeight}
            hasFilterComponent={!!filtersComponent}
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataTableToolBarComponent={dataTableToolBarComponent}
            pageStart={pageStart}
            pageSize={currentPageSize}
          />
        </React.Suspense>
      </div>
    </DataTableContext.Provider>
  );
};

export default DataTableComponent;
