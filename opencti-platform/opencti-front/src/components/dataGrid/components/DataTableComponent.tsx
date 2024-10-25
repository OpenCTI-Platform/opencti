import React, { useMemo, useRef, useState } from 'react';
import * as R from 'ramda';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableColumns, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeaders from './DataTableHeaders';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import { DataTableProvider } from './DataTableContext';
import { useComputeLink, useDataCellHelpers, useDataTableFormatter, useDataTableLocalStorage, useDataTablePaginationLocalStorage, useDataTableToggle } from '../dataTableHooks';
import { getDefaultFilterObject } from '../../../utils/filters/filtersUtils';

type DataTableComponentProps = Pick<DataTableProps,
| 'dataColumns'
| 'settingsMessagesBannerHeight'
| 'filtersComponent'
| 'hideHeaders'
| 'dataTableToolBarComponent'
| 'variant'
| 'actions'
| 'availableFilterKeys'
| 'initialValues'
| 'disableNavigation'
| 'storageKey'
| 'dataQueryArgs'
| 'resolvePath'
| 'redirectionModeEnabled'
| 'useLineData'
| 'useDataTable'
| 'rootRef'
| 'createButton'
| 'disableToolBar'
| 'disableSelectAll'
| 'selectOnLineClick'
| 'onLineClick'
| 'canToggleLine'
| 'disableLineSelection'>;

const DataTableComponent = ({
  dataColumns,
  resolvePath,
  storageKey,
  initialValues,
  availableFilterKeys,
  dataQueryArgs,
  redirectionModeEnabled = false,
  useLineData,
  useDataTable,
  settingsMessagesBannerHeight,
  filtersComponent,
  hideHeaders,
  dataTableToolBarComponent,
  variant = DataTableVariant.default,
  rootRef,
  actions,
  createButton,
  disableNavigation,
  disableLineSelection,
  disableToolBar,
  disableSelectAll,
  selectOnLineClick,
  onLineClick,
  canToggleLine = true,
}: DataTableComponentProps) => {
  const columnsLocalStorage = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true);
  const [localStorageColumns] = columnsLocalStorage;

  const paginationLocalStorage = useDataTablePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);
  const {
    viewStorage: {
      redirectionMode,
      sortBy,
      orderAsc,
      pageSize,
    },
    helpers,
  } = paginationLocalStorage;

  const columnsInitialState = [
    ...(canToggleLine && !disableLineSelection ? [{ id: 'select', visible: true } as DataTableColumn] : []),
    ...Object.entries(dataColumns).map(([key, column], index) => {
      const currentColumn = localStorageColumns?.[key];
      return R.mergeDeepRight(defaultColumnsMap.get(key) as DataTableColumn, {
        ...column,
        order: currentColumn?.index ?? index,
        visible: currentColumn?.visible ?? true,
        ...(currentColumn?.size ? { size: currentColumn?.size } : {}),
      });
    }),
    // inject "navigate" action (chevron) if navigable and no specific actions defined
    ...((disableNavigation || actions) ? [] : [{ id: 'navigate', visible: true } as DataTableColumn]),
  ];

  const [columns, setColumns] = useState<DataTableColumns>(columnsInitialState);

  // main tag only exists in the app, we fallback to root element for public dashboards
  const mainElement = document.getElementsByTagName('main')[0];
  const rootElement = document.getElementById('root');
  const clientWidth = (mainElement ?? rootElement).clientWidth - 46;

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
      const size = col.percentWidth * ((clientWidth - 2 * SELECT_COLUMN_SIZE) / 100) - 2; // 2 is spacing
      temporaryColumnsSize[`--header-${col.id}-size`] = size;
      temporaryColumnsSize[`--col-${col.id}-size`] = size;
    }
  });

  // QUERY PART
  const [page, setPage] = useState<number>(1);
  const defaultPageSize = variant === DataTableVariant.default ? 25 : 100;
  const currentPageSize = pageSize ? Number.parseInt(pageSize, 10) : defaultPageSize;
  const pageStart = useMemo(() => {
    return page ? (page - 1) * currentPageSize : 0;
  }, [page, currentPageSize]);

  const dataTableHeaderRef = useRef<HTMLDivElement | null>(null);

  const [reset, setReset] = useState(false);

  return (
    <DataTableProvider
      initialValue={{
        storageKey,
        columns,
        availableFilterKeys,
        effectiveColumns: columns.filter(({ visible }) => visible).sort((a, b) => a.order - b.order),
        initialValues,
        setColumns,
        resetColumns: () => setReset(true),
        resolvePath,
        redirectionModeEnabled,
        useLineData,
        useDataTable: useDataTable(dataQueryArgs),
        useDataCellHelpers: useDataCellHelpers(helpers, variant),
        useDataTableToggle: useDataTableToggle(storageKey),
        useComputeLink,
        useDataTableColumnsLocalStorage: columnsLocalStorage,
        useDataTablePaginationLocalStorage: paginationLocalStorage,
        onAddFilter: (id) => helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(id)),
        onSort: helpers.handleSort,
        formatter: useDataTableFormatter(),
        variant,
        rootRef,
        actions,
        createButton,
        disableNavigation,
        disableToolBar,
        disableSelectAll,
        selectOnLineClick,
        onLineClick,
        page,
        setPage,
      }}
    >
      <div ref={dataTableHeaderRef}>
        {filtersComponent}
      </div>
      <>
        <React.Suspense
          fallback={(
            <div style={{ ...temporaryColumnsSize, width: '100%' }}>
              <DataTableHeaders
                effectiveColumns={columns}
                sortBy={sortBy}
                orderAsc={orderAsc}
                dataTableToolBarComponent={dataTableToolBarComponent}
              />
              {<DataTableLinesDummy number={Math.max(currentPageSize, 25)} />}
            </div>
          )}
        >
          <DataTableBody
            columns={columns.filter(({ visible }) => visible)}
            redirectionMode={redirectionMode}
            storageHelpers={helpers}
            settingsMessagesBannerHeight={settingsMessagesBannerHeight}
            hasFilterComponent={!!filtersComponent}
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataTableToolBarComponent={dataTableToolBarComponent}
            pageStart={pageStart}
            pageSize={currentPageSize}
            dataTableHeaderRef={dataTableHeaderRef}
            reset={reset}
            setReset={setReset}
            hideHeaders={hideHeaders}
          />
        </React.Suspense>
      </>
    </DataTableProvider>
  );
};

export default DataTableComponent;
