import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as R from 'ramda';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeaders from './DataTableHeaders';
import { DataTableProvider } from './DataTableContext';
import {
  useDataTableComputeLink as defaultComputeLink,
  useDataCellHelpers,
  useDataTableFormatter,
  useDataTableLocalStorage,
  useDataTablePaginationLocalStorage,
  useDataTableToggle,
} from '../dataTableHooks';
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
| 'useComputeLink'
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
  useComputeLink,
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
  const [localStorageColumns, setLocalStorageColumns] = columnsLocalStorage;

  const paginationLocalStorage = useDataTablePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);
  const {
    viewStorage: { pageSize },
    helpers,
  } = paginationLocalStorage;

  const buildColumns = (withLocalStorage = true) => {
    const dataColumnsKeys = Object.keys(dataColumns);
    const localStorageColumnsKeys = Object.keys(localStorageColumns)
      .filter((key) => key !== 'select' && key !== 'navigate');

    // Check if keys order/length is the same
    const isOrderSame = dataColumnsKeys.length === localStorageColumnsKeys.length
      && dataColumnsKeys.every((key, index) => key === localStorageColumnsKeys[index]);

    // Only use localStorage if order matches and we are allowed to
    const useLocalStorage = isOrderSame && withLocalStorage;

    return [
      // Checkbox if necessary
      ...(canToggleLine && !disableLineSelection ? [{ id: 'select', visible: true } as DataTableColumn] : []),
      // Our real columns
      ...Object.entries(dataColumns).map(([key, column], index) => {
        const currentColumn = localStorageColumns?.[key];
        const percentWidth = column.percentWidth ?? defaultColumnsMap.get(key)?.percentWidth;

        return R.mergeDeepRight(defaultColumnsMap.get(key) as DataTableColumn, {
          ...column,
          // Override column config with what we have in local storage
          order: useLocalStorage && currentColumn?.index ? currentColumn?.index : index,
          visible: useLocalStorage && currentColumn?.visible ? currentColumn?.visible : true,
          percentWidth: useLocalStorage && currentColumn?.percentWidth ? currentColumn?.percentWidth : percentWidth,
        });
      }),
      // inject "navigate" action (chevron) if navigable and no specific actions defined
      ...((disableNavigation || actions) ? [] : [{ id: 'navigate', visible: true } as DataTableColumn]),
    ].sort((a, b) => a.order - b.order);
  };

  const [columns, setColumns] = useState(() => buildColumns());

  useEffect(() => {
    const updatedColumns = buildColumns();
    setColumns(updatedColumns);
  }, [dataColumns]);

  useEffect(() => {
    setLocalStorageColumns((curr) => {
      return columns.reduce((acc, c) => {
        acc[c.id] = {
          ...curr[c.id],
          percentWidth: c.percentWidth,
          visible: c.visible,
          index: c.order,
        };
        return acc;
      }, {} as LocalStorageColumns);
    });
  }, [columns]);

  const startsWithAction = useMemo(() => columns.at(0)?.id === 'select', [columns]);
  const endsWithNavigate = useMemo(() => columns.at(-1)?.id === 'navigate', [columns]);
  const endsWithAction = useMemo(() => endsWithNavigate || !!actions, [endsWithNavigate, actions]);

  // QUERY PART
  const [page, setPage] = useState<number>(1);
  const defaultPageSize = variant === DataTableVariant.default ? 25 : 100;
  const currentPageSize = pageSize ? Number.parseInt(pageSize, 10) : defaultPageSize;
  const pageStart = useMemo(() => {
    return page ? (page - 1) * currentPageSize : 0;
  }, [page, currentPageSize]);

  const tableWidthState = useState(0);
  const tableRef = useRef<HTMLDivElement | null>(null);

  return (
    <DataTableProvider
      initialValue={{
        storageKey,
        columns,
        availableFilterKeys,
        initialValues,
        setColumns,
        resetColumns: () => setColumns(buildColumns(false)),
        resolvePath,
        redirectionModeEnabled,
        useLineData,
        useDataTable: useDataTable(dataQueryArgs),
        useDataCellHelpers: useDataCellHelpers(helpers, variant),
        useDataTableToggle: useDataTableToggle(storageKey),
        useComputeLink: useComputeLink ?? defaultComputeLink,
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
        tableWidthState,
        startsWithAction,
        endsWithAction,
        endsWithNavigate,
      }}
    >
      {filtersComponent && <div>{filtersComponent}</div>}
      <div
        className="datatable-container"
        style={{ width: '100%', overflow: 'auto hidden' }}
        ref={tableRef}
      >
        <React.Suspense
          fallback={(
            <>
              <DataTableHeaders dataTableToolBarComponent={dataTableToolBarComponent} />
              <DataTableLinesDummy number={Math.max(currentPageSize, 10)} />
            </>
          )}
        >
          <DataTableBody
            settingsMessagesBannerHeight={settingsMessagesBannerHeight}
            hasFilterComponent={!!filtersComponent}
            dataTableToolBarComponent={dataTableToolBarComponent}
            pageStart={pageStart}
            pageSize={currentPageSize}
            hideHeaders={hideHeaders}
            tableRef={tableRef}
          />
        </React.Suspense>
      </div>
    </DataTableProvider>
  );
};

export default DataTableComponent;
