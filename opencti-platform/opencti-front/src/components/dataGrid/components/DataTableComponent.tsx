import React, { useEffect, useMemo, useState } from 'react';
import * as R from 'ramda';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeaders from './DataTableHeaders';
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
  const [localStorageColumns, setLocalStorageColumns] = columnsLocalStorage;

  const paginationLocalStorage = useDataTablePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);
  const {
    viewStorage: { pageSize },
    helpers,
  } = paginationLocalStorage;

  const buildColumns = (withLocalStorage = true) => {
    return [
      // Checkbox if necessary
      ...(canToggleLine && !disableLineSelection ? [{ id: 'select', visible: true } as DataTableColumn] : []),
      // Our real columns
      ...Object.entries(dataColumns).map(([key, column], index) => {
        const currentColumn = localStorageColumns?.[key];
        let percentWidth = column.percentWidth ?? defaultColumnsMap.get(key)?.percentWidth;
        if (withLocalStorage && currentColumn?.percentWidth) percentWidth = currentColumn?.percentWidth;
        return R.mergeDeepRight(defaultColumnsMap.get(key) as DataTableColumn, {
          ...column,
          // Override column config with what we have in local storage
          order: withLocalStorage && currentColumn?.index ? currentColumn?.index : index,
          visible: withLocalStorage && currentColumn?.visible ? currentColumn?.visible : true,
          percentWidth,
        });
      }),
      // inject "navigate" action (chevron) if navigable and no specific actions defined
      ...((disableNavigation || actions) ? [] : [{ id: 'navigate', visible: true } as DataTableColumn]),
    ].sort((a, b) => a.order - b.order);
  };

  const [columns, setColumns] = useState(buildColumns());
  useEffect(() => {
    setLocalStorageColumns((curr) => {
      const cols = { ...curr };
      columns.forEach((c) => {
        cols[c.id] = {
          ...cols[c.id],
          percentWidth: c.percentWidth,
          visible: c.visible,
          index: c.order,
        };
      });
      return cols;
    });
  }, [columns]);

  // QUERY PART
  const [page, setPage] = useState<number>(1);
  const defaultPageSize = variant === DataTableVariant.default ? 25 : 100;
  const currentPageSize = pageSize ? Number.parseInt(pageSize, 10) : defaultPageSize;
  const pageStart = useMemo(() => {
    return page ? (page - 1) * currentPageSize : 0;
  }, [page, currentPageSize]);

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
      {filtersComponent && <div>{filtersComponent}</div>}
      <>
        <React.Suspense
          fallback={(
            <div style={{ width: '100%' }}>
              <DataTableHeaders dataTableToolBarComponent={dataTableToolBarComponent} />
              {<DataTableLinesDummy number={Math.max(currentPageSize, 25)} />}
            </div>
          )}
        >
          <DataTableBody
            settingsMessagesBannerHeight={settingsMessagesBannerHeight}
            hasFilterComponent={!!filtersComponent}
            dataTableToolBarComponent={dataTableToolBarComponent}
            pageStart={pageStart}
            pageSize={currentPageSize}
            hideHeaders={hideHeaders}
          />
        </React.Suspense>
      </>
    </DataTableProvider>
  );
};

export default DataTableComponent;
