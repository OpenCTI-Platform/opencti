import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as R from 'ramda';
import { useAppData } from '../../../utils/hooks/useAppData';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { buildMetricsColumns, defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeaders from './DataTableHeaders';
import { DataTableProvider } from './DataTableContext';
import {
  useDataTableComputeLink,
  useDataCellHelpers,
  useDataTableFormatter,
  useDataTableLocalStorage,
  useDataTablePaginationLocalStorage,
  useDataTableToggle,
} from '../dataTableHooks';
import { getDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { ICON_COLUMN_SIZE, SELECT_COLUMN_SIZE } from './DataTableHeader';
import callbackResizeObserver from '../../../utils/resizeObservers';

type DataTableComponentProps = Pick<DataTableProps,
| 'dataColumns'
| 'settingsMessagesBannerHeight'
| 'filtersComponent'
| 'hideHeaders'
| 'dataTableToolBarComponent'
| 'variant'
| 'actions'
| 'icon'
| 'availableFilterKeys'
| 'initialValues'
| 'disableNavigation'
| 'storageKey'
| 'dataQueryArgs'
| 'resolvePath'
| 'redirectionModeEnabled'
| 'useLineData'
| 'rootRef'
| 'createButton'
| 'disableToolBar'
| 'removeSelectAll'
| 'getComputeLink'
| 'selectOnLineClick'
| 'onLineClick'
| 'data'
| 'emptyStateMessage'
| 'disableLineSelection'
| 'pageSize'
>;

const DataTableComponent = ({
  dataColumns,
  resolvePath,
  storageKey,
  initialValues,
  availableFilterKeys,
  dataQueryArgs,
  data,
  redirectionModeEnabled = false,
  useLineData,
  getComputeLink,
  settingsMessagesBannerHeight,
  filtersComponent,
  hideHeaders,
  dataTableToolBarComponent,
  variant = DataTableVariant.default,
  rootRef,
  actions,
  icon,
  createButton,
  disableNavigation,
  disableLineSelection,
  disableToolBar,
  removeSelectAll,
  selectOnLineClick,
  onLineClick,
  emptyStateMessage,
  pageSize,
}: DataTableComponentProps) => {
  const { metricsDefinition } = useAppData();

  const defaultComputeLink = useDataTableComputeLink();
  const columnsLocalStorage = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true);
  const [localStorageColumns, setLocalStorageColumns] = columnsLocalStorage;

  const paginationLocalStorage = useDataTablePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);
  const {
    viewStorage: { pageSize: viewStoragePageSize },
    helpers,
  } = paginationLocalStorage;

  const getMetricsColumns = () => {
    if (!data || !metricsDefinition || !Array.isArray(data)) return {};

    const entityTypes: string[] = [];
    for (const item of data) {
      if (item.entity_type) {
        if (!entityTypes.includes(item.entity_type)) {
          entityTypes.push(item.entity_type);
        }
      }
    }

    const allMetrics: Record<string, DataTableColumn> = {};
    for (const entityType of entityTypes) {
      const metricsForType = buildMetricsColumns(entityType, metricsDefinition);
      Object.assign(allMetrics, metricsForType);
    }

    return allMetrics;
  };

  const metricsColumns = getMetricsColumns();

  const buildColumns = (withLocalStorage = true) => {
    const allDataColumns = { ...dataColumns, ...metricsColumns };

    const dataColumnsKeys = Object.keys(allDataColumns);
    const localStorageColumnsKeys = Object.keys(localStorageColumns)
      .filter((key) => key !== 'select' && key !== 'navigate' && key !== 'icon');

    // Check if keys order/length is the same
    const isOrderSame = dataColumnsKeys.length === localStorageColumnsKeys.length
      && dataColumnsKeys.every((key, index) => key === localStorageColumnsKeys[index]);

    // Only use localStorage if order matches and we are allowed to
    const useLocalStorage = isOrderSame && withLocalStorage;

    const extendedColumnsMap = new Map(defaultColumnsMap);
    Object.entries(metricsColumns).forEach(([key, value]) => {
      extendedColumnsMap.set(key, value);
    });

    return [
      // Checkbox if necessary
      ...(!disableLineSelection ? [{ id: 'select', visible: true } as DataTableColumn] : []),
      // Icon if necessary
      ...(icon ? [{ id: 'icon', visible: true } as DataTableColumn] : []),
      // Our real columns
      ...Object.entries(dataColumns).map(([key, column], index) => {
        const currentColumn = localStorageColumns?.[key];
        const percentWidth = column.percentWidth ?? extendedColumnsMap.get(key)?.percentWidth;

        return R.mergeDeepRight(extendedColumnsMap.get(key) as DataTableColumn, {
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
  const startsWithIcon = useMemo(() => {
    return !!columns.find((column) => column.id === 'icon');
  }, [columns]);
  const endsWithNavigate = useMemo(() => columns.at(-1)?.id === 'navigate', [columns]);
  const endsWithAction = useMemo(() => endsWithNavigate || !!actions, [endsWithNavigate, actions]);

  // QUERY PART
  const [page, setPage] = useState<number>(1);
  const defaultPageSize = variant === DataTableVariant.default ? 25 : 100;

  let currentPageSize = 0;

  if (pageSize) {
    currentPageSize = Number.parseInt(pageSize, 10);
  } else if (viewStoragePageSize) {
    currentPageSize = Number.parseInt(viewStoragePageSize, 10);
  } else {
    currentPageSize = defaultPageSize;
  }

  const pageStart = useMemo(() => {
    return page ? (page - 1) * currentPageSize : 0;
  }, [page, currentPageSize]);

  const tableWidthState = useState(0);
  const [tableWidth, setTableWidth] = tableWidthState;
  const tableRef = useRef<HTMLDivElement | null>(null);

  const startColumnWidth = useMemo(() => {
    if (startsWithIcon && startsWithAction) {
      return ICON_COLUMN_SIZE + SELECT_COLUMN_SIZE;
    }
    if (startsWithIcon) {
      return ICON_COLUMN_SIZE;
    }
    return SELECT_COLUMN_SIZE;
  }, [startsWithIcon, startsWithAction]);

  // Keep table width up to date.
  useLayoutEffect(() => {
    let observer: ResizeObserver;
    if (tableRef.current) {
      const resize = (el: Element) => {
        let offset = 10;
        if (startsWithAction) offset += SELECT_COLUMN_SIZE;
        if (startsWithIcon) offset += ICON_COLUMN_SIZE;
        if (endsWithAction) offset += SELECT_COLUMN_SIZE;
        if ((el.clientWidth - offset) !== tableWidth) {
          setTableWidth(el.clientWidth - offset);
        }
      };
      resize(tableRef.current);
      observer = callbackResizeObserver(tableRef.current, resize);
    }
    return () => { observer?.disconnect(); };
  }, [tableRef.current, tableWidth, endsWithAction, startsWithAction, startsWithIcon]);

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
        dataQueryArgs,
        data,
        useDataCellHelpers: useDataCellHelpers(helpers, variant),
        useDataTableToggle: useDataTableToggle(storageKey),
        getComputeLink: getComputeLink ?? defaultComputeLink,
        useDataTableColumnsLocalStorage: columnsLocalStorage,
        useDataTablePaginationLocalStorage: paginationLocalStorage,
        onAddFilter: (id) => helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(id)),
        onSort: helpers.handleSort,
        formatter: useDataTableFormatter(),
        variant,
        rootRef,
        actions,
        icon,
        createButton,
        disableNavigation,
        disableToolBar,
        removeSelectAll,
        selectOnLineClick,
        onLineClick,
        disableLineSelection,
        page,
        setPage,
        tableWidthState,
        startsWithAction,
        startsWithIcon,
        startColumnWidth,
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
            emptyStateMessage={emptyStateMessage}
          />
        </React.Suspense>
      </div>
    </DataTableProvider>
  );
};

export default DataTableComponent;
