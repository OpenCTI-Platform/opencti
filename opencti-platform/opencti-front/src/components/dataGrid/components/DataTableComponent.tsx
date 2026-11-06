import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as R from 'ramda';
import { useAppData } from '../../../utils/hooks/useAppData';
import { DataTableLinesDummy } from './DataTableLine';
import DataTableBody from './DataTableBody';
import { buildMetricsColumns, defaultColumnsMap } from '../dataTableUtils';
import { DataTableColumn, DataTableColumns, DataTableProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
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
import { computeVisibleWidthRatio, isSameListColumnConfig, legacyListColumnConfig, ListColumnConfig, toListColumnConfig } from '../dataTableColumnsConfig';
import useListColumnsPreference from '../useListColumnsPreference';

type DataTableComponentProps = Pick<DataTableProps,
  | 'dataColumns'
  | 'availableColumns'
  | 'columnsScopeLabel'
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
  | 'disableColumnMenu'
  | 'removeSelectAll'
  | 'getComputeLink'
  | 'selectOnLineClick'
  | 'onLineClick'
  | 'onSort'
  | 'data'
  | 'emptyStateMessage'
  | 'disableLineSelection'
  | 'pageSize'
  | 'actionsColumnWidth'
  | 'enableInfiniteScroll'
  | 'searchTerm'
>;

const DataTableComponent = ({
  dataColumns,
  availableColumns,
  columnsScopeLabel,
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
  disableColumnMenu,
  removeSelectAll,
  selectOnLineClick,
  onLineClick,
  onSort,
  emptyStateMessage,
  searchTerm,
  pageSize,
  actionsColumnWidth,
  enableInfiniteScroll = false,
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

  const defaultColumnIds = Object.keys(dataColumns);
  // Every column that can be displayed, completed with its registered definition (label, rendering...).
  const columnsCatalog = useMemo(() => Object.fromEntries(
    Object.entries({ ...availableColumns, ...dataColumns })
      .map(([id, column]) => [id, { ...defaultColumnsMap.get(id), ...column }]),
  ), [availableColumns, dataColumns]);

  // Default lists keep their columns in the user profile, other ones (e.g. widgets) only in the browser.
  const { savedConfig, saveConfig, isEnabled: isProfileEnabled } = useListColumnsPreference(storageKey, variant === DataTableVariant.default);
  // Configuration currently displayed: it is the reference when the columns are rebuilt,
  // as the profile and the browser storage are only updated afterwards.
  const currentConfig = useRef<ListColumnConfig[] | undefined>(undefined);
  // Columns of the last display, to only save the changes.
  const displayedConfig = useRef<ListColumnConfig[] | undefined>(undefined);

  const getDefaultPercentWidth = (key: string) => {
    const column = columnsCatalog[key] ?? {};
    return column.percentWidth ?? defaultColumnsMap.get(key)?.percentWidth ?? metricsColumns[key]?.percentWidth ?? 10;
  };

  const buildColumns = (withStoredConfig = true): DataTableColumns => {
    const extendedColumnsMap = new Map(defaultColumnsMap);
    Object.entries(metricsColumns).forEach(([key, value]) => {
      extendedColumnsMap.set(key, value);
    });

    const storedConfig = withStoredConfig
      ? currentConfig.current ?? savedConfig ?? legacyListColumnConfig(localStorageColumns, defaultColumnIds)
      : undefined;
    // An attribute that no longer exists (e.g. a deleted custom field) is ignored,
    // and a default column the configuration does not know yet is displayed at the end.
    const configuredColumns: (ListColumnConfig | { id: string })[] = storedConfig
      ? [
          ...storedConfig.filter(({ id }) => !!columnsCatalog[id]),
          ...defaultColumnIds.filter((id) => !storedConfig.some((c) => c.id === id)).map((id) => ({ id })),
        ]
      : defaultColumnIds.map((id) => ({ id }));

    return [
      // Checkbox if necessary
      ...(!disableLineSelection ? [{ id: 'select', visible: true } as DataTableColumn] : []),
      // Icon if necessary
      ...(icon ? [{ id: 'icon', visible: true } as DataTableColumn] : []),
      // Our real columns
      ...configuredColumns.map((config, index) => {
        const { id: key } = config;
        const stored = 'visible' in config ? config : undefined;
        return R.mergeDeepRight((extendedColumnsMap.get(key) ?? {}) as DataTableColumn, {
          ...columnsCatalog[key],
          id: key,
          order: index,
          visible: stored?.visible ?? true,
          percentWidth: stored?.percentWidth ?? getDefaultPercentWidth(key),
        }) as DataTableColumn;
      }),
      // inject "navigate" action (chevron) if navigable and no specific actions defined
      ...((disableNavigation || actions) ? [] : [{ id: 'navigate', visible: true } as DataTableColumn]),
    ];
  };

  const [columns, setColumns] = useState(() => buildColumns());

  useEffect(() => {
    const updatedColumns = buildColumns();
    setColumns(updatedColumns);
  }, [dataColumns, availableColumns]);

  const defaultConfig = useMemo(() => toListColumnConfig(buildColumns(false)), [dataColumns, availableColumns]);
  const isColumnsCustomized = !isSameListColumnConfig(toListColumnConfig(columns), defaultConfig);

  useEffect(() => {
    const config = toListColumnConfig(columns);
    // Columns displayed before this change: on the first display, the saved ones (or the default ones).
    const previousConfig = displayedConfig.current ?? savedConfig ?? defaultConfig;
    displayedConfig.current = config;
    currentConfig.current = config;
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
    // Only a change of the columns is saved: the list being displayed again (e.g. in another tab after
    // the profile changed) must not overwrite the profile with its own columns.
    if (isProfileEnabled && !isSameListColumnConfig(config, previousConfig)) {
      // The default view is not saved: the list then follows the future default columns.
      saveConfig(isSameListColumnConfig(config, defaultConfig) ? undefined : config);
    }
  }, [columns]);

  const applyColumnsSelection = (selection: { id: string; visible: boolean }[]) => {
    currentConfig.current = selection
      .filter(({ id }) => !!columnsCatalog[id])
      .map(({ id, visible }) => ({
        id,
        visible,
        percentWidth: columns.find((c) => c.id === id)?.percentWidth ?? getDefaultPercentWidth(id),
      }));
    setColumns(buildColumns());
  };

  const resetColumns = () => {
    currentConfig.current = undefined;
    setColumns(buildColumns(false));
  };

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

  const [tableWidth, setTableWidth] = useState(0);
  // Visible columns fill the table width, even when some columns are hidden.
  const visibleWidthRatio = useMemo(() => computeVisibleWidthRatio(columns), [columns]);
  const [visibleWidth, setVisibleWidth] = useState(0);
  const tableRef = useRef<HTMLDivElement | null>(null);

  const endActionsWidth = actionsColumnWidth ?? SELECT_COLUMN_SIZE;
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
        if (endsWithAction) offset += endActionsWidth;
        if ((el.clientWidth - offset) !== tableWidth) {
          setTableWidth(el.clientWidth - offset);
        }
        setVisibleWidth(el.clientWidth);
      };
      resize(tableRef.current);
      observer = callbackResizeObserver(tableRef.current, resize);
    }
    return () => {
      observer?.disconnect();
    };
  }, [tableRef.current, tableWidth, endActionsWidth, endsWithAction, startsWithAction, startsWithIcon]);

  return (
    <DataTableProvider
      initialValue={{
        storageKey,
        columns,
        availableFilterKeys,
        initialValues,
        setColumns,
        resetColumns,
        columnsCatalog,
        defaultColumnIds,
        lockedColumnId: defaultColumnIds[0],
        isColumnsCustomized,
        applyColumnsSelection,
        columnsScopeLabel,
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
        onSort: onSort ?? helpers.handleSort,
        formatter: useDataTableFormatter(),
        variant,
        rootRef,
        actions,
        icon,
        createButton,
        disableNavigation,
        disableToolBar,
        disableColumnMenu,
        removeSelectAll,
        selectOnLineClick,
        onLineClick,
        disableLineSelection,
        page,
        setPage,
        tableWidthState: [Math.round(tableWidth * visibleWidthRatio), setTableWidth],
        visibleWidth,
        startsWithAction,
        startsWithIcon,
        startColumnWidth,
        endsWithAction,
        endsWithNavigate,
        actionsColumnWidth: endActionsWidth,
        enableInfiniteScroll,
      }}
    >
      {filtersComponent && <div>{filtersComponent}</div>}
      <div
        role="grid"
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
            searchTerm={searchTerm}
          />
        </React.Suspense>
      </div>
    </DataTableProvider>
  );
};

export default DataTableComponent;
