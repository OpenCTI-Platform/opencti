/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Dispatch, MutableRefObject, ReactNode, SetStateAction } from 'react';
import React from 'react';
import { GraphQLTaggedNode } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover/Popover';
import type { LocalStorage } from '../../utils/hooks/useLocalStorageModel';
import { NumberOfElements, UseLocalStorageHelpers } from '../../utils/hooks/useLocalStorage';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';

export type ColumnSizeVars = Record<string, number>;

export type LocalStorageColumn = { size: number, visible?: boolean, index?: number };
export type LocalStorageColumns = Record<string, LocalStorageColumn>;

export enum DataTableVariant {
  default = 'default',
  inline = 'inline',
  widget = 'widget',
}

export interface UseDataTable<T = any> {
  data: T[]
  hasMore: () => boolean
  loadMore: (count: number, options?: Record<string, any>) => void
  isLoading: boolean
  isLoadingMore: () => boolean
}

export interface DataTableColumn {
  id: string
  isSortable?: boolean
  label?: string
  size?: number
  percentWidth: number
  render?: (v: any, helpers?: any) => ReactNode
  visible?: boolean
  order: number
  lastX?: number
}

export type DataTableColumns = DataTableColumn[];

export interface DataTableContextProps {
  storageKey: string
  columns: DataTableColumns
  availableFilterKeys?: string[] | undefined;
  effectiveColumns: DataTableColumns
  initialValues: DataTableProps['initialValues']
  setColumns: Dispatch<SetStateAction<DataTableColumns>>
  resolvePath: (data: any) => any
  redirectionModeEnabled?: boolean
  toolbarFilters?: FilterGroup
  useLineData: (row: any) => any
  useDataTable: (args: any) => any
  useDataCellHelpers: (cell: DataTableColumn) => any
  useDataTableToggle: (key: string) => {
    selectedElements: Record<string, any>
    deSelectedElements: Record<string, any>
    selectAll: boolean
    numberOfSelectedElements: number
    onToggleEntity: (
      entity: any,
      _?: React.SyntheticEvent,
      forceRemove?: any[],
    ) => void
    handleClearSelectedElements: () => void
    handleToggleSelectAll: () => void
    setSelectedElements: (selectedElements: Record<string, any>) => void
  } | Record<string, any>
  useComputeLink: (entity: any) => string
  useDataTableLocalStorage: <T extends LocalStorage = LocalStorage>(
    key: string,
    initialValues?: T,
    ignoreUri?: boolean,
    ignoreDispatch?: boolean,
  ) => [T, Dispatch<SetStateAction<T>>]
  onAddFilter: (key: string) => void
  onSort: (sortBy: string, orderAsc: boolean) => void
  formatter: Record<string, (args: any) => any>
  variant: DataTableVariant
  actions?: DataTableProps['actions']
  rootRef?: DataTableProps['rootRef']
  createButton?: DataTableProps['createButton']
  resetColumns: () => void
  disableNavigation: DataTableProps['disableNavigation']
  onLineClick: DataTableProps['onLineClick']
}

export interface DataTableProps {
  dataColumns: Record<string, Partial<DataTableColumn>>
  resolvePath: (data: any) => any
  storageKey: string
  initialValues: LocalStorage
  toolbarFilters?: FilterGroup
  lineFragment?: GraphQLTaggedNode
  dataQueryArgs: any
  availableFilterKeys?: string[] | undefined;
  redirectionModeEnabled?: boolean
  additionalFilterKeys?: string[]
  entityTypes?: string[]
  settingsMessagesBannerHeight?: number
  storageHelpers?: UseLocalStorageHelpers
  redirectionMode?: string | undefined
  filtersComponent?: ReactNode
  dataTableToolBarComponent?: ReactNode
  numberOfElements?: NumberOfElements
  onAddFilter?: DataTableContextProps['onAddFilter']
  onSort?: (sortBy: string, orderAsc: boolean) => void
  formatter: DataTableContextProps['formatter']
  useDataTableLocalStorage: DataTableContextProps['useDataTableLocalStorage']
  useComputeLink: DataTableContextProps['useComputeLink']
  useDataTableToggle: DataTableContextProps['useDataTableToggle']
  useLineData: DataTableContextProps['useLineData']
  useDataTable: DataTableContextProps['useDataTable']
  useDataCellHelpers: DataTableContextProps['useDataCellHelpers']
  sortBy?: string | undefined
  orderAsc?: boolean | undefined
  variant?: DataTableVariant
  rootRef?: HTMLDivElement
  actions?: (row: any) => ReactNode
  createButton?: ReactNode
  pageSize?: string
  disableNavigation?: boolean
  onLineClick?: (line: any) => void
}

export interface DataTableBodyProps {
  columns: DataTableColumns
  redirectionMode: DataTableProps['redirectionMode']
  storageHelpers: DataTableProps['storageHelpers']
  hasFilterComponent: boolean
  dataTableToolBarComponent?: ReactNode
  sortBy: DataTableProps['sortBy']
  orderAsc: DataTableProps['orderAsc']
  settingsMessagesBannerHeight?: DataTableProps['settingsMessagesBannerHeight']
  dataQueryArgs: DataTableProps['dataQueryArgs']
  pageSize: number
  pageStart: number
}

export interface DataTableDisplayFiltersProps {
  entityTypes?: string[]
  additionalFilterKeys?: string[]
  availableRelationFilterTypes?: Record<string, string[]> | undefined
  availableFilterKeys?: string[] | undefined;
  paginationOptions: any
}

export interface DataTableFiltersProps {
  availableFilterKeys?: string[] | undefined;
  availableRelationFilterTypes?: Record<string, string[]> | undefined
  availableEntityTypes?: string[]
  availableRelationshipTypes?: string[]
  searchContextFinal?: { entityTypes: string[]; elementId?: string[] | undefined; } | undefined
  exportContext?: { entity_type: string, entity_id?: string }
  paginationOptions: any
  currentView?: string
  additionalHeaderButtons?: ReactNode[]
}

export interface DataTableHeadersProps {
  containerRef?: MutableRefObject<HTMLDivElement | null>
  effectiveColumns: DataTableColumns
  sortBy: DataTableProps['sortBy']
  orderAsc: DataTableProps['orderAsc']
  dataTableToolBarComponent: ReactNode
}

export interface DataTableHeaderProps {
  column: DataTableColumn
  setAnchorEl: Dispatch<SetStateAction<PopoverProps['anchorEl']>>
  setActiveColumn: Dispatch<SetStateAction<DataTableColumn | undefined>>
  setLocalStorageColumns: Dispatch<SetStateAction<LocalStorageColumns>>
  containerRef?: MutableRefObject<HTMLDivElement | null>
  sortBy: boolean
  orderAsc: boolean
}

export interface DataTableLineProps {
  row: any
  redirectionMode?: string | undefined
  effectiveColumns: DataTableColumns
  storageHelpers: DataTableProps['storageHelpers']
  index: number
  onToggleShiftEntity: (currentIndex: number, currentEntity: { id: string }, event?: React.SyntheticEvent) => void
}

export interface DataTableCellProps {
  cell: DataTableColumn
  data: any
  storageHelpers: DataTableProps['storageHelpers']
}
