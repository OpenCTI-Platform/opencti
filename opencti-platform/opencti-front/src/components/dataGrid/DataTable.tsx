import React, { ReactNode } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import * as R from 'ramda';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { OperationType } from 'relay-runtime';
import { GraphQLTaggedNode } from 'react-relay';
import { useTheme } from '@mui/styles';
import DataTableFilters, { DataTableDisplayFilters } from './DataTableFilters';
import SearchInput from '../SearchInput';
import { DataTableProps, DataTableVariant } from './dataTableTypes';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useAuth from '../../utils/hooks/useAuth';
import { useComputeLink, useDataCellHelpers, useDataTable, useDataTableToggle, useLineData } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { useFormatter } from '../i18n';
import { SELECT_COLUMN_SIZE } from './components/DataTableHeader';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { FilterIconButtonProps } from '../FilterIconButton';
import { isNotEmptyField } from '../../utils/utils';
import type { Theme } from '../Theme';
import { useDataTableContext } from './components/DataTableContext';
import { getDefaultFilterObject } from '../../utils/filters/filtersUtils';

type DataTableInternalFiltersProps = Pick<DataTableProps,
| 'additionalFilterKeys'
| 'entityTypes'> & {
  hideSearch?: boolean
  hideFilters?: boolean
  availableRelationFilterTypes?: FilterIconButtonProps['availableRelationFilterTypes']
  availableEntityTypes?: string[]
  availableRelationshipTypes?: string[]
  searchContextFinal?: { entityTypes: string[]; elementId?: string[] }
  additionalHeaderButtons?: ReactNode[]
  currentView?: string
  exportContext?: { entity_type: string, entity_id?: string }
};

const DataTableInternalFilters = ({
  additionalFilterKeys,
  entityTypes,
  hideSearch,
  hideFilters,
  availableEntityTypes,
  availableRelationFilterTypes,
  availableRelationshipTypes,
  searchContextFinal,
  additionalHeaderButtons,
  currentView,
  exportContext,
}: DataTableInternalFiltersProps) => {
  const theme = useTheme<Theme>();

  const {
    storageKey,
    initialValues,
    availableFilterKeys,
  } = useDataTableContext();

  const {
    viewStorage: { searchTerm },
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage(storageKey, initialValues);

  const computedEntityTypes = entityTypes ?? (exportContext?.entity_type ? [exportContext.entity_type] : []);

  return (
    <>
      <div
        style={{
          display: 'flex',
          gap: theme.spacing(1),
          marginBottom: theme.spacing(2),
        }}
      >
        {!hideSearch && (
          <SearchInput
            variant={'small'}
            onSubmit={helpers.handleSearch}
            keyword={searchTerm}
          />
        )}
        {!hideFilters && (
          <DataTableFilters
            availableFilterKeys={availableFilterKeys}
            searchContextFinal={searchContextFinal}
            availableEntityTypes={availableEntityTypes}
            availableRelationshipTypes={availableRelationshipTypes}
            availableRelationFilterTypes={availableRelationFilterTypes}
            exportContext={exportContext}
            paginationOptions={paginationOptions}
            additionalHeaderButtons={additionalHeaderButtons}
            currentView={currentView}
          />
        )}
      </div>
      {!hideFilters && (
        <DataTableDisplayFilters
          availableFilterKeys={availableFilterKeys}
          availableRelationFilterTypes={availableRelationFilterTypes}
          availableEntityTypes={availableEntityTypes}
          additionalFilterKeys={additionalFilterKeys}
          entityTypes={computedEntityTypes}
          paginationOptions={paginationOptions}
        />
      )}
    </>
  );
};

type DataTableInternalToolbarProps = Pick<DataTableProps,
| 'toolbarFilters'
| 'handleCopy'
> & {
  taskScope?: string
};

const DataTableInternalToolbar = ({
  taskScope,
  handleCopy,
  toolbarFilters,
}: DataTableInternalToolbarProps) => {
  const theme = useTheme<Theme>();

  const {
    storageKey,
    initialValues,
    useDataTableToggle: {
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      selectAll,
      handleClearSelectedElements,
    },
  } = useDataTableContext();

  const {
    viewStorage: { searchTerm },
  } = usePaginationLocalStorage(storageKey, initialValues);

  return (
    <div
      style={{
        background: theme.palette.background.accent,
        width: `calc(( var(--header-table-size) - ${SELECT_COLUMN_SIZE} ) * 1px)`,
      }}
    >
      <DataTableToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        search={searchTerm}
        filters={toolbarFilters}
        handleClearSelectedElements={handleClearSelectedElements}
        taskScope={taskScope}
        handleCopy={handleCopy}
      />
    </div>
  );
};

type OCTIDataTableProps = Pick<DataTableProps,
| 'dataColumns'
| 'resolvePath'
| 'storageKey'
| 'initialValues'
| 'availableFilterKeys'
| 'redirectionModeEnabled'
| 'additionalFilterKeys'
| 'variant'
| 'actions'
| 'rootRef'
| 'onLineClick'
| 'disableNavigation'
| 'disableLineSelection'
| 'disableToolBar'
| 'disableSelectAll'
| 'selectOnLineClick'
| 'entityTypes'> & {
  lineFragment: GraphQLTaggedNode
  preloadedPaginationProps: UsePreloadedPaginationFragment<OperationType>,
  exportContext?: { entity_type: string, entity_id?: string }
  globalSearch?: string;
  createButton?: ReactNode
} & DataTableInternalFiltersProps & DataTableInternalToolbarProps;

const DataTable = (props: OCTIDataTableProps) => {
  const { schema } = useAuth();
  const formatter = useFormatter();

  const {
    storageKey,
    initialValues,
    availableFilterKeys: defaultAvailableFilterKeys,
    globalSearch,
    searchContextFinal,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    preloadedPaginationProps: dataQueryArgs,
    additionalFilterKeys,
    lineFragment,
    exportContext,
    entityTypes,
    toolbarFilters,
    handleCopy,
    variant = DataTableVariant.default,
    additionalHeaderButtons,
    currentView,
    hideSearch,
    hideFilters,
    taskScope,
  } = props;

  const {
    viewStorage: {
      redirectionMode,
      sortBy,
      orderAsc,
      pageSize,
    },
    helpers,
  } = usePaginationLocalStorage(storageKey, initialValues);
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const computedEntityTypes = entityTypes ?? (exportContext?.entity_type ? [exportContext.entity_type] : []);
  let availableFilterKeys = defaultAvailableFilterKeys ?? [];
  if (availableFilterKeys.length === 0 && isNotEmptyField(computedEntityTypes)) {
    const filterKeysMap = new Map();
    computedEntityTypes.forEach((entityType: string) => {
      const currentMap = schema.filterKeysSchema.get(entityType);
      currentMap?.forEach((value, key) => filterKeysMap.set(key, value));
    });
    availableFilterKeys = R.uniq(Array.from(filterKeysMap.keys())); // keys of the entity type if availableFilterKeys is not specified
  }
  if (additionalFilterKeys) {
    availableFilterKeys = availableFilterKeys.concat(additionalFilterKeys);
  }

  return (
    <DataTableComponent
      {...props}
      availableFilterKeys={availableFilterKeys}
      dataQueryArgs={{ ...dataQueryArgs }}
      useLineData={useLineData(lineFragment)}
      useDataTable={useDataTable}
      useDataCellHelpers={useDataCellHelpers(helpers, variant)}
      useDataTableToggle={useDataTableToggle(storageKey)}
      useComputeLink={useComputeLink}
      onAddFilter={(id) => helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(id))}
      formatter={formatter}
      settingsMessagesBannerHeight={settingsMessagesBannerHeight}
      storageHelpers={helpers}
      redirectionMode={redirectionMode}
      onSort={helpers.handleSort}
      sortBy={sortBy}
      orderAsc={orderAsc}
      pageSize={pageSize}
      filtersComponent={(
        <DataTableInternalFilters
          entityTypes={entityTypes}
          additionalFilterKeys={additionalFilterKeys}
          additionalHeaderButtons={additionalHeaderButtons}
          availableEntityTypes={availableEntityTypes}
          availableRelationFilterTypes={availableRelationFilterTypes}
          hideFilters={hideFilters}
          hideSearch={hideSearch}
          availableRelationshipTypes={availableRelationshipTypes}
          currentView={currentView}
          exportContext={exportContext}
          searchContextFinal={searchContextFinal}
        />
      )}
      dataTableToolBarComponent={(
        <DataTableInternalToolbar
          handleCopy={handleCopy}
          taskScope={taskScope}
          toolbarFilters={toolbarFilters}
        />
      )}
    />
  );
};

export default DataTable;
