import React, { ReactNode } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import * as R from 'ramda';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { OperationType } from 'relay-runtime';
import { GraphQLTaggedNode } from 'react-relay';
import { useTheme } from '@mui/styles';
import DataTableFilters, { DataTableDisplayFilters } from './DataTableFilters';
import SearchInput from '../SearchInput';
import type { DataTableProps } from './dataTableTypes';
import { DataTableVariant } from './dataTableTypes';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useAuth from '../../utils/hooks/useAuth';
import { useComputeLink, useDataCellHelpers, useDataTable, useDataTableLocalStorage, useDataTableToggle, useLineData } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { useFormatter } from '../i18n';
import { SELECT_COLUMN_SIZE } from './components/DataTableHeader';
import { getDefaultFilterObject } from '../../utils/filters/filtersUtils';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { FilterIconButtonProps } from '../FilterIconButton';
import { isNotEmptyField } from '../../utils/utils';
import type { Theme } from '../Theme';

type OCTIDataTableProps = Pick<DataTableProps, 'dataColumns'
| 'resolvePath'
| 'storageKey'
| 'initialValues'
| 'toolbarFilters'
| 'availableFilterKeys'
| 'redirectionModeEnabled'
| 'additionalFilterKeys'
| 'variant'
| 'actions'
| 'entityTypes'> & {
  lineFragment: GraphQLTaggedNode
  preloadedPaginationProps: UsePreloadedPaginationFragment<OperationType>,
  availableRelationFilterTypes?: FilterIconButtonProps['availableRelationFilterTypes']
  availableEntityTypes?: string[]
  availableRelationshipTypes?: string[]
  searchContextFinal?: { entityTypes: string[]; elementId?: string[] }
  exportContext?: { entity_type: string, entity_id?: string }
  additionalHeaderButtons?: ReactNode[]
  createButton?: ReactNode
  currentView?: string
  hideFilters?: boolean
  taskScope?: string
};

const DataTable = (props: OCTIDataTableProps) => {
  const { schema } = useAuth();
  const formatter = useFormatter();
  const theme = useTheme<Theme>();

  const {
    storageKey,
    initialValues,
    availableFilterKeys: defaultAvailableFilterKeys,
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
    variant = DataTableVariant.default,
    additionalHeaderButtons,
    currentView,
    hideFilters,
    taskScope,
  } = props;

  const {
    viewStorage: {
      searchTerm,
      redirectionMode,
      numberOfElements,
      sortBy,
      orderAsc,
      pageSize,
    },
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);

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

  const {
    selectedElements,
    deSelectedElements,
    numberOfSelectedElements,
    selectAll,
    handleClearSelectedElements,
  } = useDataTableToggle(storageKey);

  return (
    <DataTableComponent
      {...props}
      availableFilterKeys={availableFilterKeys}
      dataQueryArgs={{ ...dataQueryArgs }}
      useLineData={useLineData(lineFragment)}
      useDataTable={useDataTable}
      useDataCellHelpers={useDataCellHelpers(helpers, variant)}
      useDataTableToggle={useDataTableToggle}
      useComputeLink={useComputeLink}
      useDataTableLocalStorage={useDataTableLocalStorage}
      onAddFilter={(id) => helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(id))}
      formatter={formatter}
      settingsMessagesBannerHeight={settingsMessagesBannerHeight}
      storageHelpers={helpers}
      redirectionMode={redirectionMode}
      numberOfElements={numberOfElements}
      onSort={helpers.handleSort}
      sortBy={sortBy}
      orderAsc={orderAsc}
      pageSize={pageSize}
      filtersComponent={(
        <>
          <div
            style={{
              display: 'flex',
              ...(variant === DataTableVariant.default ? { marginTop: -10 } : { marginTop: 10, marginLeft: 10, marginRight: 10 }),
            }}
          >
            <SearchInput
              variant={'small'}
              onSubmit={helpers.handleSearch}
              keyword={searchTerm}
            />
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
          {!hideFilters ? (
            <DataTableDisplayFilters
              availableFilterKeys={availableFilterKeys}
              availableRelationFilterTypes={availableRelationFilterTypes}
              additionalFilterKeys={additionalFilterKeys}
              entityTypes={computedEntityTypes}
              paginationOptions={paginationOptions}
            />
          ) : (<div style={{ minHeight: 10 }} />)}
        </>
      )}
      dataTableToolBarComponent={(
        <div
          style={{
            background: theme.palette.background.default,
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
          />
        </div>
      )}
    />
  );
};

export default DataTable;
