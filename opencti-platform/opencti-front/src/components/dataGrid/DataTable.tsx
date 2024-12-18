import React, { ReactNode } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import * as R from 'ramda';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { OperationType } from 'relay-runtime';
import { GraphQLTaggedNode } from 'react-relay';
import { useTheme } from '@mui/styles';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import DataTableFilters, { DataTableDisplayFilters } from './DataTableFilters';
import SearchInput from '../SearchInput';
import { DataTableProps } from './dataTableTypes';
import useAuth from '../../utils/hooks/useAuth';
import { useDataTable, useLineData } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { FilterIconButtonProps } from '../FilterIconButton';
import { isNotEmptyField } from '../../utils/utils';
import type { Theme } from '../Theme';
import { useDataTableContext } from './components/DataTableContext';
import { useFormatter } from '../i18n';

type DataTableInternalFiltersProps = Pick<DataTableProps,
| 'additionalFilterKeys'
| 'message'
| 'storageKey'
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
  storageKey,
  message,
}: DataTableInternalFiltersProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const {
    availableFilterKeys,
    useDataTablePaginationLocalStorage: {
      viewStorage: { searchTerm },
      helpers,
      paginationOptions,
    },
  } = useDataTableContext();

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
      {message && (
        <div style={{ width: '100%', marginTop: 20 }}>
          <Alert
            severity="info"
            variant="outlined"
            style={{ padding: '0px 10px' }}
          >
            <Typography>
              {message}
            </Typography>
          </Alert>
        </div>
      )}
      {storageKey === 'restrictedEntities' && (
        <div style={{ width: '100%', marginBottom: 20 }}>
          <Alert
            severity="info"
            variant="outlined"
            style={{ padding: '0px 10px 0px 10px' }}
          >
            {t_i18n('This list displays all the entities that have some access restriction enabled, meaning that they are only accessible to some specific users. You can remove this access restriction on this screen.')}
          </Alert>
        </div>
      )}
      {!hideFilters && (
        <DataTableDisplayFilters
          availableFilterKeys={availableFilterKeys}
          availableRelationFilterTypes={availableRelationFilterTypes}
          availableEntityTypes={availableEntityTypes}
          additionalFilterKeys={additionalFilterKeys}
          entityTypes={computedEntityTypes}
        />
      )}

    </>
  );
};

type DataTableInternalToolbarProps = Pick<DataTableProps,
| 'toolbarFilters'
| 'handleCopy'
| 'removeAuthMembersEnabled'
> & {
  taskScope?: string
  globalSearch?: string;
};

const DataTableInternalToolbar = ({
  taskScope,
  handleCopy,
  toolbarFilters,
  globalSearch,
  removeAuthMembersEnabled,
}: DataTableInternalToolbarProps) => {
  const theme = useTheme<Theme>();

  const {
    useDataTableToggle: {
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      selectAll,
      handleClearSelectedElements,
    },
    useDataTablePaginationLocalStorage: {
      viewStorage: { searchTerm },
    },
  } = useDataTableContext();

  return (
    <div
      style={{
        background: theme.palette.background.accent,
        flex: 1,
      }}
    >

      <DataTableToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        search={searchTerm ?? globalSearch}
        filters={toolbarFilters}
        handleClearSelectedElements={handleClearSelectedElements}
        taskScope={taskScope}
        handleCopy={handleCopy}
        removeAuthMembersEnabled={removeAuthMembersEnabled}
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
| 'canToggleLine'
| 'selectOnLineClick'
| 'createButton'
| 'message'
| 'entityTypes'> & {
  lineFragment: GraphQLTaggedNode
  preloadedPaginationProps: UsePreloadedPaginationFragment<OperationType>,
  exportContext?: { entity_type: string, entity_id?: string }
  globalSearch?: string;
  createButton?: ReactNode
} & DataTableInternalFiltersProps & DataTableInternalToolbarProps;

const DataTable = (props: OCTIDataTableProps) => {
  const { schema } = useAuth();

  const {
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
    additionalHeaderButtons,
    currentView,
    hideSearch,
    hideFilters,
    taskScope,
    message,
    storageKey,
    removeAuthMembersEnabled,
  } = props;

  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const computedEntityTypes = entityTypes ?? (exportContext?.entity_type ? [exportContext.entity_type] : []);
  const computedSearchContextFinal = searchContextFinal?.entityTypes
    ? searchContextFinal
    : { ...searchContextFinal, entityTypes: computedEntityTypes };
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
      settingsMessagesBannerHeight={settingsMessagesBannerHeight}
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
          searchContextFinal={computedSearchContextFinal}
          storageKey={storageKey}
          message={message}
        />
      )}
      dataTableToolBarComponent={(
        <DataTableInternalToolbar
          handleCopy={handleCopy}
          taskScope={taskScope}
          toolbarFilters={toolbarFilters}
          globalSearch={globalSearch}
          removeAuthMembersEnabled={removeAuthMembersEnabled}
        />
      )}
    />
  );
};

export default DataTable;
