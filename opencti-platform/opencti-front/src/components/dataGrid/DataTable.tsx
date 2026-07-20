import React, { ReactNode } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { OperationType } from 'relay-runtime';
import { GraphQLTaggedNode } from 'react-relay';
import { useTheme } from '@mui/styles';
import DataTableFilters, { DataTableDisplayFilters } from './DataTableFilters';
import SearchInput from '../SearchInput';
import { DataTableProps } from './dataTableTypes';
import { useLineData } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { FilterIconButtonProps } from '../FilterIconButton';
import { isNotEmptyField } from '../../utils/utils';
import type { Theme } from '../Theme';
import { useDataTableContext } from './components/DataTableContext';
import { FilterSearchContext, useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';
import useDraftContext from '../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../utils/authorizedMembers';

type DataTableInternalFiltersProps = Pick<DataTableProps,
  | 'contextFilters'
  | 'entityTypes'
  | 'hideSavedFilters'> & {
    hideSearch?: boolean;
    hideFilters?: boolean;
    availableRelationFilterTypes?: FilterIconButtonProps['availableRelationFilterTypes'];
    availableEntityTypes?: string[];
    availableRelationshipTypes?: string[];
    searchContextFinal?: FilterSearchContext;
    additionalHeaderButtons?: ReactNode[];
    additionalHeaderToggleButtons?: ReactNode[];
    currentView?: string;
    exportContext?: { entity_type: string; entity_id?: string };
    disableLogging?:boolean;
  };

const DataTableInternalFilters = ({
  contextFilters,
  entityTypes,
  hideSearch,
  hideFilters,
  availableEntityTypes,
  availableRelationFilterTypes,
  availableRelationshipTypes,
  searchContextFinal,
  additionalHeaderButtons,
  additionalHeaderToggleButtons: additionalToggleButtons,
  currentView,
  exportContext,
  hideSavedFilters,
  disableLogging = false
}: DataTableInternalFiltersProps) => {
  const theme = useTheme<Theme>();
  const {
    columns,
    availableFilterKeys,
    useDataTablePaginationLocalStorage: {
      viewStorage: { searchTerm },
      helpers,
      paginationOptions,
    },
  } = useDataTableContext();
  const extendedExportContext = React.useMemo(
    () => (exportContext
      ? {
          ...exportContext,
          visible_columns: columns
            .filter(({ id, visible }) => !['select', 'navigate', 'icon'].includes(id) && visible)
            .map((c) => c.id),
        }
      : undefined),
    [exportContext, columns],
  );
  const computedEntityTypes = entityTypes ?? (exportContext?.entity_type ? [exportContext.entity_type] : []);

  return (
    <>
      {/* Wrap div in logic so if there are no filters and no search,
        * there isn't an empty div block with 16px bottom margin.
        */}
      {(!hideFilters || !hideSearch) && (
        <div
          style={{
            display: 'flex',
            gap: theme.spacing(1),
            marginBottom: theme.spacing(2),
          }}
        >
          {!hideSearch && (
            <SearchInput
              variant="small"
              onSubmit={helpers.handleSearch}
              searchContext={searchContextFinal}
              keyword={searchTerm}
              disableLogging={disableLogging}
            />
          )}

          {!hideFilters && (
            <DataTableFilters
              contextFilters={contextFilters}
              availableFilterKeys={availableFilterKeys}
              searchContextFinal={searchContextFinal}
              availableEntityTypes={availableEntityTypes}
              availableRelationshipTypes={availableRelationshipTypes}
              availableRelationFilterTypes={availableRelationFilterTypes}
              exportContext={extendedExportContext}
              paginationOptions={paginationOptions}
              additionalHeaderButtons={additionalHeaderButtons}
              additionalHeaderToggleButtons={additionalToggleButtons}
              currentView={currentView}
              hideSavedFilters={hideSavedFilters}
            />
          )}
        </div>
      )}
      {!hideFilters && (
        <DataTableDisplayFilters
          availableFilterKeys={availableFilterKeys}
          availableRelationFilterTypes={availableRelationFilterTypes}
          availableEntityTypes={availableEntityTypes}
          entityTypes={computedEntityTypes}
          searchContext={searchContextFinal}
        />
      )}
    </>
  );
};

type DataTableInternalToolbarProps = Pick<DataTableProps,
  | 'contextFilters'
  | 'handleCopy'
  | 'removeAuthMembersEnabled'
  | 'removeFromDraftEnabled'
  | 'markAsReadEnabled'
  | 'entityTypes'
  | 'trashOperationsEnabled'
  | 'disableBulkEnroll'
  | 'deleteDisable'
  | 'container'
> & {
  taskScope?: string;
  globalSearch?: string;
  displayEditButtons?: boolean;
};

const DataTableInternalToolbar = ({
  taskScope,
  handleCopy,
  contextFilters,
  globalSearch,
  removeAuthMembersEnabled,
  removeFromDraftEnabled,
  markAsReadEnabled,
  entityTypes,
  displayEditButtons,
  trashOperationsEnabled,
  disableBulkEnroll,
  deleteDisable,
  container,
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
        filters={contextFilters}
        types={entityTypes}
        handleClearSelectedElements={handleClearSelectedElements}
        taskScope={taskScope}
        handleCopy={handleCopy}
        removeAuthMembersEnabled={removeAuthMembersEnabled}
        removeFromDraftEnabled={removeFromDraftEnabled}
        markAsReadEnabled={markAsReadEnabled}
        displayEditButtons={displayEditButtons}
        trashOperationsEnabled={trashOperationsEnabled}
        disableBulkEnroll={disableBulkEnroll}
        deleteDisable={deleteDisable}
        container={container}
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
  | 'contextFilters'
  | 'variant'
  | 'actions'
  | 'hideHeaders'
  | 'emptyStateMessage'
  | 'icon'
  | 'rootRef'
  | 'onLineClick'
  | 'getComputeLink'
  | 'disableNavigation'
  | 'disableLineSelection'
  | 'disableToolBar'
  | 'disableColumnMenu'
  | 'removeSelectAll'
  | 'selectOnLineClick'
  | 'createButton'
  | 'entityTypes'
  | 'actionsColumnWidth'
  | 'enableInfiniteScroll'
  | 'container'> & {
    lineFragment: GraphQLTaggedNode;
    preloadedPaginationProps: UsePreloadedPaginationFragment<OperationType>;
    exportContext?: { entity_type: string; entity_id?: string };
    globalSearch?: string;
    createButton?: ReactNode;
  } & DataTableInternalFiltersProps & DataTableInternalToolbarProps;

const DataTable = (props: OCTIDataTableProps) => {
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
    contextFilters,
    handleCopy,
    additionalHeaderButtons,
    additionalHeaderToggleButtons,
    currentView,
    hideSearch,
    hideFilters,
    hideSavedFilters,
    taskScope,
    removeAuthMembersEnabled,
    removeFromDraftEnabled,
    markAsReadEnabled,
    trashOperationsEnabled,
    disableBulkEnroll,
    deleteDisable,
    container,
  } = props;

  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const computedEntityTypes = entityTypes ?? (exportContext?.entity_type ? [exportContext.entity_type] : []);
  const computedSearchContextFinal = searchContextFinal?.entityTypes
    ? searchContextFinal
    : { ...searchContextFinal, entityTypes: computedEntityTypes };
  let availableFilterKeys = defaultAvailableFilterKeys ?? [];
  if (availableFilterKeys.length === 0 && isNotEmptyField(computedEntityTypes)) {
    availableFilterKeys = useAvailableFilterKeysForEntityTypes(computedEntityTypes);
  }
  if (additionalFilterKeys) {
    availableFilterKeys = availableFilterKeys.concat(additionalFilterKeys);
  }

  // Remove toolbar in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const hasAuthorizedMembersCanEdit = !draftContext || currentAccessRight.canEdit;

  return (
    <>
      <DataTableComponent
        {...props}
        availableFilterKeys={availableFilterKeys}
        dataQueryArgs={{ ...dataQueryArgs }}
        useLineData={useLineData(lineFragment)}
        settingsMessagesBannerHeight={settingsMessagesBannerHeight}
        filtersComponent={(
          <DataTableInternalFilters
            entityTypes={entityTypes}
            contextFilters={contextFilters}
            additionalHeaderButtons={additionalHeaderButtons}
            additionalHeaderToggleButtons={additionalHeaderToggleButtons}
            availableEntityTypes={availableEntityTypes}
            availableRelationFilterTypes={availableRelationFilterTypes}
            hideFilters={hideFilters}
            hideSearch={hideSearch}
            hideSavedFilters={hideSavedFilters}
            availableRelationshipTypes={availableRelationshipTypes}
            currentView={currentView}
            exportContext={exportContext}
            searchContextFinal={computedSearchContextFinal}
          />
        )}
        dataTableToolBarComponent={(
          <DataTableInternalToolbar
            container={container}
            entityTypes={entityTypes}
            handleCopy={handleCopy}
            taskScope={taskScope}
            contextFilters={contextFilters}
            globalSearch={globalSearch}
            removeAuthMembersEnabled={removeAuthMembersEnabled}
            removeFromDraftEnabled={removeFromDraftEnabled}
            markAsReadEnabled={markAsReadEnabled}
            displayEditButtons={hasAuthorizedMembersCanEdit}
            trashOperationsEnabled={trashOperationsEnabled}
            disableBulkEnroll={disableBulkEnroll}
            deleteDisable={deleteDisable}
          />
        )}
      />
    </>
  );
};

export default DataTable;
