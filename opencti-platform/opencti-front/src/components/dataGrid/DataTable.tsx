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
import { useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';
import useDraftContext from '../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../utils/authorizedMembers';

type DataTableInternalFiltersProps = Pick<DataTableProps,
| 'additionalFilters'
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
  additionalFilters,
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
              variant={'small'}
              onSubmit={helpers.handleSearch}
              keyword={searchTerm}
            />
          )}

          {!hideFilters && (
            <DataTableFilters
              additionalFilters={additionalFilters}
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
      )}
      {!hideFilters && (
        <DataTableDisplayFilters
          availableFilterKeys={availableFilterKeys}
          availableRelationFilterTypes={availableRelationFilterTypes}
          availableEntityTypes={availableEntityTypes}
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
| 'removeFromDraftEnabled'
| 'markAsReadEnabled'
| 'entityTypes'
> & {
  taskScope?: string
  globalSearch?: string;
  displayEditButtons: boolean
};

const DataTableInternalToolbar = ({
  taskScope,
  handleCopy,
  toolbarFilters,
  globalSearch,
  removeAuthMembersEnabled,
  removeFromDraftEnabled,
  markAsReadEnabled,
  entityTypes,
  displayEditButtons,
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
        types={entityTypes}
        handleClearSelectedElements={handleClearSelectedElements}
        taskScope={taskScope}
        handleCopy={handleCopy}
        removeAuthMembersEnabled={removeAuthMembersEnabled}
        removeFromDraftEnabled={removeFromDraftEnabled}
        markAsReadEnabled={markAsReadEnabled}
        displayEditButtons={displayEditButtons}
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
| 'additionalFilters'
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
| 'removeSelectAll'
| 'selectOnLineClick'
| 'createButton'
| 'entityTypes'> & {
  lineFragment: GraphQLTaggedNode
  preloadedPaginationProps: UsePreloadedPaginationFragment<OperationType>,
  exportContext?: { entity_type: string, entity_id?: string }
  globalSearch?: string;
  createButton?: ReactNode
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
    additionalFilters,
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
    removeAuthMembersEnabled,
    removeFromDraftEnabled,
    markAsReadEnabled,
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
            additionalFilters={additionalFilters}
            additionalHeaderButtons={additionalHeaderButtons}
            availableEntityTypes={availableEntityTypes}
            availableRelationFilterTypes={availableRelationFilterTypes}
            hideFilters={hideFilters}
            hideSearch={hideSearch}
            availableRelationshipTypes={availableRelationshipTypes}
            currentView={currentView}
            exportContext={exportContext}
            searchContextFinal={computedSearchContextFinal}
          />
        )}
        dataTableToolBarComponent={(
          <DataTableInternalToolbar
            entityTypes={entityTypes}
            handleCopy={handleCopy}
            taskScope={taskScope}
            toolbarFilters={toolbarFilters}
            globalSearch={globalSearch}
            removeAuthMembersEnabled={removeAuthMembersEnabled}
            removeFromDraftEnabled={removeFromDraftEnabled}
            markAsReadEnabled={markAsReadEnabled}
            displayEditButtons={hasAuthorizedMembersCanEdit}
          />
      )}
      />
    </>
  );
};

export default DataTable;
