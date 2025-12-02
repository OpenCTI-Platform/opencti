import Filters from '@components/common/lists/Filters';
import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import StixDomainObjectsExports from '@components/common/stix_domain_objects/StixDomainObjectsExports';
import StixCoreRelationshipsExports from '@components/common/stix_core_relationships/StixCoreRelationshipsExports';
import StixCoreObjectsExports from '@components/common/stix_core_objects/StixCoreObjectsExports';
import StixCyberObservablesExports from '@components/observations/stix_cyber_observables/StixCyberObservablesExports';
import { ToggleButtonGroup } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import FilterIconButton from '../FilterIconButton';
import { useFormatter } from '../i18n';
import { DataTableDisplayFiltersProps, DataTableFiltersProps, DataTableVariant } from './dataTableTypes';
import { export_max_size } from '../../utils/utils';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import Security from '../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import { ExportContext } from '../../utils/ExportContextProvider';
import DataTablePagination from './DataTablePagination';
import { isFilterGroupNotEmpty } from '../../utils/filters/filtersUtils';
import { useDataTableContext } from './components/DataTableContext';

export const DataTableDisplayFilters = ({
  availableFilterKeys,
  availableRelationFilterTypes,
  availableEntityTypes,
  entityTypes,
  searchContext,
}: DataTableDisplayFiltersProps) => {
  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { filters, savedFilters },
    },
  } = useDataTableContext();

  return (
    <div id="filter-container" style={{ display: 'flex', alignItems: 'center' }}>
      <FilterIconButton
        helpers={helpers}
        availableFilterKeys={availableFilterKeys}
        filters={filters}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        availableRelationFilterTypes={availableRelationFilterTypes}
        availableEntityTypes={availableEntityTypes}
        entityTypes={entityTypes}
        hasSavedFilters={!!savedFilters}
        redirection
        searchContext={searchContext}
      />
    </div>
  );
};

const DataTableFilters = ({
  contextFilters,
  availableFilterKeys,
  searchContextFinal,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  paginationOptions,
  exportContext,
  currentView,
  additionalHeaderButtons,
}: DataTableFiltersProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const {
    storageKey,
    redirectionModeEnabled,
    variant,
    createButton,
    page,
    setPage,
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { numberOfElements, openExports },
    },
  } = useDataTableContext();
  const { selectedElements } = useEntityToggle(storageKey);

  const exportDisabled = !exportContext || (numberOfElements
    && ((Object.keys(selectedElements).length > export_max_size
        && numberOfElements.number > export_max_size)
      || (Object.keys(selectedElements).length === 0
        && numberOfElements.number > export_max_size)));

  const hasFilters = availableFilterKeys && availableFilterKeys.length > 0;

  const hasToggleGroup = additionalHeaderButtons || redirectionModeEnabled || !exportDisabled;

  const exportFilterGroups = [];
  if (isFilterGroupNotEmpty(contextFilters)) {
    exportFilterGroups.push(contextFilters);
  }
  if (isFilterGroupNotEmpty(paginationOptions.filters)) {
    exportFilterGroups.push(paginationOptions.filters);
  }
  const exportPaginationOptions = {
    ...paginationOptions,
    filters: {
      mode: 'and',
      filters: [],
      filterGroups: exportFilterGroups,
    },
  };

  return (
    <ExportContext.Provider value={{ selectedIds: Object.keys(selectedElements) }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', flex: 1 }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(1),
        }}
        >
          {hasFilters && (
            <Filters
              isDatatable
              helpers={helpers}
              variant={variant}
              searchContext={searchContextFinal}
              availableFilterKeys={availableFilterKeys}
              handleAddFilter={helpers.handleAddFilter}
              handleSwitchFilter={helpers.handleSwitchFilter}
              handleRemoveFilter={helpers.handleRemoveFilter}
              handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
              handleSwitchLocalMode={helpers.handleSwitchLocalMode}
              availableEntityTypes={availableEntityTypes}
              availableRelationshipTypes={availableRelationshipTypes}
              availableRelationFilterTypes={availableRelationFilterTypes}
            />
          )}
        </div>
        <div style={{ display: 'flex' }}>
          {(variant === DataTableVariant.default) && (
            <DataTablePagination
              page={page}
              setPage={setPage}
              numberOfElements={numberOfElements}
              redirectionModeEnabled={redirectionModeEnabled}
            />
          )}
          <ToggleButtonGroup
            size="small"
            color="secondary"
            value={currentView || 'lines'}
            exclusive={true}
            style={hasToggleGroup ? { marginLeft: theme.spacing(1) } : undefined}
            onChange={(_, value) => {
              if (value && value === 'export') {
                helpers.handleToggleExports();
              } else if (value && value !== 'export-csv') {
                helpers.handleChangeView(value);
              }
            }}
          >
            {additionalHeaderButtons && [...additionalHeaderButtons]}
            {!exportDisabled && (
              <ToggleButton value="export" aria-label="export">
                <Tooltip title={t_i18n('Open export panel')}>
                  <FileDownloadOutlined
                    fontSize="small"
                    color={openExports ? 'secondary' : 'primary'}
                  />
                </Tooltip>
              </ToggleButton>
            )}
          </ToggleButtonGroup>
          {createButton}
        </div>
      </div>
      {exportContext
        && exportContext.entity_type !== 'Stix-Core-Object'
        && exportContext.entity_type !== 'Stix-Cyber-Observable'
        && exportContext.entity_type !== 'stix-core-relationship' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixDomainObjectsExports
              open={!!openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={exportPaginationOptions}
              exportContext={exportContext}
            />
          </Security>
      )}
      {helpers.handleToggleExports && exportContext
        && exportContext.entity_type === 'stix-core-relationship' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCoreRelationshipsExports
              open={openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={exportPaginationOptions}
              exportContext={exportContext}
            />
          </Security>
      )}
      {helpers.handleToggleExports && exportContext
        && exportContext.entity_type === 'Stix-Core-Object' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCoreObjectsExports
              open={openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={exportPaginationOptions}
              exportContext={exportContext}
              exportType={undefined}
            />
          </Security>
      )}
      {helpers.handleToggleExports && exportContext
        && exportContext.entity_type === 'Stix-Cyber-Observable' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCyberObservablesExports
              open={openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={exportPaginationOptions}
              exportContext={exportContext}
            />
          </Security>
      )}
    </ExportContext.Provider>
  );
};

export default DataTableFilters;
