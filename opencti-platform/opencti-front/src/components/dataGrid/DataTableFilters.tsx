import Filters from '@components/common/lists/Filters';
import StixCoreObjectsExports from '@components/common/stix_core_objects/StixCoreObjectsExports';
import StixCoreRelationshipsExports from '@components/common/stix_core_relationships/StixCoreRelationshipsExports';
import StixDomainObjectsExports from '@components/common/stix_domain_objects/StixDomainObjectsExports';
import StixCyberObservablesExports from '@components/observations/stix_cyber_observables/StixCyberObservablesExports';
import { FileDownloadOutlined } from '@mui/icons-material';
import { Stack, ToggleButtonGroup } from '@mui/material';
import { Theme } from '@mui/material/styles/createTheme';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { ExportContext } from '../../utils/ExportContextProvider';
import { isFilterGroupNotEmpty } from '../../utils/filters/filtersUtils';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import Security from '../../utils/Security';
import { export_max_size } from '../../utils/utils';
import FilterIconButton from '../FilterIconButton';
import { useFormatter } from '../i18n';
import { useDataTableContext } from './components/DataTableContext';
import DataTablePagination from './DataTablePagination';
import { DataTableDisplayFiltersProps, DataTableFiltersProps, DataTableVariant } from './dataTableTypes';

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
  additionalHeaderToggleButtons: additionalToggleButtons,
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
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
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
            color="primary"
            value={currentView || 'lines'}
            exclusive={true}
            onChange={(_, value) => {
              if (value && value === 'export') {
                helpers.handleToggleExports();
              } else if (value && value !== 'export-csv') {
                helpers.handleChangeView(value);
              }
            }}
            sx={{
              '&:empty': {
                display: 'none',
              },
            }}
          >
            {additionalToggleButtons && [...additionalToggleButtons]}
            {!exportDisabled && (
              <ToggleButton value="export" aria-label="export">
                <Tooltip title={t_i18n('Open export panel')}>
                  <FileDownloadOutlined
                    fontSize="small"
                  />
                </Tooltip>
              </ToggleButton>
            )}
          </ToggleButtonGroup>

          {
            additionalHeaderButtons && (
              <Stack
                direction="row"
                gap={1}
                sx={{
                  '&:empty': {
                    display: 'none',
                  },
                }}
              >
                {[...additionalHeaderButtons]}
              </Stack>
            )
          }

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
