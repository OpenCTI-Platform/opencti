import Filters from '@components/common/lists/Filters';
import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, SettingsOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import StixDomainObjectsExports from '@components/common/stix_domain_objects/StixDomainObjectsExports';
import StixCoreRelationshipsExports from '@components/common/stix_core_relationships/StixCoreRelationshipsExports';
import StixCoreObjectsExports from '@components/common/stix_core_objects/StixCoreObjectsExports';
import StixCyberObservablesExports from '@components/observations/stix_cyber_observables/StixCyberObservablesExports';
import { ToggleButtonGroup } from '@mui/material';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import FilterIconButton from '../FilterIconButton';
import { useFormatter } from '../i18n';
import { DataTableDisplayFiltersProps, DataTableFiltersProps, DataTableVariant } from './dataTableTypes';
import { useDataTableContext } from './dataTableUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import { export_max_size } from '../../utils/utils';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import Security from '../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import { ExportContext } from '../../utils/ExportContextProvider';
import Transition from '../Transition';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  filterContainer: {
    minHeight: 10,
  },
  filterInliner: {
    display: 'inline-flex',
    justifyContent: 'space-between',
    flex: 1,
  },
  filterHeaderContainer: {
    display: 'inline-grid',
    gridAutoFlow: 'column',
    marginLeft: 10,
    gap: 10,
  },
  viewsAligner: {
    display: 'flex',
    alignItems: 'center',
  },
}));

export const DataTableDisplayFilters = ({
  availableFilterKeys,
  availableRelationFilterTypes,
  additionalFilterKeys,
  entityTypes,
}: DataTableDisplayFiltersProps) => {
  const classes = useStyles();
  const { storageKey, initialValues, variant } = useDataTableContext();
  const { helpers, viewStorage: { filters } } = usePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);

  return (
    <div id="filter-container" className={classes.filterContainer}>
      <FilterIconButton
        helpers={helpers}
        availableFilterKeys={availableFilterKeys}
        filters={filters}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        availableRelationFilterTypes={availableRelationFilterTypes}
        entityTypes={entityTypes}
        filtersRestrictions={{
          preventRemoveFor: additionalFilterKeys,
        }}
        redirection
      />
    </div>
  );
};

const DataTableFilters = ({
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
  const { t_i18n } = useFormatter();

  const [openSettings, setOpenSettings] = useState(false);

  const {
    storageKey,
    initialValues,
    redirectionModeEnabled,
    variant,
    createButton,
  } = useDataTableContext();
  const {
    helpers,
    viewStorage: { numberOfElements, openExports, redirectionMode },
  } = usePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);

  const { selectedElements } = useEntityToggle(storageKey);

  const classes = useStyles();

  const exportDisabled = !exportContext || (numberOfElements
    && ((Object.keys(selectedElements).length > export_max_size
        && numberOfElements.number > export_max_size)
      || (Object.keys(selectedElements).length === 0
        && numberOfElements.number > export_max_size)));

  return (
    <ExportContext.Provider value={{ selectedIds: Object.keys(selectedElements) }}>
      {availableFilterKeys && availableFilterKeys.length > 0 && (
        <div className={classes.filterInliner}>
          <div className={classes.filterHeaderContainer}>
            <Filters
              helpers={helpers}
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
          </div>
          <div className={classes.viewsAligner}>
            <ToggleButtonGroup
              size="small"
              color="secondary"
              value={currentView || 'lines'}
              exclusive={true}
              onChange={(_, value) => {
                if (value && value === 'export') {
                  helpers.handleToggleExports();
                } else if (value && value === 'settings') {
                  setOpenSettings(true);
                } else if (value && value !== 'export-csv') {
                  helpers.handleChangeView(value);
                }
              }}
            >
              {additionalHeaderButtons && [...additionalHeaderButtons]}
              {redirectionModeEnabled && (
                <ToggleButton
                  size="small"
                  value="settings"
                  aria-label="settings"
                >
                  <Tooltip title={t_i18n('List settings')}>
                    <SettingsOutlined fontSize="small" color="primary" />
                  </Tooltip>
                </ToggleButton>
              )}
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
      )}
      {exportContext
        && exportContext.entity_type !== 'Stix-Core-Object'
        && exportContext.entity_type !== 'Stix-Cyber-Observable'
        && exportContext.entity_type !== 'stix-core-relationship' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixDomainObjectsExports
              open={!!openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={paginationOptions}
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
              paginationOptions={paginationOptions}
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
              paginationOptions={paginationOptions}
              exportContext={exportContext}
            />
          </Security>
      )}
      {helpers.handleToggleExports && exportContext
        && exportContext.entity_type === 'Stix-Cyber-Observable' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCyberObservablesExports
              open={openExports}
              handleToggle={helpers.handleToggleExports}
              paginationOptions={paginationOptions}
              exportContext={exportContext}
            />
          </Security>
      )}
      {redirectionModeEnabled && (
        <Dialog
          open={openSettings}
          PaperProps={{ elevation: 1 }}
          TransitionComponent={Transition}
          onClose={() => setOpenSettings(false)}
          maxWidth="xs"
          fullWidth
        >
          <DialogTitle>{t_i18n('List settings')}</DialogTitle>
          <DialogContent>
            <FormControl style={{ width: '100%' }}>
              <InputLabel id="redirectionMode">
                {t_i18n('Redirection mode')}
              </InputLabel>
              <Select
                value={redirectionMode}
                onChange={(event) => helpers.handleAddProperty('redirectionMode', event.target.value)}
                fullWidth
              >
                <MenuItem value="overview">
                  {t_i18n('Redirecting to the Overview section')}
                </MenuItem>
                <MenuItem value="knowledge">
                  {t_i18n('Redirecting to the Knowledge section')}
                </MenuItem>
                <MenuItem value="content">
                  {t_i18n('Redirecting to the Content section')}
                </MenuItem>
              </Select>
            </FormControl>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpenSettings(false)}>
              {t_i18n('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </ExportContext.Provider>
  );
};

export default DataTableFilters;
