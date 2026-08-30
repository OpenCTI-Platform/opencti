import { useState } from 'react';
import Button from '@common/button/Button';
import { ArrowDropDown, ArrowDropUp, FileDownloadOutlined, LibraryBooksOutlined, SettingsOutlined, ViewModuleOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import { FileDelimitedOutline, FormatListGroup, Group, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import { compose, toPairs, uniq } from 'ramda';
import { ErrorBoundary } from '../../private/components/Error';
import FiligranIcon from '../../private/components/common/FiligranIcon';
import Filters from '../../private/components/common/lists/Filters';
import StixCoreObjectsExports from '../../private/components/common/stix_core_objects/StixCoreObjectsExports';
import StixCoreRelationshipsExports from '../../private/components/common/stix_core_relationships/StixCoreRelationshipsExports';
import StixDomainObjectsExports from '../../private/components/common/stix_domain_objects/StixDomainObjectsExports';
import StixCyberObservablesExports from '../../private/components/observations/stix_cyber_observables/StixCyberObservablesExports';
import { ExportContext } from '../../utils/ExportContextProvider';
import Security from '../../utils/Security';
import { UserContext } from '../../utils/hooks/useAuth';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import { export_max_size } from '../../utils/utils';
import FilterIconButton from '../FilterIconButton';
import SearchInput from '../SearchInput';
import { useFormatter } from '../i18n';

const styles = (theme) => ({
  container: {
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    padding: '0 0 50px 0',
  },
  containerNoPadding: {
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    padding: '0 0 0 0',
  },
  parameters: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    paddingBottom: 10,
    flexWrap: 'wrap',
  },
  parametersWithPadding: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    paddingBottom: 10,
    flexWrap: 'wrap',
  },
  filler: {
    flex: 'auto',
  },
  views: {
    marginTop: -5,
    display: 'flex',
  },
  linesContainer: {
    margin: 0,
    padding: 0,
  },
  linesContainerBottomNav: {
    margin: '0 0 90px 0',
    padding: 0,
  },
  item: {
    paddingLeft: 10,
  },
  headerItem: {
    display: 'flex',
    fontSize: 12,
    fontWeight: 700,
    alignItems: 'center',
  },
  sortableHeaderItem: {
    display: 'flex',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    paddingRight: 10,
    alignItems: 'center',
  },
  headerItemText: {
    marginRight: theme.spacing(1),
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textTransform: 'lowercase',
    '&::first-letter': {
      textTransform: 'uppercase',
    },
  },
  info: {
    paddingTop: 10,
  },
});

const ListLines = (props) => {
  const { t_i18n } = useFormatter();
  const [openSettings, setOpenSettings] = useState(false);
  const handleOpenSettings = () => {
    setOpenSettings(true);
  };

  const handleCloseSettings = () => {
    setOpenSettings(false);
  };

  const reverseBy = (field) => {
    props.handleSort(field, !props.orderAsc);
  };

  const renderHeaderElement = (field, label, width, isSortable) => {
    const { classes, sortBy, orderAsc } = props;
    if (isSortable) {
      const orderComponent = orderAsc ? (<ArrowDropDown />) : (<ArrowDropUp />);
      return (
        <div
          key={field}
          className={classes.sortableHeaderItem}
          style={{ width }}
          onClick={reverseBy.bind(null, field)}
        >
          <div className={classes.headerItemText}>{t_i18n(label)}</div>
          {sortBy === field ? orderComponent : ''}
        </div>
      );
    }
    return (
      <div
        className={classes.headerItem}
        style={{ width }}
        key={field}
      >
        <div className={classes.headerItemText}>{t_i18n(label)}</div>
      </div>
    );
  };

  const renderContent = (availableFilterKeys, entityTypes, selectedIds = []) => {
    const {
      classes,
      handleSearch,
      handleChangeView,
      disableCards,
      extraFields,
      handleAddFilter,
      handleRemoveFilter,
      handleSwitchFilter,
      handleSwitchGlobalMode,
      handleSwitchLocalMode,
      handleToggleExports,
      handleToggleSelectAll,
      selectAll,
      openExports,
      noPadding,
      dataColumns,
      secondaryAction,
      paginationOptions,
      keyword,
      filters,
      bottomNav,
      children,
      exportContext,
      numberOfElements,
      noHeaders,
      iconExtension,
      checkboxExtension,
      searchVariant,
      message,
      enableGraph,
      enableSubEntityLines,
      availableEntityTypes,
      availableRelationshipTypes,
      availableRelationFilterTypes,
      enableNestedView,
      enableEntitiesView,
      enableContextualView,
      currentView,
      handleSwitchRedirectionMode,
      redirectionMode,
      parametersWithPadding,
      searchContext,
      handleExportCsv,
      helpers,
      inline,
      additionalFilterKeys,
      createButton,
    } = props;
    const exportDisabled = numberOfElements
      && ((selectedIds.length > export_max_size
        && numberOfElements.number > export_max_size)
      || (selectedIds.length === 0
        && numberOfElements.number > export_max_size));
    const searchContextFinal = {
      ...(searchContext ?? {}),
      entityTypes: entityTypes ?? [],
    };
    return (
      <div className={noPadding ? classes.containerNoPadding : classes.container}>
        {!inline && (
          <div
            className={
              parametersWithPadding
                ? classes.parametersWithPadding
                : classes.parameters
            }
          >

            {typeof handleSearch === 'function' && (
              <SearchInput
                variant={searchVariant || 'small'}
                onSubmit={handleSearch}
                keyword={keyword}
              />
            )}

            {extraFields}
            {handleAddFilter && handleRemoveFilter && availableFilterKeys && availableFilterKeys.length > 0 && (
              <Filters
                helpers={helpers}
                searchContext={searchContextFinal}
                availableFilterKeys={availableFilterKeys}
                handleAddFilter={handleAddFilter}
                handleSwitchFilter={handleSwitchFilter}
                handleRemoveFilter={handleRemoveFilter}
                handleSwitchGlobalMode={handleSwitchGlobalMode}
                handleSwitchLocalMode={handleSwitchLocalMode}
                availableEntityTypes={availableEntityTypes}
                availableRelationshipTypes={availableRelationshipTypes}
                availableRelationFilterTypes={availableRelationFilterTypes}
              />
            )}
            <div className={classes.filler} />

            <div className={classes.views} style={{ display: 'flex', gap: 8 }}>

              {numberOfElements && (
                <div
                  style={
                    parametersWithPadding
                      ? { float: 'left', padding: '7px 20px 0 0' }
                      : { float: 'left', padding: '7px 5px 0 0' }
                  }
                >
                  <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                  {t_i18n('entitie(s)')}
                </div>
              )}
              {(typeof handleChangeView === 'function'
                || typeof handleToggleExports === 'function'
                || typeof handleExportCsv === 'function') && (
                <ToggleButtonGroup
                  size="small"
                  color="primary"
                  value={(!enableEntitiesView && currentView === 'entities') ? 'relationships' : currentView || 'lines'}
                  exclusive={true}
                  onChange={(_, value) => {
                    if (value && value === 'export') {
                      handleToggleExports();
                    } else if (value && value === 'settings') {
                      handleOpenSettings();
                    } else if (value && value !== 'export-csv') {
                      handleChangeView(value);
                    }
                  }}
                >
                  {typeof handleChangeView === 'function' && !disableCards && (
                    <ToggleButton value="cards" aria-label="cards">
                      <Tooltip title={t_i18n('Cards view')}>
                        <ViewModuleOutlined fontSize="small" color="primary" />
                      </Tooltip>
                    </ToggleButton>
                  )}
                  {typeof handleChangeView === 'function'
                    && enableEntitiesView && (
                    <ToggleButton value="entities" aria-label="entities">
                      <Tooltip title={t_i18n('Entities view')}>
                        <LibraryBooksOutlined
                          fontSize="small"
                        />
                      </Tooltip>
                    </ToggleButton>
                  )}
                  {(enableEntitiesView || (!enableEntitiesView && currentView === 'entities') || currentView === 'relationships') && (
                    <Tooltip title={t_i18n('Relationships view')}>
                      <ToggleButton
                        value="relationships"
                        aria-label="relationships"
                      >
                        <RelationManyToMany
                          fontSize="small"
                        />
                      </ToggleButton>
                    </Tooltip>
                  )}

                  {typeof handleChangeView === 'function' && !enableEntitiesView && currentView !== 'relationships' && currentView !== 'entities' && (
                    <Tooltip title={t_i18n('Lines view')}>
                      <ToggleButton value="lines" aria-label="lines">
                        <FiligranIcon icon={ListViewIcon} size="small" />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleChangeView === 'function' && enableGraph && (
                    <Tooltip title={t_i18n('Graph view')}>
                      <ToggleButton value="graph" aria-label="graph">
                        <VectorPolygon fontSize="small" />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleChangeView === 'function'
                    && enableNestedView && (
                    <Tooltip title={t_i18n('Nested view')}>
                      <ToggleButton value="nested" aria-label="nested">
                        <FormatListGroup fontSize="small" />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleChangeView === 'function'
                    && enableContextualView && (
                    <ToggleButton value="contextual" aria-label="contextual">
                      <Tooltip
                        title={t_i18n('Knowledge from related containers view')}
                      >
                        <Group
                          fontSize="small"
                        />
                      </Tooltip>
                    </ToggleButton>
                  )}
                  {typeof handleChangeView === 'function' && enableSubEntityLines && (
                    <Tooltip title={t_i18n('Sub entity lines view')}>
                      <ToggleButton value="subEntityLines" aria-label="subEntityLines">
                        <FiligranIcon icon={SublistViewIcon} size="small" />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {handleSwitchRedirectionMode && (
                    <Tooltip title={t_i18n('List settings')}>
                      <ToggleButton
                        size="small"
                        value="settings"
                        aria-label="settings"
                      >
                        <SettingsOutlined fontSize="small" />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleToggleExports === 'function'
                    && !exportDisabled && (
                    <Tooltip title={t_i18n('Open export panel')}>
                      <ToggleButton value="export" aria-label="export">
                        <FileDownloadOutlined
                          fontSize="small"
                        />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleExportCsv === 'function' && !exportDisabled && (
                    <Tooltip title={t_i18n('Export first 5000 rows in CSV')}>
                      <ToggleButton
                        value="export-csv"
                        onClick={() => handleExportCsv()}
                        aria-label="export"
                      >
                        <FileDelimitedOutline
                          fontSize="small"
                        />
                      </ToggleButton>
                    </Tooltip>
                  )}
                  {typeof handleToggleExports === 'function'
                    && exportDisabled && (
                    <Tooltip
                      title={`${
                        t_i18n(
                          'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                        ) + export_max_size
                      })`}
                    >
                      <span>
                        <ToggleButton
                          size="small"
                          value="export"
                          aria-label="export"
                          disabled={true}
                        >
                          <FileDownloadOutlined fontSize="small" />
                        </ToggleButton>
                      </span>
                    </Tooltip>
                  )}
                </ToggleButtonGroup>
              )}
              {createButton}
            </div>
          </div>
        )}
        <FilterIconButton
          helpers={helpers}
          availableFilterKeys={availableFilterKeys}
          filters={filters}
          handleRemoveFilter={handleRemoveFilter}
          handleSwitchGlobalMode={handleSwitchGlobalMode}
          handleSwitchLocalMode={handleSwitchLocalMode}
          availableRelationFilterTypes={availableRelationFilterTypes}
          redirection
          entityTypes={entityTypes}
          filtersRestrictions={additionalFilterKeys?.filtersRestrictions ?? undefined}
          searchContext={searchContextFinal}
          availableEntityTypes={availableEntityTypes}
          availableRelationshipTypes={availableRelationshipTypes}
        />
        <ErrorBoundary key={keyword}>
          {message && (
            <div style={{ width: '100%', marginTop: 10 }}>
              <Alert
                severity="info"
                variant="outlined"
                style={{ padding: '0px 10px 0px 10px' }}
                classes={{ message: classes.info }}
              >
                {message}
              </Alert>
            </div>
          )}
          <List
            classes={{ root: bottomNav ? classes.linesContainerBottomNav : classes.linesContainer }}
            style={!handleToggleSelectAll ? { marginTop: 10 } : null}
          >
            {!noHeaders && (
              <ListItem
                classes={{ root: classes.item }}
                divider={false}
                style={{ paddingTop: 0 }}
                secondaryAction={secondaryAction && (
                  <> &nbsp; </>
                )}
              >
                {handleToggleSelectAll && (
                  <ListItemIcon
                    style={{
                      minWidth: handleToggleSelectAll ? 40 : 56,
                    }}
                  >
                    <Checkbox
                      edge="start"
                      checked={selectAll}
                      disableRipple={true}
                      onChange={
                        typeof handleToggleSelectAll === 'function'
                        && handleToggleSelectAll
                      }
                      disabled={typeof handleToggleSelectAll !== 'function'}
                    />
                  </ListItemIcon>
                )}
                {checkboxExtension && (
                  <span style={{ width: '56px' }}>
                  </span>
                )}
                {iconExtension && (
                  <span style={{ width: '56px' }}>
                  </span>
                )}
                <ListItemText
                  primary={(
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {toPairs(dataColumns).map((dataColumn) => renderHeaderElement(
                        dataColumn[0],
                        dataColumn[1].label,
                        dataColumn[1].width,
                        dataColumn[1].isSortable,
                      ))}
                    </Box>
                  )}
                />
              </ListItem>
            )}
            {children}
          </List>
          {typeof handleToggleExports === 'function' && exportContext
            && exportContext.entity_type !== 'Stix-Core-Object'
            && exportContext.entity_type !== 'Stix-Cyber-Observable'
            && exportContext.entity_type !== 'stix-core-relationship' && (
            <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
              <StixDomainObjectsExports
                open={openExports}
                handleToggle={handleToggleExports}
                paginationOptions={paginationOptions}
                exportContext={exportContext}
              />
            </Security>
          )}
          {typeof handleToggleExports === 'function' && exportContext
            && exportContext.entity_type === 'stix-core-relationship' && (
            <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
              <StixCoreRelationshipsExports
                open={openExports}
                handleToggle={handleToggleExports}
                paginationOptions={paginationOptions}
                exportContext={exportContext}
              />
            </Security>
          )}
          {typeof handleToggleExports === 'function' && exportContext
            && exportContext.entity_type === 'Stix-Core-Object' && (
            <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
              <StixCoreObjectsExports
                open={openExports}
                handleToggle={handleToggleExports}
                paginationOptions={paginationOptions}
                exportContext={exportContext}
              />
            </Security>
          )}
          {typeof handleToggleExports === 'function' && exportContext
            && exportContext.entity_type === 'Stix-Cyber-Observable' && (
            <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
              <StixCyberObservablesExports
                open={openExports}
                handleToggle={handleToggleExports}
                paginationOptions={paginationOptions}
                exportContext={exportContext}
              />
            </Security>
          )}
          {handleSwitchRedirectionMode && (
            <Dialog
              open={openSettings}
              onClose={handleCloseSettings}
              size="small"
              title={t_i18n('List settings')}
            >
              <FormControl style={{ width: '100%' }}>
                <InputLabel id="redirectionMode">
                  {t_i18n('Redirection mode')}
                </InputLabel>
                <Select
                  value={redirectionMode}
                  onChange={(event) => handleSwitchRedirectionMode(event.target.value)
                  }
                  fullWidth={true}
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

              <DialogActions>
                <Button onClick={handleCloseSettings}>
                  {t_i18n('Close')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </ErrorBoundary>
      </div>
    );
  };

  const { disableExport, exportContext, additionalFilterKeys } = props;
  const entityTypes = props.entityTypes ?? (exportContext?.entity_type ? [exportContext?.entity_type] : undefined);
  return (
    <UserContext.Consumer>
      {({ schema }) => {
        let availableFilterKeys = props.availableFilterKeys ?? [];
        if (availableFilterKeys.length === 0 && entityTypes) {
          const filterKeysMap = new Map();
          entityTypes.forEach((entityType) => {
            const currentMap = schema.filterKeysSchema.get(entityType);
            currentMap?.forEach((value, key) => filterKeysMap.set(key, value));
          });
          availableFilterKeys = uniq(Array.from(filterKeysMap.keys())); // keys of the entity type if availableFilterKeys is not specified
        }
        if (additionalFilterKeys && additionalFilterKeys.filterKeys) availableFilterKeys = uniq(availableFilterKeys.concat(additionalFilterKeys.filterKeys));
        if (disableExport) {
          return renderContent(availableFilterKeys, entityTypes);
        }
        return (
          <ExportContext.Consumer>
            {({ selectedIds }) => {
              return renderContent(availableFilterKeys, entityTypes, selectedIds);
            }}
          </ExportContext.Consumer>
        );
      }}
    </UserContext.Consumer>
  );
};

ListLines.propTypes = {
  classes: PropTypes.object,
  children: PropTypes.object,
  handleSearch: PropTypes.func,
  handleSort: PropTypes.func,
  handleChangeView: PropTypes.func,
  disableCards: PropTypes.bool,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  handleSwitchFilter: PropTypes.func,
  handleSwitchGlobalMode: PropTypes.func,
  handleSwitchLocalMode: PropTypes.func,
  handleToggleExports: PropTypes.func,
  selectAll: PropTypes.bool,
  openExports: PropTypes.bool,
  noPadding: PropTypes.bool,
  noBottomPadding: PropTypes.bool,
  views: PropTypes.array,
  exportContext: PropTypes.object,
  keyword: PropTypes.string,
  filters: PropTypes.object,
  sortBy: PropTypes.string,
  orderAsc: PropTypes.bool,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  secondaryAction: PropTypes.bool,
  bottomNav: PropTypes.bool,
  numberOfElements: PropTypes.object,
  noHeaders: PropTypes.bool,
  iconExtension: PropTypes.bool,
  checkboxExtension: PropTypes.bool,
  searchVariant: PropTypes.string,
  message: PropTypes.string,
  enableGraph: PropTypes.bool,
  availableEntityTypes: PropTypes.array,
  availableRelationshipTypes: PropTypes.array,
  availableRelationFilterTypes: PropTypes.object,
  enableNestedView: PropTypes.bool,
  enableEntitiesView: PropTypes.bool,
  enableSubEntityLines: PropTypes.bool,
  enableContextualView: PropTypes.bool,
  currentView: PropTypes.string,
  handleSwitchRedirectionMode: PropTypes.func,
  redirectionMode: PropTypes.string,
  parametersWithPadding: PropTypes.bool,
  inline: PropTypes.bool,
  searchContext: PropTypes.object,
  handleExportCsv: PropTypes.func,
  helpers: PropTypes.object,
  availableFilterKeys: PropTypes.array,
  additionalFilterKeys: PropTypes.object,
  entityTypes: PropTypes.array,
  createButton: PropTypes.object,
};

export default compose(withStyles(styles))(ListLines);
