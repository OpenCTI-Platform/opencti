import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, toPairs } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import {
  ArrowDropDown,
  ArrowDropUp,
  FileDownloadOutlined,
  LibraryBooksOutlined,
  PreviewOutlined,
  SourceOutlined,
  ViewListOutlined,
  ViewModuleOutlined,
} from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Checkbox from '@mui/material/Checkbox';
import Alert from '@mui/material/Alert';
import { FormatListGroup, GraphOutline, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
import SearchInput from '../SearchInput';
import inject18n from '../i18n';
import StixDomainObjectsExports from '../../private/components/common/stix_domain_objects/StixDomainObjectsExports';
import Security from '../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import Filters from '../../private/components/common/lists/Filters';
import StixCyberObservablesExports
  from '../../private/components/observations/stix_cyber_observables/StixCyberObservablesExports';
import StixCoreRelationshipsExports
  from '../../private/components/common/stix_core_relationships/StixCoreRelationshipsExports';
import StixCoreObjectsExports from '../../private/components/common/stix_core_objects/StixCoreObjectsExports';
import FilterIconButton from '../FilterIconButton';

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
  containerOpenExports: {
    flexGrow: 1,
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '0 310px 50px 0',
  },
  parameters: {
    float: 'left',
    marginTop: -10,
  },
  views: {
    float: 'right',
  },
  linesContainer: {
    margin: '10px 0 0 0',
    padding: 0,
  },
  linesContainerBottomNav: {
    margin: '10px 0 90px 0',
    padding: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  sortIcon: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
  },
  headerItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  sortableHeaderItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
  info: {
    paddingTop: 10,
  },
});

class ListLines extends Component {
  reverseBy(field) {
    this.props.handleSort(field, !this.props.orderAsc);
  }

  renderHeaderElement(field, label, width, isSortable) {
    const { classes, t, sortBy, orderAsc, handleToggleSelectAll } = this.props;
    if (isSortable) {
      const orderComponent = orderAsc ? (
        <ArrowDropDown
          classes={{ root: classes.sortIcon }}
          style={{ top: typeof handleToggleSelectAll === 'function' ? 7 : 0 }}
        />
      ) : (
        <ArrowDropUp
          classes={{ root: classes.sortIcon }}
          style={{ top: typeof handleToggleSelectAll === 'function' ? 7 : 0 }}
        />
      );
      return (
        <div
          key={field}
          className={classes.sortableHeaderItem}
          style={{ width }}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {sortBy === field ? orderComponent : ''}
        </div>
      );
    }
    return (
      <div className={classes.headerItem} style={{ width }} key={field}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const {
      t,
      classes,
      handleSearch,
      handleChangeView,
      disableCards,
      handleAddFilter,
      handleRemoveFilter,
      handleToggleExports,
      handleToggleSelectAll,
      selectAll,
      openExports,
      noPadding,
      noBottomPadding,
      dataColumns,
      secondaryAction,
      paginationOptions,
      keyword,
      filters,
      bottomNav,
      children,
      exportEntityType,
      exportContext,
      numberOfElements,
      availableFilterKeys,
      noHeaders,
      iconExtension,
      searchVariant,
      message,
      noTopMargin,
      noFilters,
      enableGraph,
      availableEntityTypes,
      availableRelationshipTypes,
      availableRelationFilterTypes,
      enableNestedView,
      enableEntitiesView,
      currentView,
      handleSwitchRedirectionMode,
      redirectionMode,
    } = this.props;
    let className = classes.container;
    if (noBottomPadding) {
      className = classes.containerWithoutPadding;
    } else if (openExports && !noPadding) {
      className = classes.containerOpenExports;
    }
    return (
            <div className={className}>
              <div className={classes.parameters}>
                {typeof handleSearch === 'function' && (
                  <div style={{ float: 'left', marginRight: 20 }}>
                    <SearchInput
                      variant={searchVariant || 'small'}
                      onSubmit={handleSearch.bind(this)}
                      keyword={keyword}
                    />
                  </div>
                )}
                {availableFilterKeys && availableFilterKeys.length > 0 && (
                  <Filters
                    availableFilterKeys={availableFilterKeys}
                    handleAddFilter={handleAddFilter}
                    availableEntityTypes={availableEntityTypes}
                    availableRelationshipTypes={availableRelationshipTypes}
                    availableRelationFilterTypes={availableRelationFilterTypes}
                  />
                )}
                {(!availableFilterKeys || availableFilterKeys.length === 0)
                  && !noHeaders
                  && !noFilters && <div style={{ height: 38 }}> &nbsp; </div>}
                <FilterIconButton
                  filters={filters}
                  handleRemoveFilter={handleRemoveFilter}
                />
              </div>
              <div className={classes.views}>
                <div style={{ float: 'right', marginTop: -20 }}>
                  {numberOfElements && (
                    <div style={{ float: 'left', padding: '16px 5px 0 0' }}>
                      <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                      {t('entitie(s)')}
                    </div>
                  )}
                  {handleSwitchRedirectionMode && (
                    <ToggleButtonGroup
                      size="small"
                      color="secondary"
                      exclusive={true}
                      onChange={(_, value) => {
                        handleSwitchRedirectionMode(value);
                      }}
                      style={{ margin: '7px 20px 0 10px' }}
                    >
                      <ToggleButton
                        value="overview" aria-label="overview"
                      >
                        <Tooltip title={t('Redirecting to the Overview section')}>
                          <PreviewOutlined
                            fontSize="small"
                            color={(!redirectionMode || redirectionMode === 'overview') ? 'secondary' : 'primary'}
                          />
                        </Tooltip>
                      </ToggleButton>
                      <ToggleButton
                        value="knowledge" aria-label="knowledge"
                      >
                        <Tooltip title={t('Redirecting to the Knowledge section')}>
                          <GraphOutline
                            fontSize="small"
                            color={redirectionMode === 'knowledge' ? 'secondary' : 'primary'}
                          />
                        </Tooltip>
                      </ToggleButton>
                      <ToggleButton
                        value="content" aria-label="content"
                      >
                        <Tooltip title={t('Redirecting to the Content section')}>
                          <SourceOutlined
                            fontSize="small"
                            color={redirectionMode === 'content' ? 'secondary' : 'primary'}
                          />
                        </Tooltip>
                      </ToggleButton>
                    </ToggleButtonGroup>
                  )}
                  {(typeof handleChangeView === 'function'
                    || typeof handleToggleExports === 'function') && (
                    <ToggleButtonGroup
                      size="small"
                      color="secondary"
                      value={currentView || 'lines'}
                      exclusive={true}
                      onChange={(_, value) => {
                        if (value && value === 'export') {
                          handleToggleExports();
                        } else if (value) {
                          handleChangeView(value);
                        }
                      }}
                      style={{ margin: '7px 0 0 5px' }}
                    >
                      {typeof handleChangeView === 'function' && !disableCards && (
                        <ToggleButton value="cards" aria-label="cards">
                          <Tooltip title={t('Cards view')}>
                            <ViewModuleOutlined fontSize="small" color="primary"/>
                          </Tooltip>
                        </ToggleButton>
                      )}
                      {typeof handleChangeView === 'function'
                        && enableEntitiesView && (
                          <ToggleButton value="entities" aria-label="entities">
                            <Tooltip title={t('Entities view')}>
                              <LibraryBooksOutlined
                                fontSize="small"
                                color={
                                  currentView === 'entities' ? 'secondary' : 'primary'
                                }
                              />
                            </Tooltip>
                          </ToggleButton>
                      )}
                      {enableEntitiesView && (
                        <ToggleButton value="relationships" aria-label="relationships">
                          <Tooltip title={t('Relationships view')}>
                            <RelationManyToMany
                              fontSize="small"
                              color={
                                currentView === 'relationships' || !currentView
                                  ? 'secondary'
                                  : 'primary'
                              }
                            />
                          </Tooltip>
                        </ToggleButton>
                      )}
                      {!enableEntitiesView && (
                        <ToggleButton value="lines" aria-label="lines">
                          <Tooltip title={t('Lines view')}>
                            <ViewListOutlined
                              fontSize="small"
                              color={
                                currentView === 'lines' || !currentView
                                  ? 'secondary'
                                  : 'primary'
                              }
                            />
                          </Tooltip>
                        </ToggleButton>
                      )}
                      {typeof handleChangeView === 'function' && enableGraph && (
                        <ToggleButton value="graph" aria-label="graph">
                          <Tooltip title={t('Graph view')}>
                            <VectorPolygon fontSize="small" color="primary"/>
                          </Tooltip>
                        </ToggleButton>
                      )}
                      {typeof handleChangeView === 'function' && enableNestedView && (
                        <ToggleButton value="nested" aria-label="nested">
                          <Tooltip title={t('Nested view')}>
                            <FormatListGroup fontSize="small" color="primary"/>
                          </Tooltip>
                        </ToggleButton>
                      )}
                      {typeof handleToggleExports === 'function' && (
                        <ToggleButton value="export" aria-label="export">
                          <Tooltip title={t('Open export panel')}>
                            <FileDownloadOutlined
                              fontSize="small"
                              color={openExports ? 'secondary' : 'primary'}
                            />
                          </Tooltip>
                        </ToggleButton>
                      )}
                    </ToggleButtonGroup>
                  )}
                </div>
              </div>
              <div className="clearfix"/>
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
                classes={{
                  root: bottomNav
                    ? classes.linesContainerBottomNav
                    : classes.linesContainer,
                }}
                style={noTopMargin ? { marginTop: 0 } : null}
              >
                {!noHeaders ? (
                  <ListItem
                    classes={{ root: classes.item }}
                    divider={false}
                    style={{ paddingTop: 0 }}
                  >
                    <ListItemIcon
                      style={{
                        minWidth:
                          typeof handleToggleSelectAll === 'function' ? 38 : 56,
                      }}
                    >
                      {typeof handleToggleSelectAll === 'function' ? (
                        <Checkbox
                          edge="start"
                          checked={selectAll}
                          disableRipple={true}
                          onChange={handleToggleSelectAll.bind(this)}
                        />
                      ) : (
                        <span
                          style={{
                            padding: '0 8px 0 8px',
                            fontWeight: 700,
                            fontSize: 12,
                          }}
                        >
                    &nbsp;
                  </span>
                      )}
                    </ListItemIcon>
                    {iconExtension && (
                      <ListItemIcon>
                  <span
                    style={{
                      padding: '0 8px 0 8px',
                      fontWeight: 700,
                      fontSize: 12,
                    }}
                  >
                    &nbsp;
                  </span>
                      </ListItemIcon>
                    )}
                    <ListItemText
                      primary={
                        <div>
                          {toPairs(dataColumns).map((dataColumn) => this.renderHeaderElement(
                            dataColumn[0],
                            dataColumn[1].label,
                            dataColumn[1].width,
                            dataColumn[1].isSortable,
                          ))}
                        </div>
                      }
                    />
                    {secondaryAction && (
                      <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
                    )}
                  </ListItem>
                ) : (
                  ''
                )}
                {children}
              </List>
              {typeof handleToggleExports === 'function'
                && exportEntityType !== 'Stix-Core-Object'
                && exportEntityType !== 'Stix-Cyber-Observable'
                && exportEntityType !== 'stix-core-relationship' && (
                  <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
                    <StixDomainObjectsExports
                      open={openExports}
                      handleToggle={handleToggleExports.bind(this)}
                      paginationOptions={paginationOptions}
                      exportEntityType={exportEntityType}
                      context={exportContext}
                    />
                  </Security>
              )}
              {typeof handleToggleExports === 'function'
                && exportEntityType === 'stix-core-relationship' && (
                  <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
                    <StixCoreRelationshipsExports
                      open={openExports}
                      handleToggle={handleToggleExports.bind(this)}
                      paginationOptions={paginationOptions}
                      context={exportContext}
                    />
                  </Security>
              )}
              {typeof handleToggleExports === 'function'
                && exportEntityType === 'Stix-Core-Object' && (
                  <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
                    <StixCoreObjectsExports
                      open={openExports}
                      handleToggle={handleToggleExports.bind(this)}
                      paginationOptions={paginationOptions}
                      exportEntityType={exportEntityType}
                      context={exportContext}
                    />
                  </Security>
              )}
              {typeof handleToggleExports === 'function'
                && exportEntityType === 'Stix-Cyber-Observable' && (
                  <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
                    <StixCyberObservablesExports
                      open={openExports}
                      handleToggle={handleToggleExports.bind(this)}
                      paginationOptions={paginationOptions}
                      context={exportContext}
                    />
                  </Security>
              )}
            </div>
    );
  }
}

ListLines.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  children: PropTypes.object,
  handleSearch: PropTypes.func,
  handleSort: PropTypes.func,
  handleChangeView: PropTypes.func,
  disableCards: PropTypes.bool,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  handleToggleExports: PropTypes.func,
  handleToggleSelectAll: PropTypes.func,
  selectAll: PropTypes.bool,
  openExports: PropTypes.bool,
  noPadding: PropTypes.bool,
  noBottomPadding: PropTypes.bool,
  views: PropTypes.array,
  exportEntityType: PropTypes.string,
  exportContext: PropTypes.string,
  keyword: PropTypes.string,
  filters: PropTypes.object,
  sortBy: PropTypes.string,
  orderAsc: PropTypes.bool,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  secondaryAction: PropTypes.bool,
  bottomNav: PropTypes.bool,
  numberOfElements: PropTypes.object,
  availableFilterKeys: PropTypes.array,
  noHeaders: PropTypes.bool,
  iconExtension: PropTypes.bool,
  searchVariant: PropTypes.string,
  message: PropTypes.string,
  noTopMargin: PropTypes.bool,
  enableGraph: PropTypes.bool,
  availableEntityTypes: PropTypes.array,
  availableRelationshipTypes: PropTypes.array,
  availableRelationFilterTypes: PropTypes.object,
  enableNestedView: PropTypes.bool,
  enableEntitiesView: PropTypes.bool,
  currentView: PropTypes.string,
  handleSwitchRedirectionMode: PropTypes.func,
  redirectionMode: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(ListLines);
