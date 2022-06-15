import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import {
  compose, last, map, toPairs,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import {
  Edit,
  Share,
  ArrowDownward,
  ArrowUpward,
  ArrowDropDown,
  ArrowDropUp,
  AppsOutlined,
  AddCircleOutline,
} from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import Button from '@material-ui/core/Button';
import Tooltip from '@material-ui/core/Tooltip';
import Checkbox from '@material-ui/core/Checkbox';
import Alert from '@material-ui/lab/Alert';
import responsiblePartiesIcon from '../../resources/images/entities/responsible_parties.svg';
import tasksIcon from '../../resources/images/entities/tasks.svg';
import locations from '../../resources/images/entities/locations.svg';
import roles from '../../resources/images/entities/roles.svg';
import notesImage from '../../resources/images/entities/notes.svg';
import labels from '../../resources/images/entities/labelsImage.svg';
import parties from '../../resources/images/entities/parties.svg';
import assessmentPlatform from '../../resources/images/entities/assessment_platform.svg';
import SearchInput from '../SearchInput';
import inject18n from '../i18n';
// import Security, { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPDATE } from '../../utils/Security';
import Filters from '../../private/components/common/lists/Filters';
import { truncate } from '../../utils/String';
import TopBarMenu from '../../private/components/nav/TopBarMenu';

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
  toolBar: {
    margin: '-20px -24px 20px -24px',
    height: '100%',
    display: 'flex',
    '@media (max-width: 1400px)': {
      flexWrap: 'wrap',
    },
    justifyContent: 'space-between',
    alignItems: 'self-start',
    color: theme.palette.header.text,
    boxShadow: 'inset 0px 4px 4px rgba(0, 0, 0, 0.25)',
  },
  dataEntities: {
    width: '180px',
  },
  parameters: {
    // float: 'left',
    display: 'flex',
    '@media (max-width: 1250px)': {
      flexWrap: 'wrap',
    },
    padding: '18px 18px 0 18px',
  },
  searchBar: {
    width: '350px',
    minWidth: '350px',
  },
  views: {
    // float: 'right',
    width: '295px',
    minWidth: '285px',
    marginTop: '5px',
    padding: '14px 18px 12px 18px',
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '7px',
  },
  linesContainer: {
    marginTop: '10px',
    padding: '0px 16px 16px 16px',
  },
  linesContainerBottomNav: {
    margin: '10px 0 90px 0',
    padding: 0,
  },
  icon: {
    marginRight: '10px',
  },
  sortField: {
    float: 'left',
  },
  sortFieldLabel: {
    margin: '7px 15px',
    fontSize: 14,
    float: 'left',
    color: theme.palette.header.text,
  },
  listItem: {
    paddingLeft: 10,
    paddingTop: 0,
  },
  listScrollItem: {
    width: '83.5%',
    top: '64px',
    zIndex: 999,
    position: 'fixed',
    backgroundColor: theme.palette.header.background,
    padding: '10px 0 10px 10px',

  },
  sortArrowButton: {
    float: 'left',
    margin: '-9px 0 0 15px',
  },
  sortIcon: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
  },
  headerItem: {
    float: 'left',
    paddingLeft: 25,
    fontSize: 16,
    fontWeight: '700',
  },
  sortableHeaderItem: {
    float: 'left',
    paddingLeft: 24,
    fontSize: 16,
    fontWeight: '700',
    cursor: 'pointer',
  },
  filters: {
    padding: '0 0 9px 12px',
    '@media (max-width: 1250px)': {
      marginTop: '20px',
    },
  },
  filter: {
    marginRight: 10,
    marginBottom: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    marginRight: 10,
    marginBottom: 10,
  },
  info: {
    paddingTop: 10,
  },
});

class CyioListLines extends Component {
  constructor(props) {
    super(props);
    this.state = {
      scrollValue: 0,
    };
  }

  reverseBy(field) {
    this.props.handleSort(field, !this.props.orderAsc);
  }

  componentDidMount() {
    window.addEventListener('scroll', this.handleScroll.bind(this));
  }

  componentWillUnmount() {
    window.removeEventListener('scroll', this.handleScroll.bind(this));
  }

  handleScroll(event) {
    this.setState({ scrollValue: window.pageYOffset });
  }

  sortBy(event) {
    this.props.handleSort(event.target.value, this.props.orderAsc);
  }

  reverse() {
    this.props.handleSort(this.props.sortBy, !this.props.orderAsc);
  }

  renderHeaderElement(field, label, width, isSortable) {
    const {
      classes, t, sortBy, orderAsc, handleToggleSelectAll,
    } = this.props;
    if (isSortable) {
      const orderComponent = orderAsc ? (
        <ArrowDropDown
          classes={{ root: classes.sortIcon }}
        // style={{ top: typeof handleToggleSelectAll === 'function' ? 7 : 0 }}
        />
      ) : (
        <ArrowDropUp
          classes={{ root: classes.sortIcon }}
        // style={{ top: typeof handleToggleSelectAll === 'function' ? 7 : 0 }}
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
      sortBy,
      orderAsc,
      classes,
      handleSearch,
      handleChangeView,
      disableCards,
      handleAddFilter,
      handleRemoveFilter,
      selectedElements,
      handleToggleSelectAll,
      filterEntityType,
      selectAll,
      openExports,
      noPadding,
      noBottomPadding,
      dataColumns,
      secondaryAction,
      keyword,
      filters,
      disabled,
      bottomNav,
      children,
      handleDisplayEdit,
      numberOfElements,
      availableFilterKeys,
      handleNewCreation,
      noHeaders,
      iconExtension,
      searchVariant,
      selectedDataEntity,
      OperationsComponent,
      message,
    } = this.props;
    let className = classes.container;
    if (noBottomPadding) {
      className = classes.containerWithoutPadding;
    } else if (openExports && !noPadding) {
      className = classes.containerOpenExports;
    }
    return (
      <>
        <div
          className={classes.toolBar}
          elevation={1}
          style={{ backgroundColor: '#075AD333' }}
        >
          <div className={classes.parameters}>
            <div className={classes.searchBar}>
              {typeof handleSearch === 'function' && (
                <div style={{ float: 'left', marginRight: 20 }}>
                  <SearchInput
                    variant={searchVariant || 'small'}
                    onSubmit={handleSearch.bind(this)}
                    keyword={keyword}
                    disabled={true}
                  />
                </div>
              )}
              {availableFilterKeys && availableFilterKeys.length > 0 && (
                <Filters
                  availableFilterKeys={availableFilterKeys}
                  handleAddFilter={handleAddFilter}
                  currentFilters={filters}
                  filterEntityType={filterEntityType}
                />
              )}
              {numberOfElements && (
                <div style={{ float: 'left', padding: '5px' }}>
                  {t('Count:')}{' '}
                  <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>
                </div>
              )}
              {/* <InputLabel
                classes={{ root: classes.sortFieldLabel }}
                style={{
                  marginLeft:
                    availableFilterKeys && availableFilterKeys.length > 0 ? 10 : 0,
                }}
              >
                {t('Sort by')}
              </InputLabel>
              <FormControl classes={{ root: classes.sortField }}>
                <Select
                  name="sort-by"
                  value={sortBy}
                  onChange={this.sortBy.bind(this)}
                  inputProps={{
                    name: 'sort-by',
                    id: 'sort-by',
                  }}
                >
                  {toPairs(dataColumns).map((dataColumn) => (
                    dataColumn[1]?.isSortable
                    && <MenuItem key={dataColumn[0]} value={dataColumn[0]}>
                      {t(dataColumn[1].label)}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <IconButton
                aria-label="Sort by"
                onClick={this.reverse.bind(this)}
                classes={{ root: classes.sortArrowButton }}
              >
                {orderAsc ? <ArrowDownward /> : <ArrowUpward />}
              </IconButton> */}
              {(!availableFilterKeys || availableFilterKeys.length === 0)
                && !noHeaders && <div style={{ height: 38 }}> &nbsp; </div>}
            </div>
            {(filterEntityType === 'Entities' || filterEntityType === 'DataSources') && (
              <FormControl
                size='small'
                fullWidth={true}
                variant='outlined'
                className={classes.dataEntities}
              >
                <InputLabel>
                  Data Types
                </InputLabel>
                <Select
                  variant='outlined'
                  value={selectedDataEntity}
                  label='Data Types'
                  className={classes.dataEntitiesSelect}
                >
                  <MenuItem
                    component={Link}
                    to='/data/entities/roles'
                    value='roles'
                  >
                    <img src={roles} className={classes.icon} alt="" />
                    {t('Roles')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/locations'
                    value='locations'
                  >
                    <img src={locations} className={classes.icon} alt="" />
                    {t('Locations')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/parties'
                    value='parties'
                  >
                    <img src={parties} className={classes.icon} alt="" />
                    {t('Parties')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/responsible_parties'
                    value='responsible_parties'
                  >
                    <img src={responsiblePartiesIcon} style={{ marginRight: '12px' }} alt="" />
                    {t('Responsible Parties')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/tasks'
                    value='tasks'
                  >
                    <img src={tasksIcon} className={classes.icon} alt="" />
                    {t('Tasks')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/assessment_platform'
                    value='assessment_platform'
                  >
                    <img src={assessmentPlatform} className={classes.icon} alt="" />
                    {t('Assessment Platform')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/notes'
                    value='notes'
                  >
                    <img src={notesImage} className={classes.icon} alt="" />
                    {t('Notes')}
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to='/data/entities/labels'
                    value='labels'
                  >
                    <img src={labels} className={classes.icon} alt="" />
                    {t('Labels')}
                  </MenuItem>
                </Select>
              </FormControl>
            )}
            <div className={classes.filters}>
              {map((currentFilter) => {
                const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
                const values = (
                  <span>
                    {map(
                      (n) => (
                        <span key={n.value}>
                          {n.value && n.value.length > 0
                            ? truncate(n.value, 15)
                            : t('No label')}{' '}
                          {last(currentFilter[1]).value !== n.value && (
                            <code>OR</code>
                          )}
                        </span>
                      ),
                      currentFilter[1],
                    )}
                  </span>
                );
                return (
                  <span>
                    <Chip
                      key={currentFilter[0]}
                      classes={{ root: classes.filter }}
                      label={
                        <div>
                          <strong>{label}</strong>: {values}
                        </div>
                      }
                      onDelete={handleRemoveFilter.bind(this, currentFilter[0])}
                    />
                    {last(toPairs(filters))[0] !== currentFilter[0] && (
                      <Chip
                        classes={{ root: classes.operator }}
                        label={t('AND')}
                      />
                    )}
                  </span>
                );
              }, toPairs(filters))}
            </div>
          </div>
          <div className={classes.views}>
            <div style={{ float: 'right' }}>
              {typeof handleChangeView === 'function' && (
                // <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <>
                  <Tooltip title={t('Edit')}>
                    <Button
                      variant="contained"
                      onClick={handleDisplayEdit && handleDisplayEdit.bind(this, selectedElements)}
                      className={classes.iconButton}
                      disabled={Boolean(Object.entries(selectedElements || {}).length !== 1)
                        || disabled}
                      color="primary"
                      size="large"
                    >
                      <Edit fontSize="inherit" />
                    </Button>
                  </Tooltip>
                  {(filterEntityType === 'Entities' || filterEntityType === 'DataSources') && (
                    <Tooltip title={t('Merge')}>
                      <Button
                        variant="contained"
                        // onClick={handleDisplayEdit &&
                        // handleDisplayEdit.bind(this, selectedElements)}
                        className={classes.iconButton}
                        // disabled={Boolean(Object.entries(selectedElements || {}).length !== 1)
                        //   || disabled}
                        disabled={true}
                        color="primary"
                        size="large"
                      >
                        <Share fontSize="inherit" />
                      </Button>
                    </Tooltip>
                  )}
                  <div style={{ display: 'inline-block' }}>
                    {OperationsComponent && React.cloneElement(OperationsComponent, {
                      id: Object.entries(selectedElements || {}).length !== 0
                        && Object.entries(selectedElements)[0][0],
                      isAllselected: selectAll,
                    })}
                  </div>
                  <Tooltip title={t('Create New')}>
                    <Button
                      variant="contained"
                      size="small"
                      startIcon={<AddCircleOutline />}
                      onClick={handleNewCreation && handleNewCreation.bind(this)}
                      color='primary'
                      disabled={disabled || false}
                      style={{ marginTop: '-22px' }}
                    >
                      {t('New')}
                    </Button>
                  </Tooltip>
                </>
                // </Security>
              )}
              {typeof handleChangeView === 'function' && !disableCards && (
                <Tooltip title={t('Cards view')}>
                  <IconButton
                    color="primary"
                    onClick={handleChangeView.bind(this, 'cards')}
                    style={{ marginTop: '-23px' }}
                  >
                    <AppsOutlined />
                  </IconButton>
                </Tooltip>
              )}
            </div>
          </div>
        </div>
        <div className={className}>
          <div className="clearfix" />
          <TopBarMenu />
          {message && (
            <div style={{ width: '100%' }}>
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
          >
            {!noHeaders ? (
              <ListItem
                divider={true}
                className={this.state.scrollValue > 130
                  ? classes.listScrollItem
                  : classes.listItem}
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
        </div>
      </>
    );
  }
}

CyioListLines.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  selectedElements: PropTypes.object,
  disablePopover: PropTypes.bool,
  children: PropTypes.object,
  handleSearch: PropTypes.func,
  handleSort: PropTypes.func,
  handleChangeView: PropTypes.func,
  disableCards: PropTypes.bool,
  enableDuplicates: PropTypes.bool,
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
  disabled: PropTypes.bool,
  sortBy: PropTypes.string,
  orderAsc: PropTypes.bool,
  selectedDataEntity: PropTypes.string,
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
};

export default compose(inject18n, withRouter, withStyles(styles))(CyioListLines);
