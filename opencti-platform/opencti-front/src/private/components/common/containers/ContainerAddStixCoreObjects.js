import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import Alert from '@mui/material/Alert';
import Tooltip from '@mui/material/Tooltip';
import Skeleton from '@mui/material/Skeleton';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import ContainerAddStixCoreObjectsLines, {
  containerAddStixCoreObjectsLinesQuery,
} from './ContainerAddStixCoreObjectsLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',

    padding: 0,
    zIndex: 1,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  createButtonExports: {
    position: 'fixed',
    bottom: 30,
    right: 590,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  createButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    zIndex: 1100,
  },
  createButtonSimple: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
    height: '100%',
    width: '100%',
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
  },
  speedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  info: {
    paddingTop: 10,
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
});

class ContainerAddStixCoreObjects extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      openSpeedDial: false,
      openCreateEntity: false,
      openCreateObservable: false,
      search: '',
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleOpenSpeedDial() {
    this.setState({ openSpeedDial: true });
  }

  handleCloseSpeedDial() {
    this.setState({ openSpeedDial: false });
  }

  handleOpenCreateEntity() {
    this.setState({ openCreateEntity: true, openSpeedDial: false });
  }

  handleCloseCreateEntity() {
    this.setState({ openCreateEntity: false, openSpeedDial: false });
  }

  handleOpenCreateObservable() {
    this.setState({ openCreateObservable: true, openSpeedDial: false });
  }

  handleCloseCreateObservable() {
    this.setState({ openCreateObservable: false, openSpeedDial: false });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  static isTypeDomainObject(types) {
    return !types || includes('Stix-Domain-Object', types);
  }

  static isTypeObservable(types) {
    return !types || includes('Stix-Cyber-Observable', types);
  }

  renderDomainObjectCreation(paginationOptions) {
    const {
      defaultCreatedBy,
      defaultMarkingDefinitions,
      confidence,
      targetStixCoreObjectTypes,
    } = this.props;
    const { open, search } = this.state;
    return (
      <StixDomainObjectCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={paginationOptions}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        targetStixDomainObjectTypes={
          targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
            ? targetStixCoreObjectTypes
            : []
        }
      />
    );
  }

  renderObservableCreation(paginationOptions) {
    const { defaultCreatedBy, defaultMarkingDefinitions } = this.props;
    const { open, search } = this.state;
    return (
      <StixCyberObservableCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={paginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
      />
    );
  }

  renderStixCoreObjectCreation(paginationOptions) {
    const {
      classes,
      defaultCreatedBy,
      defaultMarkingDefinitions,
      confidence,
      targetStixCoreObjectTypes,
      t,
    } = this.props;
    const {
      open,
      openSpeedDial,
      openCreateEntity,
      openCreateObservable,
      search,
    } = this.state;
    return (
      <div>
        <SpeedDial
          className={classes.createButton}
          ariaLabel="Create"
          icon={<SpeedDialIcon />}
          onClose={this.handleCloseSpeedDial.bind(this)}
          onOpen={this.handleOpenSpeedDial.bind(this)}
          open={openSpeedDial}
          FabProps={{
            color: 'secondary',
          }}
        >
          <SpeedDialAction
            title={t('Create an observable')}
            icon={<HexagonOutline />}
            tooltipTitle={t('Create an observable')}
            onClick={this.handleOpenCreateObservable.bind(this)}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
          <SpeedDialAction
            title={t('Create an entity')}
            icon={<GlobeModel />}
            tooltipTitle={t('Create an entity')}
            onClick={this.handleOpenCreateEntity.bind(this)}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
        </SpeedDial>
        <StixDomainObjectCreation
          display={open}
          contextual={true}
          inputValue={search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={paginationOptions}
          confidence={confidence}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          targetStixDomainObjectTypes={
            targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
              ? targetStixCoreObjectTypes
              : []
          }
          speeddial={true}
          open={openCreateEntity}
          handleClose={this.handleCloseCreateEntity.bind(this)}
        />
        <StixCyberObservableCreation
          display={open}
          contextual={true}
          inputValue={search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={paginationOptions}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          speeddial={true}
          open={openCreateObservable}
          handleClose={this.handleCloseCreateObservable.bind(this)}
        />
      </div>
    );
  }

  renderEntityCreation(paginationOptions) {
    const { targetStixCoreObjectTypes } = this.props;
    if (
      targetStixCoreObjectTypes
      && ContainerAddStixCoreObjects.isTypeDomainObject(
        targetStixCoreObjectTypes,
      )
      && !ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)
    ) {
      return this.renderDomainObjectCreation(paginationOptions);
    }
    if (
      targetStixCoreObjectTypes
      && ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)
      && !ContainerAddStixCoreObjects.isTypeDomainObject(targetStixCoreObjectTypes)
    ) {
      return this.renderObservableCreation(paginationOptions);
    }
    if (
      !targetStixCoreObjectTypes
      || (ContainerAddStixCoreObjects.isTypeObservable(
        targetStixCoreObjectTypes,
      )
        && ContainerAddStixCoreObjects.isTypeDomainObject(
          targetStixCoreObjectTypes,
        ))
    ) {
      return this.renderStixCoreObjectCreation(paginationOptions);
    }
    return null;
  }

  renderSearchResults(paginationOptions) {
    const {
      classes,
      containerId,
      knowledgeGraph,
      containerStixCoreObjects,
      t,
    } = this.props;
    const { search } = this.state;

    return (
      <div>
        {search.length === 0 && (
          <Alert
            severity="info"
            variant="outlined"
            style={{ margin: '15px 15px 0 15px' }}
            classes={{ message: classes.info }}
          >
            {t(
              'This panel shows by default the latest created entities, use the search to find more.',
            )}
          </Alert>
        )}
        <QueryRenderer
          query={containerAddStixCoreObjectsLinesQuery}
          variables={{ count: 100, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <ContainerAddStixCoreObjectsLines
                  containerId={containerId}
                  data={props}
                  paginationOptions={this.props.paginationOptions}
                  knowledgeGraph={knowledgeGraph}
                  containerStixCoreObjects={containerStixCoreObjects}
                  onAdd={this.props.onAdd}
                  onDelete={this.props.onDelete}
                />
              );
            }
            return (
              <List>
                {Array.from(Array(20), (e, i) => (
                  <ListItem key={i} divider={true} button={false}>
                    <ListItemIcon>
                      <Skeleton
                        animation="wave"
                        variant="circular"
                        width={30}
                        height={30}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      }
                      secondary={
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      }
                    />
                  </ListItem>
                ))}
              </List>
            );
          }}
        />
      </div>
    );
  }

  renderSearch(paginationOptions) {
    return this.renderSearchResults(paginationOptions);
  }

  getSearchTypes() {
    const { paginationOptions, targetStixCoreObjectTypes } = this.props;
    let searchTypes;
    if (targetStixCoreObjectTypes !== undefined) {
      searchTypes = [...targetStixCoreObjectTypes];
    }
    if (paginationOptions !== undefined) {
      const { types } = paginationOptions;
      searchTypes = [...types];
    }
    return searchTypes;
  }

  getPaginationOptions() {
    const { targetStixCoreObjectTypes } = this.props;
    const { search } = this.state;
    let orderMode = 'desc';
    let orderBy = 'created_at';
    if (
      targetStixCoreObjectTypes
      && ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)
    ) {
      orderBy = 'created_at';
    }
    if (search.length > 0) {
      orderBy = null;
      orderMode = null;
    }
    const types = this.getSearchTypes();
    return {
      types,
      search,
      orderBy,
      orderMode,
    };
  }

  onSearchTypeFilterDelete(typeFilter) {
    this.props.onTypesChange(typeFilter);
  }

  renderSearchTypeFilter(paginationOptions) {
    if (!paginationOptions) {
      return null;
    }
    const { types } = paginationOptions;
    if (!types) {
      return null;
    }
    if (
      types.length === 1
      && (ContainerAddStixCoreObjects.isTypeDomainObject(types)
        || ContainerAddStixCoreObjects.isTypeObservable(types))
    ) {
      return null;
    }

    const { t } = this.props;

    const renderedTypes = types.map((type) => (
      <Chip
        key={type}
        color="secondary"
        style={{ marginLeft: '10px' }}
        label={t(`entity_${type}`)}
        onDelete={
          typeof this.props.onTypesChange === 'function'
            ? this.onSearchTypeFilterDelete.bind(this, type)
            : null
        }
      />
    ));

    return (
      <div style={{ float: 'left', margin: '-3px 0 0 5px' }}>
        {renderedTypes}
      </div>
    );
  }

  render() {
    const { t, classes, withPadding, simple, knowledgeGraph, openExports } = this.props;
    const paginationOptions = this.getPaginationOptions();
    return (
      <div>
        {/* eslint-disable-next-line no-nested-ternary */}
        {knowledgeGraph ? (
          <Tooltip title={t('Add an entity to this container')}>
            <IconButton
              color="primary"
              aria-label="Add"
              onClick={this.handleOpen.bind(this)}
              size="large"
            >
              <Add />
            </IconButton>
          </Tooltip>
        ) : simple ? (
          <IconButton
            color="secondary"
            aria-label="Add"
            onClick={this.handleOpen.bind(this)}
            classes={{ root: classes.createButtonSimple }}
            size="large"
          >
            <Add fontSize="small" />
          </IconButton>
        ) : (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={
              // eslint-disable-next-line no-nested-ternary
              openExports
                ? classes.createButtonExports
                : withPadding
                  ? classes.createButtonWithPadding
                  : classes.createButton
            }
          >
            <Add />
          </Fab>
        )}
        <Drawer
          open={this.state.open}
          keepMounted={true}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            {(ContainerAddStixCoreObjects.isTypeDomainObject(
              paginationOptions.types,
            )
              || ContainerAddStixCoreObjects.isTypeObservable(
                paginationOptions.types,
              )) && (
              <Typography variant="h6" classes={{ root: classes.title }}>
                {t('Add entities')}
              </Typography>
            )}
            {this.renderSearchTypeFilter(paginationOptions)}
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.container}>
            {this.renderSearch(paginationOptions)}
          </div>
          {this.renderEntityCreation(paginationOptions)}
        </Drawer>
      </div>
    );
  }
}

ContainerAddStixCoreObjects.propTypes = {
  containerId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  withPadding: PropTypes.bool,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.array,
  confidence: PropTypes.number,
  containerStixCoreObjects: PropTypes.array,
  simple: PropTypes.bool,
  targetStixCoreObjectTypes: PropTypes.array,
  onTypesChange: PropTypes.func,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerAddStixCoreObjects);
