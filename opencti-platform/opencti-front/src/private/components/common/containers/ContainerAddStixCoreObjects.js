import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import Avatar from '@material-ui/core/Avatar';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import Alert from '@material-ui/lab/Alert';
import Tooltip from '@material-ui/core/Tooltip';
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
    backgroundColor: theme.palette.navAlt.background,
    padding: 0,
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
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
});

class ContainerAddStixCoreObjects extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
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
      return this.renderDomainObjectCreation(paginationOptions);
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
                      <Avatar classes={{ root: classes.avatar }}>{i}</Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <span className="fakeItem" style={{ width: '80%' }} />
                      }
                      secondary={
                        <span className="fakeItem" style={{ width: '90%' }} />
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
    const {
      t,
      classes,
      withPadding,
      simple,
      knowledgeGraph,
      openExports,
    } = this.props;
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
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
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
