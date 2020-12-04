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
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
// TODO @SAM Fix cyclic redundancies
// eslint-disable-next-line import/no-cycle
import ContainerAddStixCoreObjectsLines, {
  containerAddStixCoreObjectsLinesQuery,
} from './ContainerAddStixCoreObjectsLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import StixCoreObjectUseSearchMessage from '../stix_core_objects/StixCoreObjectUseSearchMessage';

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
    return includes('Stix-Domain-Object', types);
  }

  static isTypeObservable(types) {
    return includes('Stix-Cyber-Observable', types);
  }

  renderDomainObjectCreation(paginationOptions) {
    const {
      defaultCreatedBy,
      defaultMarkingDefinitions,
    } = this.props;

    const { open, search } = this.state;

    return <StixDomainObjectCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationKey='Pagination_stixCoreObjects'
        paginationOptions={paginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
    />;
  }

  renderObservableCreation(paginationOptions) {
    const {
      defaultCreatedBy,
      defaultMarkingDefinitions,
    } = this.props;

    const { open, search } = this.state;

    return <StixCyberObservableCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={paginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
    />;
  }

  renderEntityCreation(paginationOptions) {
    const { targetStixCoreObjectTypes } = this.props;

    if (targetStixCoreObjectTypes
        && ContainerAddStixCoreObjects.isTypeDomainObject(targetStixCoreObjectTypes)
        && !ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)) {
      return this.renderDomainObjectCreation(paginationOptions);
    }

    if (targetStixCoreObjectTypes
        && ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)
        && !ContainerAddStixCoreObjects.isTypeDomainObject(targetStixCoreObjectTypes)) {
      return this.renderObservableCreation(paginationOptions);
    }

    if (!targetStixCoreObjectTypes
        || (ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)
            && ContainerAddStixCoreObjects.isTypeDomainObject(targetStixCoreObjectTypes))) {
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
    } = this.props;

    return (
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
                />
            );
          }
          return (
            <List>
              {Array.from(Array(20), (e, i) => (
                <ListItem key={i} divider={true} button={false}>
                  <ListItemIcon>
                    <Avatar classes={{ root: classes.avatar }}>
                      {i}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <span
                          className="fakeItem"
                          style={{ width: '80%' }}
                      />
                    }
                    secondary={
                      <span
                          className="fakeItem"
                          style={{ width: '90%' }}
                      />
                    }
                  />
                </ListItem>
              ))}
            </List>
          );
        }}
      />
    );
  }

  renderSearch(paginationOptions) {
    const { search } = this.state;

    if (search === '') {
      return <StixCoreObjectUseSearchMessage />;
    }

    return this.renderSearchResults(paginationOptions);
  }

  getSearchTypes() {
    const {
      paginationOptions,
      targetStixCoreObjectTypes,
    } = this.props;

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
    let orderBy = 'name';
    if (targetStixCoreObjectTypes
        && ContainerAddStixCoreObjects.isTypeObservable(targetStixCoreObjectTypes)) {
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

    if (types.length === 1
        && (ContainerAddStixCoreObjects.isTypeDomainObject(types)
            || ContainerAddStixCoreObjects.isTypeObservable(types))) {
      return null;
    }

    const { t } = this.props;

    const renderedTypes = types.map((type) => (
        <Chip
            key={type}
            style={{ marginLeft: '5px' }}
            label={t(`entity_${type}`)}
            onDelete={this.onSearchTypeFilterDelete.bind(this, type)}
        />
    ));

    return (
        <div style={{ margin: '20px 20px 0 20px' }}>
          <span style={{ marginRight: '5px' }}>{t('Applied type filter(s):')}</span>
          <span>{renderedTypes}</span>
        </div>
    );
  }

  render() {
    const {
      t,
      classes,
      withPadding,
      simple,
    } = this.props;
    const paginationOptions = this.getPaginationOptions();

    return (
      <div>
        {simple ? (
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
              withPadding
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
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add entities')}
            </Typography>
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.container}>
            {this.renderSearchTypeFilter(paginationOptions)}
            {this.renderSearch(paginationOptions)}
          </div>
        </Drawer>
        {this.renderEntityCreation(paginationOptions)}
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
};

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerAddStixCoreObjects);
