import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add, ChevronRightOutlined, Close } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import Skeleton from '@mui/material/Skeleton';
import { commitMutation, handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationFromEntityStixDomainObjectsLines, {
  stixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixDomainObjectsLines';
import StixCoreRelationshipCreationFromEntityStixCyberObservablesLines, {
  stixCoreRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixCyberObservablesLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import SearchInput from '../../../../components/SearchInput';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { isNodeInConnection } from '../../../../utils/store';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
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
  continue: {
    position: 'fixed',
    bottom: 40,
    right: 30,
    zIndex: 1001,
  },
});

const stixCoreRelationshipCreationFromEntityQuery = graphql`
  query StixCoreRelationshipCreationFromEntityQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      parent_types
      ... on AttackPattern {
        name
      }
      ... on Campaign {
        name
      }
      ... on CourseOfAction {
        name
      }
      ... on Individual {
        name
      }
      ... on Organization {
        name
      }
      ... on Sector {
        name
      }
      ... on System {
        name
      }
      ... on Indicator {
        name
      }
      ... on Infrastructure {
        name
      }
      ... on IntrusionSet {
        name
      }
      ... on Position {
        name
      }
      ... on City {
        name
      }
      ... on AdministrativeArea {
        name
      }
      ... on Country {
        name
      }
      ... on Region {
        name
      }
      ... on Malware {
        name
      }
      ... on ThreatActorGroup {
        name
      }
      ... on Tool {
        name
      }
      ... on Vulnerability {
        name
      }
      ... on Incident {
        name
      }
      ... on Event {
        name
      }
      ... on Channel {
        name
      }
      ... on Narrative {
        name
      }
      ... on Language {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Case {
        name
      }
      ... on MalwareAnalysis {
        result_name
      }
      ... on StixCyberObservable {
        observable_value
      }
    }
  }
`;

const stixCoreRelationshipCreationFromEntityFromMutation = graphql`
  mutation StixCoreRelationshipCreationFromEntityFromMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineAll_node
    }
  }
`;

const stixCoreRelationshipCreationFromEntityToMutation = graphql`
  mutation StixCoreRelationshipCreationFromEntityToMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineAll_node
    }
  }
`;

class StixCoreRelationshipCreationFromEntity extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      step: 0,
      targetEntities: [],
      search: '',
    };
  }

  componentDidUpdate(prevProps) {
    if (
      this.props.targetEntities
      && this.props.targetEntities.length > 0
      && !R.equals(this.props.targetEntities, prevProps.targetEntities)
    ) {
      this.setState({
        open: true,
        step: 1,
        targetEntities: this.props.targetEntities,
      });
    }
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ step: 0, targetEntities: [], open: false });
  }

  commit(finalValues) {
    const { isRelationReversed, connectionKey } = this.props;
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: isRelationReversed
          ? stixCoreRelationshipCreationFromEntityToMutation
          : stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        updater: (store) => {
          if (typeof this.props.onCreate !== 'function') {
            const userProxy = store.get(store.getRoot().getDataID());
            const payload = store.getRootField('stixCoreRelationshipAdd');
            const createdNode = connectionKey
              ? payload.getLinkedRecord(isRelationReversed ? 'from' : 'to')
              : payload;
            const connKey = connectionKey || 'Pagination_stixCoreRelationships';
            // When using connectionKey we use less props of PaginationOptions, we need to filter them
            const { paginationOptions } = this.props;
            const conn = ConnectionHandler.getConnection(
              userProxy,
              connKey,
              paginationOptions,
            );
            if (!isNodeInConnection(payload, conn)) {
              const newEdge = payload.setLinkedRecord(createdNode, 'node');
              ConnectionHandler.insertEdgeBefore(conn, newEdge);
            }
          }
        },
        onError: (error) => {
          reject(error);
        },
        onCompleted: (response) => {
          resolve(response);
        },
      });
    });
  }

  async onSubmit(values, { setSubmitting, setErrors, resetForm }) {
    const { isRelationReversed, entityId } = this.props;
    const { targetEntities } = this.state;
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = isRelationReversed ? targetEntity.id : entityId;
      const toEntityId = isRelationReversed ? entityId : targetEntity.id;
      const finalValues = R.pipe(
        R.assoc('confidence', parseInt(values.confidence, 10)),
        R.assoc('fromId', fromEntityId),
        R.assoc('toId', toEntityId),
        R.assoc('start_time', formatDate(values.start_time)),
        R.assoc('stop_time', formatDate(values.stop_time)),
        R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
        R.assoc('createdBy', values.createdBy?.value),
        R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
        R.assoc(
          'externalReferences',
          R.pluck('value', values.externalReferences),
        ),
      )(values);
      try {
        // eslint-disable-next-line no-await-in-loop
        await this.commit(finalValues);
      } catch (error) {
        setSubmitting(false);
        return handleErrorInForm(error, setErrors);
      }
    }
    setSubmitting(false);
    resetForm();
    this.handleClose();
    if (typeof this.props.onCreate === 'function') {
      this.props.onCreate();
    }
    return true;
  }

  handleResetSelection() {
    this.setState({ step: 0, targetEntities: [] });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  handleSelectEntity(stixDomainObject) {
    this.setState({
      targetEntities: R.includes(
        stixDomainObject.id,
        R.pluck('id', this.state.targetEntities),
      )
        ? R.filter(
          (n) => n.id !== stixDomainObject.id,
          this.state.targetEntities,
        )
        : R.append(stixDomainObject, this.state.targetEntities),
    });
  }

  handleNextStep() {
    this.setState({ step: 1 });
  }

  // eslint-disable-next-line class-methods-use-this
  renderFakeList() {
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
  }

  renderSelectEntity() {
    const { search, targetEntities } = this.state;
    const {
      classes,
      t,
      targetStixDomainObjectTypes,
      targetStixCyberObservableTypes,
    } = this.props;
    const stixDomainObjectsPaginationOptions = {
      search,
      types: targetStixDomainObjectTypes,
      orderBy: search.length > 0 ? null : 'created_at',
      orderMode: search.length > 0 ? null : 'desc',
    };
    const stixCyberObservablesPaginationOptions = {
      search,
      types: targetStixCyberObservableTypes,
      orderBy: search.length > 0 ? null : 'created_at',
      orderMode: search.length > 0 ? null : 'desc',
    };
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
            size="large"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Create a relationship')}
          </Typography>
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              placeholder={`${t('Search')}...`}
              onSubmit={this.handleSearch.bind(this)}
            />
          </div>
          <div className="clearfix" />
        </div>
        <div className={classes.containerList}>
          {targetStixDomainObjectTypes
            && targetStixDomainObjectTypes.length > 0 && (
              <QueryRenderer
                query={
                  stixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery
                }
                variables={{ count: 25, ...stixDomainObjectsPaginationOptions }}
                render={({ props }) => {
                  if (props) {
                    return (
                      <StixCoreRelationshipCreationFromEntityStixDomainObjectsLines
                        handleSelect={this.handleSelectEntity.bind(this)}
                        targetEntities={targetEntities}
                        data={props}
                      />
                    );
                  }
                  return this.renderFakeList();
                }}
              />
          )}
          {targetStixCyberObservableTypes
            && targetStixCyberObservableTypes.length > 0 && (
              <QueryRenderer
                query={
                  stixCoreRelationshipCreationFromEntityStixCyberObservablesLinesQuery
                }
                variables={{
                  count: 25,
                  ...stixCyberObservablesPaginationOptions,
                }}
                render={({ props }) => {
                  if (props) {
                    return (
                      <StixCoreRelationshipCreationFromEntityStixCyberObservablesLines
                        noPadding={!!targetStixDomainObjectTypes}
                        targetEntities={targetEntities}
                        handleSelect={this.handleSelectEntity.bind(this)}
                        data={props}
                      />
                    );
                  }
                  return !targetStixDomainObjectTypes
                  || targetStixDomainObjectTypes.length === 0 ? (
                      this.renderFakeList()
                    ) : (
                    <div> &nbsp; </div>
                    );
                }}
              />
          )}
          {targetEntities.length === 0
            && !targetStixCyberObservableTypes
            && targetStixDomainObjectTypes
            && targetStixDomainObjectTypes.length > 0 && (
              <StixDomainObjectCreation
                display={this.state.open}
                inputValue={this.state.search}
                paginationOptions={stixDomainObjectsPaginationOptions}
                stixDomainObjectTypes={targetStixDomainObjectTypes}
              />
          )}
          {targetEntities.length === 0
            && (!targetStixDomainObjectTypes
              || targetStixDomainObjectTypes.length === 0)
            && targetStixCyberObservableTypes
            && targetStixCyberObservableTypes.length > 0 && (
              <StixCyberObservableCreation
                display={this.state.open}
                contextual={true}
                inputValue={this.state.search}
                paginationKey="Pagination_stixCyberObservables"
                paginationOptions={stixCyberObservablesPaginationOptions}
                targetStixDomainObjectTypes={targetStixCyberObservableTypes}
              />
          )}
          {targetEntities.length > 0 && (
            <Fab
              variant="extended"
              className={classes.continue}
              size="small"
              color="secondary"
              onClick={this.handleNextStep.bind(this)}
            >
              {t('Continue')}
              <ChevronRightOutlined />
            </Fab>
          )}
        </div>
      </div>
    );
  }

  renderForm(sourceEntity) {
    const {
      t,
      classes,
      isRelationReversed,
      allowedRelationshipTypes,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const { targetEntities } = this.state;
    let fromEntities = [sourceEntity];
    let toEntities = targetEntities;
    if (isRelationReversed) {
      // eslint-disable-next-line prefer-destructuring
      fromEntities = targetEntities;
      toEntities = [sourceEntity];
    }
    const relationshipTypes = R.filter(
      (n) => R.isNil(allowedRelationshipTypes)
        || allowedRelationshipTypes.length === 0
        || allowedRelationshipTypes.includes('stix-core-relationship')
        || allowedRelationshipTypes.includes(n),
      resolveRelationsTypes(fromEntities[0].entity_type, toEntities[0].entity_type),
    );
    return (
      <>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
            size="large"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a relationship')}</Typography>
        </div>
      <StixCoreRelationshipCreationForm
        fromEntities={fromEntities}
        toEntities={toEntities}
        relationshipTypes={relationshipTypes}
        handleReverseRelation={this.props.handleReverseRelation}
        handleResetSelection={this.handleResetSelection.bind(this)}
        onSubmit={this.onSubmit.bind(this)}
        handleClose={this.handleClose.bind(this)}
        defaultStartTime={defaultStartTime}
        defaultStopTime={defaultStopTime}/>
    </>
    );
  }

  // eslint-disable-next-line
  renderLoader() {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  }

  render() {
    const { classes, entityId, variant, paddingRight, openExports } = this.props;
    const { open, step } = this.state;
    return (
      <div>
        {/* eslint-disable-next-line no-nested-ternary */}
        {variant === 'inLine' ? (
          <IconButton
            color="secondary"
            aria-label="Label"
            onClick={this.handleOpen.bind(this)}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            size="large"
          >
            <Add fontSize="small" />
          </IconButton>
        ) : !openExports ? (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
            style={{ right: paddingRight || 30 }}
          >
            <Add />
          </Fab>
        ) : (
          ''
        )}
        <Drawer
          open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: this.props.classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={stixCoreRelationshipCreationFromEntityQuery}
            variables={{ id: entityId }}
            render={({ props }) => {
              if (props && props.stixCoreObject) {
                return (
                  <div style={{ minHeight: '100%' }}>
                    {step === 0 ? this.renderSelectEntity() : ''}
                    {step === 1 ? this.renderForm(props.stixCoreObject) : ''}
                  </div>
                );
              }
              return this.renderLoader();
            }}
          />
        </Drawer>
      </div>
    );
  }
}

StixCoreRelationshipCreationFromEntity.propTypes = {
  entityId: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  targetStixDomainObjectTypes: PropTypes.array,
  targetStixCyberObservableTypes: PropTypes.array,
  allowedRelationshipTypes: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  variant: PropTypes.string,
  onCreate: PropTypes.func,
  paddingRight: PropTypes.number,
  openExports: PropTypes.bool,
  connectionKey: PropTypes.string,
  connectionIsFrom: PropTypes.bool,
  handleReverseRelation: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
  isEntitiesView: PropTypes.bool,
  entitiesViewPaginationKey: PropTypes.string,
  targetEntities: PropTypes.array,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreationFromEntity);
