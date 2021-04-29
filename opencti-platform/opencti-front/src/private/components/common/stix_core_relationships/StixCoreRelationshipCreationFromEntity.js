import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Form, Formik, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import * as R from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import {
  Add,
  ArrowRightAlt,
  ChevronRightOutlined,
  Close,
} from '@material-ui/icons';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Avatar from '@material-ui/core/Avatar';
import ListItemText from '@material-ui/core/ListItemText';
import Fab from '@material-ui/core/Fab';
import CircularProgress from '@material-ui/core/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { parse } from '../../../../utils/Time';
import {
  hasKillChainPhase,
  resolveRelationsTypes,
} from '../../../../utils/Relation';
import ItemIcon from '../../../../components/ItemIcon';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import DatePickerField from '../../../../components/DatePickerField';
import StixCoreRelationshipCreationFromEntityStixDomainObjectsLines, {
  stixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixDomainObjectsLines';
import StixCoreRelationshipCreationFromEntityStixCyberObservablesLines, {
  stixCoreRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixCyberObservablesLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import SearchInput from '../../../../components/SearchInput';
import { truncate } from '../../../../utils/String';
import KillChainPhasesField from '../form/KillChainPhasesField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ConfidenceField from '../form/ConfidenceField';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
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
  containerRelation: {
    padding: '10px 20px 20px 20px',
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
    marginBottom: 10,
  },
  relationCreation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: '#ffffff',
  },
  buttonBack: {
    marginTop: 20,
    textAlign: 'left',
    float: 'left',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
    float: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
      ... on Country {
        name
      }
      ... on Region {
        name
      }
      ... on Malware {
        name
      }
      ... on ThreatActor {
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

const stixCoreRelationshipValidation = (t) => Yup.object().shape({
  relationship_type: Yup.string().required(t('This field is required')),
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  start_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  stop_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  description: Yup.string(),
});

const sharedUpdater = (
  store,
  userId,
  paginationOptions,
  newEdge,
  connectionKey = null,
) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    connectionKey || 'Pagination_stixCoreRelationships',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

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
            const payload = store.getRootField('stixCoreRelationshipAdd');
            const newEdge = payload.setLinkedRecord(
              connectionKey
                ? payload.getLinkedRecord(isRelationReversed ? 'from' : 'to')
                : payload,
              'node',
            );
            const container = store.getRoot();
            sharedUpdater(
              store,
              container.getDataID(),
              this.props.paginationOptions,
              newEdge,
              connectionKey,
            );
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

  async onSubmit(values, { setSubmitting, resetForm }) {
    const { isRelationReversed, entityId } = this.props;
    const { targetEntities } = this.state;
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = isRelationReversed ? targetEntity.id : entityId;
      const toEntityId = isRelationReversed ? entityId : targetEntity.id;
      const finalValues = R.pipe(
        R.assoc('fromId', fromEntityId),
        R.assoc('toId', toEntityId),
        R.assoc(
          'start_time',
          values.start_time ? parse(values.start_time).format() : null,
        ),
        R.assoc(
          'stop_time',
          values.stop_time ? parse(values.stop_time).format() : null,
        ),
        R.assoc('createdBy', values.createdBy.value),
        R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
        R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      )(values);
      // eslint-disable-next-line no-await-in-loop
      await this.commit(finalValues);
    }
    setSubmitting(false);
    resetForm();
    this.handleClose();
    if (typeof this.props.onCreate === 'function') {
      this.props.onCreate();
    }
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

  renderFakeList() {
    return (
      <List>
        {Array.from(Array(20), (e, i) => (
          <ListItem key={i} divider={true} button={false}>
            <ListItemIcon>
              <Avatar classes={{ root: this.props.classes.avatar }}>{i}</Avatar>
            </ListItemIcon>
            <ListItemText
              primary={<span className="fakeItem" style={{ width: '80%' }} />}
              secondary={<span className="fakeItem" style={{ width: '90%' }} />}
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
          >
            <Close fontSize="small" />
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
                contextual={true}
                inputValue={this.state.search}
                paginationOptions={stixDomainObjectsPaginationOptions}
                targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              />
          )}
          {targetEntities.length === 0
            && !targetStixDomainObjectTypes
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
    } = this.props;
    const { targetEntities } = this.state;
    const isMultiple = targetEntities.length > 1;
    let fromEntity = sourceEntity;
    let toEntity = targetEntities[0];
    if (isRelationReversed) {
      // eslint-disable-next-line prefer-destructuring
      fromEntity = targetEntities[0];
      toEntity = sourceEntity;
    }
    const relationshipTypes = R.filter(
      (n) => R.isNil(allowedRelationshipTypes)
        || allowedRelationshipTypes.length === 0
        || allowedRelationshipTypes.includes('stix-core-relationship')
        || allowedRelationshipTypes.includes(n),
      resolveRelationsTypes(fromEntity.entity_type, toEntity.entity_type),
    );
    // eslint-disable-next-line no-nested-ternary
    const defaultRelationshipType = R.head(relationshipTypes)
      ? R.head(relationshipTypes)
      : relationshipTypes.includes('related-to')
        ? 'related-to'
        : '';
    const initialValues = {
      relationship_type: defaultRelationshipType,
      confidence: 15,
      start_time: null,
      stop_time: null,
      description: '',
      killChainPhases: [],
      objectMarking: [],
      createdBy: '',
    };
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixCoreRelationshipValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={this.handleClose.bind(this)}
      >
        {({
          submitForm, handleReset, isSubmitting, setFieldValue, values,
        }) => (
          <Form style={{ paddingBottom: 50 }}>
            <div className={classes.header}>
              <IconButton
                aria-label="Close"
                className={classes.closeButton}
                onClick={this.handleClose.bind(this)}
              >
                <Close fontSize="small" />
              </IconButton>
              <Typography variant="h6">{t('Create a relationship')}</Typography>
            </div>
            <div className={classes.containerRelation}>
              <div className={classes.relationCreate}>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(fromEntity.entity_type)}`,
                    top: 10,
                    left: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        fromEntity.entity_type,
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={fromEntity.entity_type}
                        color={itemColor(fromEntity.entity_type)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {t(fromEntity.entity_type)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {isRelationReversed && isMultiple ? (
                        <em>{t('Multiple entities selected')}</em>
                      ) : (
                        truncate(
                          R.includes(
                            'Stix-Cyber-Observable',
                            fromEntity.parent_types,
                          )
                            ? fromEntity.observable_value
                            : fromEntity.name,
                          20,
                        )
                      )}
                    </span>
                  </div>
                </div>
                <div className={classes.middle} style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize="large" />
                  <br />
                  {typeof this.props.handleReverseRelation === 'function' && (
                    <Button
                      variant="outlined"
                      onClick={this.props.handleReverseRelation.bind(this)}
                      color="secondary"
                      size="small"
                    >
                      {t('Reverse')}
                    </Button>
                  )}
                </div>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(toEntity.entity_type)}`,
                    top: 10,
                    right: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        toEntity.entity_type,
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={toEntity.entity_type}
                        color={itemColor(toEntity.entity_type)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {t(toEntity.entity_type)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {!isRelationReversed && isMultiple ? (
                        <em>{t('Multiple entities selected')}</em>
                      ) : (
                        truncate(
                          R.includes(
                            'Stix-Cyber-Observable',
                            toEntity.parent_types,
                          )
                            ? toEntity.observable_value
                            : toEntity.name,
                          20,
                        )
                      )}
                    </span>
                  </div>
                </div>
              </div>
              <Field
                component={SelectField}
                name="relationship_type"
                label={t('Relationship type')}
                fullWidth={true}
                containerstyle={{ marginTop: 20, width: '100%' }}
              >
                {R.map(
                  (type) => (
                    <MenuItem key={type} value={type}>
                      {t(`relationship_${type}`)}
                    </MenuItem>
                  ),
                  relationshipTypes,
                )}
              </Field>
              <ConfidenceField
                name="confidence"
                label={t('Confidence level')}
                fullWidth={true}
                containerstyle={{ marginTop: 20, width: '100%' }}
              />
              <Field
                component={DatePickerField}
                name="start_time"
                label={t('Start time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={DatePickerField}
                name="stop_time"
                label={t('Stop time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={MarkDownField}
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
              />
              {hasKillChainPhase(values.relationship_type) ? (
                <KillChainPhasesField
                  name="killChainPhases"
                  style={{ marginTop: 20, width: '100%' }}
                />
              ) : (
                ''
              )}
              <CreatedByField
                name="createdBy"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={{ marginTop: 20, width: '100%' }}
              />
              <div className={classes.buttonBack}>
                <Button
                  variant="contained"
                  onClick={this.handleResetSelection.bind(this)}
                  disabled={isSubmitting}
                >
                  {t('Back')}
                </Button>
              </div>
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
                </Button>
              </div>
            </div>
          </Form>
        )}
      </Formik>
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
    const {
      classes,
      entityId,
      variant,
      paddingRight,
      openExports,
    } = this.props;
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
  nsd: PropTypes.func,
  variant: PropTypes.string,
  onCreate: PropTypes.func,
  paddingRight: PropTypes.number,
  openExports: PropTypes.bool,
  connectionKey: PropTypes.string,
  connectionIsFrom: PropTypes.bool,
  handleReverseRelation: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreationFromEntity);
