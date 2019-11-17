import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Field, Form } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import {
  compose,
  map,
  pipe,
  head,
  assoc,
  pathOr,
  pluck,
  sortWith,
  ascend,
  path,
  union,
} from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import { Close, ArrowRightAlt, Add } from '@material-ui/icons';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Avatar from '@material-ui/core/Avatar';
import ListItemText from '@material-ui/core/ListItemText';
import Fab from '@material-ui/core/Fab';
import CircularProgress from '@material-ui/core/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import {
  commitMutation,
  fetchQuery,
  QueryRenderer,
} from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { parse } from '../../../../utils/Time';
import {
  resolveRoles,
  resolveRelationsTypes,
} from '../../../../utils/Relation';
import ItemIcon from '../../../../components/ItemIcon';
import TextField from '../../../../components/TextField';
import Select from '../../../../components/Select';
import DatePickerField from '../../../../components/DatePickerField';
import StixRelationCreationFromEntityStixDomainEntitiesLines, {
  stixRelationCreationFromEntityStixDomainEntitiesLinesQuery,
} from './StixRelationCreationFromEntityStixDomainEntitiesLines';
import StixRelationCreationFromEntityStixObservablesLines, {
  stixRelationCreationFromEntityStixObservablesLinesQuery,
} from './StixRelationCreationFromEntityStixObservablesLines';
import StixDomainEntityCreation from '../stix_domain_entities/StixDomainEntityCreation';
import SearchInput from '../../../../components/SearchInput';
import Autocomplete from '../../../../components/Autocomplete';
import { markingDefinitionsSearchQuery } from '../../settings/MarkingDefinitions';
import { killChainPhasesSearchQuery } from '../../settings/KillChainPhases';
import { truncate } from '../../../../utils/String';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import StixObservableCreation from '../../stix_observables/StixObservableCreation';

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
    right: 290,
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
});

const stixRelationCreationFromEntityQuery = graphql`
  query StixRelationCreationFromEntityQuery($id: String) {
    stixEntity(id: $id) {
      id
      entity_type
      name
      description
      parent_type
      ... on StixObservable {
        observable_value
      }
    }
  }
`;

const stixRelationCreationFromEntityMutation = graphql`
  mutation StixRelationCreationFromEntityMutation(
    $input: StixRelationAddInput!
  ) {
    stixRelationAdd(input: $input) {
      ...EntityStixRelationLine_node
    }
  }
`;

const stixRelationValidation = (t) => Yup.object().shape({
  relationship_type: Yup.string().required(t('This field is required')),
  weight: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  description: Yup.string(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixRelations',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixRelationCreationFromEntity extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      step: 0,
      targetEntity: null,
      search: '',
      killChainPhases: [],
      markingDefinitions: [],
      currentType: props.currentType ? props.currentType : null,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ step: 0, targetEntity: null, open: false });
  }

  searchKillchainPhases(event) {
    fetchQuery(killChainPhasesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const killChainPhases = pipe(
        pathOr([], ['killChainPhases', 'edges']),
        sortWith([ascend(path(['node', 'order']))]),
        map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(data);
      this.setState({
        killChainPhases: union(this.state.killChainPhases, killChainPhases),
      });
    });
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map((n) => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      this.setState({ markingDefinitions });
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { isFrom, isFromRelation } = this.props;
    const { targetEntity } = this.state;
    const roles = resolveRoles(values.relationship_type);
    const fromEntityId = this.props.entityId;
    const toEntityId = this.state.targetEntity.id;
    const finalValues = pipe(
      assoc('fromId', fromEntityId),
      assoc(
        'fromRole',
        isFrom
          && !(isFromRelation && targetEntity.parent_type === 'Stix-Observable')
          ? roles.fromRole
          : roles.toRole,
      ),
      assoc('toId', toEntityId),
      assoc(
        'toRole',
        isFrom
          && !(isFromRelation && targetEntity.parent_type === 'Stix-Observable')
          ? roles.toRole
          : roles.fromRole,
      ),
      assoc('first_seen', parse(values.first_seen).format()),
      assoc('last_seen', parse(values.last_seen).format()),
      assoc('killChainPhases', pluck('value', values.killChainPhases)),
      assoc('markingDefinitions', pluck('value', values.markingDefinitions)),
    )(values);
    commitMutation({
      mutation: stixRelationCreationFromEntityMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('stixRelationAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  handleResetSelection() {
    this.setState({ step: 0, targetEntity: null });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  handleSelectEntity(stixDomainEntity) {
    this.setState({ step: 1, targetEntity: stixDomainEntity });
  }

  renderSelectEntity() {
    const { classes, t, targetEntityTypes } = this.props;
    const paginationOptions = {
      search: this.state.search,
      types: targetEntityTypes,
      orderBy: 'created_at',
      orderMode: 'desc',
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
          <QueryRenderer
            query={stixRelationCreationFromEntityStixDomainEntitiesLinesQuery}
            variables={{
              search: this.state.search,
              types: targetEntityTypes,
              count: 50,
              orderBy: 'created_at',
              orderMode: 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixRelationCreationFromEntityStixDomainEntitiesLines
                    handleSelect={this.handleSelectEntity.bind(this)}
                    data={props}
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
          <QueryRenderer
            query={stixRelationCreationFromEntityStixObservablesLinesQuery}
            variables={{
              search: this.state.search,
              types: targetEntityTypes,
              count: 50,
              orderBy: 'created_at',
              orderMode: 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixRelationCreationFromEntityStixObservablesLines
                    handleSelect={this.handleSelectEntity.bind(this)}
                    data={props}
                  />
                );
              }
              return <div> &nbsp; </div>;
            }}
          />
          <StixDomainEntityCreation
            display={this.state.open}
            contextual={true}
            inputValue={this.state.search}
            paginationOptions={paginationOptions}
            targetEntityTypes={targetEntityTypes}
          />
        </div>
      </div>
    );
  }

  renderForm(sourceEntity) {
    const {
      t, classes, isFrom, isFromRelation,
    } = this.props;
    const { targetEntity } = this.state;
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (
      !isFrom
      || (isFromRelation && targetEntity.parent_type === 'Stix-Observable')
    ) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }
    const relationshipTypes = resolveRelationsTypes(
      fromEntity.parent_type === 'Stix-Observable'
        ? 'observable'
        : fromEntity.entity_type,
      toEntity.entity_type,
    );
    const defaultRelationshipType = head(relationshipTypes)
      ? head(relationshipTypes)
      : 'related-to';
    const initialValues = {
      relationship_type: defaultRelationshipType,
      weight: 1,
      role_played: '',
      first_seen: new Date(),
      last_seen: new Date(),
      description: '',
      killChainPhases: [],
      markingDefinitions: [],
    };
    return (
      <QueryRenderer
        query={attributesQuery}
        variables={{ type: 'role_played' }}
        render={({ props }) => {
          if (props && props.attributes) {
            const rolesPlayedEdges = props.attributes.edges;
            return (
              <Formik
                enableReinitialize={true}
                initialValues={initialValues}
                validationSchema={stixRelationValidation(t)}
                onSubmit={this.onSubmit.bind(this)}
                onReset={this.handleClose.bind(this)}
                render={({ submitForm, handleReset, isSubmitting }) => (
                  <Form>
                    <div className={classes.header}>
                      <IconButton
                        aria-label="Close"
                        className={classes.closeButton}
                        onClick={this.handleClose.bind(this)}
                      >
                        <Close fontSize="small" />
                      </IconButton>
                      <Typography variant="h6">
                        {t('Create a relationship')}
                      </Typography>
                    </div>
                    <div className={classes.containerRelation}>
                      <div className={classes.relationCreate}>
                        <div
                          className={classes.item}
                          style={{
                            border: `2px solid ${itemColor(
                              fromEntity.entity_type,
                            )}`,
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
                                type={fromEntity.type}
                                color={itemColor(fromEntity.entity_type)}
                                size="small"
                              />
                            </div>
                            <div className={classes.type}>
                              {fromEntity.parent_type === 'Stix-Observable'
                                ? t(`observable_${fromEntity.entity_type}`)
                                : t(`entity_${fromEntity.entity_type}`)}
                            </div>
                          </div>
                          <div className={classes.content}>
                            <span className={classes.name}>
                              {truncate(
                                fromEntity.parent_type === 'Stix-Observable'
                                  ? fromEntity.observable_value
                                  : fromEntity.name,
                                20,
                              )}
                            </span>
                          </div>
                        </div>
                        <div
                          className={classes.middle}
                          style={{ paddingTop: 25 }}
                        >
                          <ArrowRightAlt fontSize="large" />
                        </div>
                        <div
                          className={classes.item}
                          style={{
                            border: `2px solid ${itemColor(
                              toEntity.entity_type,
                            )}`,
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
                                type={toEntity.type}
                                color={itemColor(toEntity.entity_type)}
                                size="small"
                              />
                            </div>
                            <div className={classes.type}>
                              {toEntity.parent_type === 'Stix-Observable'
                                ? t(`observable_${toEntity.entity_type}`)
                                : t(`entity_${toEntity.entity_type}`)}
                            </div>
                          </div>
                          <div className={classes.content}>
                            <span className={classes.name}>
                              {truncate(
                                toEntity.parent_type === 'Stix-Observable'
                                  ? toEntity.observable_value
                                  : toEntity.name,
                                20,
                              )}
                            </span>
                          </div>
                        </div>
                      </div>
                      <Field
                        name="relationship_type"
                        component={Select}
                        label={t('Relationship type')}
                        fullWidth={true}
                        inputProps={{
                          name: 'relationship_type',
                          id: 'relationship_type',
                        }}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                        onChange={(name, value) => {
                          this.setState({ currentType: value });
                        }}
                      >
                        {map(
                          (type) => (
                            <MenuItem key={type} value={type}>
                              {t(`relation_${type}`)}
                            </MenuItem>
                          ),
                          relationshipTypes,
                        )}
                        <MenuItem value="related-to">
                          {t('relation_related-to')}
                        </MenuItem>
                      </Field>
                      <Field
                        name="weight"
                        component={Select}
                        label={t('Confidence level')}
                        fullWidth={true}
                        inputProps={{
                          name: 'weight',
                          id: 'weight',
                        }}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      >
                        <MenuItem value={1}>{t('Low')}</MenuItem>
                        <MenuItem value={2}>{t('Moderate')}</MenuItem>
                        <MenuItem value={3}>{t('Good')}</MenuItem>
                        <MenuItem value={4}>{t('Strong')}</MenuItem>
                      </Field>
                      {this.state.currentType === 'indicates' ? (
                        <Field
                          name="role_played"
                          component={Select}
                          label={t('Played role')}
                          fullWidth={true}
                          inputProps={{
                            name: 'role_played',
                            id: 'role_played',
                          }}
                          containerstyle={{ marginTop: 20, width: '100%' }}
                        >
                          {rolesPlayedEdges.map((rolePlayedEdge) => (
                            <MenuItem
                              key={rolePlayedEdge.node.value}
                              value={rolePlayedEdge.node.value}
                            >
                              {rolePlayedEdge.node.value}
                            </MenuItem>
                          ))}
                        </Field>
                      ) : (
                        ''
                      )}
                      <Field
                        name="first_seen"
                        component={DatePickerField}
                        label={t('First seen')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        name="last_seen"
                        component={DatePickerField}
                        label={t('Last seen')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        name="description"
                        component={TextField}
                        label={t('Description')}
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        name="killChainPhases"
                        component={Autocomplete}
                        multiple={true}
                        label={t('Kill chain phases')}
                        options={this.state.killChainPhases}
                        onInputChange={this.searchKillchainPhases.bind(this)}
                      />
                      <Field
                        name="markingDefinitions"
                        component={Autocomplete}
                        multiple={true}
                        label={t('Marking')}
                        options={this.state.markingDefinitions}
                        onInputChange={this.searchMarkingDefinitions.bind(this)}
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
              />
            );
          }
          return <div> &nbsp; </div>;
        }}
      />
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
    const { classes, entityId, variant } = this.props;
    const { open, step } = this.state;
    return (
      <div>
        {variant === 'inLine' ? (
          <IconButton
            color="secondary"
            aria-label="Tag"
            onClick={this.handleOpen.bind(this)}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          >
            <Add fontSize="small" />
          </IconButton>
        ) : (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
          >
            <Add />
          </Fab>
        )}
        <Drawer
          open={open}
          anchor="right"
          classes={{ paper: this.props.classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={stixRelationCreationFromEntityQuery}
            variables={{ id: entityId }}
            render={({ props }) => {
              if (props && props.stixEntity) {
                return (
                  <div>
                    {step === 0 ? this.renderSelectEntity() : ''}
                    {step === 1 ? this.renderForm(props.stixEntity) : ''}
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

StixRelationCreationFromEntity.propTypes = {
  entityId: PropTypes.string,
  isFrom: PropTypes.bool,
  isFromRelation: PropTypes.bool,
  targetEntityTypes: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  variant: PropTypes.string,
  currentType: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationCreationFromEntity);
