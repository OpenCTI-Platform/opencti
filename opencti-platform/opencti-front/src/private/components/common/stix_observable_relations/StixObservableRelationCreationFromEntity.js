import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, map, pipe, head, assoc,
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
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { dayStartDate, parse } from '../../../../utils/Time';
import {
  resolveRoles,
  resolveRelationsTypes,
} from '../../../../utils/Relation';
import ItemIcon from '../../../../components/ItemIcon';
import SelectField from '../../../../components/SelectField';
import DatePickerField from '../../../../components/DatePickerField';
import StixObservableRelationCreationFromEntityLines, {
  stixObservableRelationCreationFromEntityLinesQuery,
} from './StixObservableRelationCreationFromEntityLines';
import StixObservableCreation from '../../signatures/stix_observables/StixObservableCreation';
import SearchInput from '../../../../components/SearchInput';
import { truncate } from '../../../../utils/String';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';

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
});

const stixObservableRelationCreationFromEntityQuery = graphql`
  query StixObservableRelationCreationFromEntityQuery($id: String) {
    stixEntity(id: $id) {
      id
      entity_type
      parent_types
      name
      description
      ... on StixObservable {
        observable_value
      }
    }
  }
`;

const stixObservableRelationCreationFromEntityMutation = graphql`
  mutation StixObservableRelationCreationFromEntityMutation(
    $input: StixObservableRelationAddInput!
  ) {
    stixObservableRelationAdd(input: $input) {
      ...StixObservableObservableLine_node
    }
  }
`;

const stixObservableRelationValidation = (t) => Yup.object().shape({
  relationship_type: Yup.string().required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixObservableRelations',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixObservableRelationCreationFromEntity extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      step: 0,
      targetEntity: null,
      search: '',
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ step: 0, targetEntity: null, open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const roles = resolveRoles(values.relationship_type);
    const fromEntityId = this.props.entityId;
    const toEntityId = this.state.targetEntity.id;
    const finalValues = pipe(
      assoc('fromId', fromEntityId),
      assoc('fromRole', this.props.isFrom ? roles.fromRole : roles.toRole),
      assoc('toId', toEntityId),
      assoc('toRole', this.props.isFrom ? roles.toRole : roles.fromRole),
      assoc('first_seen', parse(values.first_seen).format()),
      assoc('last_seen', parse(values.last_seen).format()),
    )(values);
    commitMutation({
      mutation: stixObservableRelationCreationFromEntityMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('stixObservableRelationAdd');
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
            query={stixObservableRelationCreationFromEntityLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixObservableRelationCreationFromEntityLines
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
          <StixObservableCreation
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
    const { t, classes, isFrom } = this.props;
    const { targetEntity } = this.state;
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (!isFrom) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }
    const relationshipTypes = resolveRelationsTypes(
      fromEntity.entity_type,
      toEntity.entity_type,
      false,
    );
    const defaultRelationshipType = head(relationshipTypes)
      ? head(relationshipTypes)
      : 'linked';
    const initialValues = {
      relationship_type: defaultRelationshipType,
      role_played: 'Unknown',
      first_seen: dayStartDate(),
      last_seen: dayStartDate(),
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
                validationSchema={stixObservableRelationValidation(t)}
                onSubmit={this.onSubmit.bind(this)}
                onReset={this.handleClose.bind(this)}
              >
                {({ submitForm, handleReset, isSubmitting }) => (
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
                                type={fromEntity.entity_type}
                                color={itemColor(fromEntity.entity_type)}
                                size="small"
                              />
                            </div>
                            <div className={classes.type}>
                              {t(`observable_${fromEntity.entity_type}`)}
                            </div>
                          </div>
                          <div className={classes.content}>
                            <span className={classes.name}>
                              {truncate(fromEntity.observable_value, 20)}
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
                                type={toEntity.entity_type}
                                color={itemColor(toEntity.entity_type)}
                                size="small"
                              />
                            </div>
                            <div className={classes.type}>
                              {t(`observable_${toEntity.entity_type}`)}
                            </div>
                          </div>
                          <div className={classes.content}>
                            <span className={classes.name}>
                              {truncate(toEntity.observable_value, 20)}
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
                        {map(
                          (type) => (
                            <MenuItem key={type} value={type}>
                              {t(`relation_${type}`)}
                            </MenuItem>
                          ),
                          relationshipTypes,
                        )}
                        <MenuItem value="linked">
                          {t('relation_linked')}
                        </MenuItem>
                      </Field>
                      <Field
                        component={SelectField}
                        name="role_played"
                        label={t('Played role')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      >
                        {rolesPlayedEdges.map((rolePlayedEdge) => (
                          <MenuItem
                            key={rolePlayedEdge.node.value}
                            value={rolePlayedEdge.node.value}
                          >
                            {t(rolePlayedEdge.node.value)}
                          </MenuItem>
                        ))}
                      </Field>
                      <Field
                        component={DatePickerField}
                        name="first_seen"
                        label={t('First seen')}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        component={DatePickerField}
                        name="last_seen"
                        label={t('Last seen')}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
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
          return <Loader variant="inElement" />;
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
            query={stixObservableRelationCreationFromEntityQuery}
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

StixObservableRelationCreationFromEntity.propTypes = {
  entityId: PropTypes.string,
  isFrom: PropTypes.bool,
  targetEntityTypes: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  variant: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableRelationCreationFromEntity);
