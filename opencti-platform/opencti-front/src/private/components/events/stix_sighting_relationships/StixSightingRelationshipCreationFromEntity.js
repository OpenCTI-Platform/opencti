import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Form, Formik, Field } from 'formik';
import { graphql } from 'react-relay';
import { assoc, compose, includes, pipe, pluck } from 'ramda';
import * as Yup from 'yup';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Add, ArrowRightAlt, Close } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import Skeleton from '@mui/material/Skeleton';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { dayStartDate, parse } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import TextField from '../../../../components/TextField';
import StixSightingRelationshipCreationFromEntityStixDomainObjectsLines, {
  stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixDomainObjectsLines';
import StixSightingRelationshipCreationFromEntityStixCyberObservablesLines, {
  stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixCyberObservablesLines';
import StixDomainObjectCreation from '../../common/stix_domain_objects/StixDomainObjectCreation';
import SearchInput from '../../../../components/SearchInput';
import { truncate } from '../../../../utils/String';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text.primary,
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
    color: theme.palette.text.primary,
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
  info: {
    paddingTop: 10,
  },
});

const stixSightingRelationshipCreationFromEntityQuery = graphql`
  query StixSightingRelationshipCreationFromEntityQuery($id: String!) {
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

const stixSightingRelationshipCreationFromEntityMutation = graphql`
  mutation StixSightingRelationshipCreationFromEntityMutation(
    $input: StixSightingRelationshipAddInput!
  ) {
    stixSightingRelationshipAdd(input: $input) {
      ...EntityStixSightingRelationshipLine_node
    }
  }
`;

const stixSightingRelationshipValidation = (t) => Yup.object().shape({
  attribute_count: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  description: Yup.string().nullable(),
  x_opencti_negative: Yup.boolean(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixSightingRelationships',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixSightingRelationshipCreationFromEntity extends Component {
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
    const { isTo, entityId } = this.props;
    const { targetEntity } = this.state;
    const fromEntityId = isTo ? targetEntity.id : entityId;
    const toEntityId = isTo ? entityId : targetEntity.id;
    const finalValues = pipe(
      assoc('confidence', parseInt(values.confidence, 10)),
      assoc('attribute_count', parseInt(values.attribute_count, 10)),
      assoc('fromId', fromEntityId),
      assoc('toId', toEntityId),
      assoc('first_seen', parse(values.first_seen).format()),
      assoc('last_seen', parse(values.last_seen).format()),
      assoc('createdBy', values.createdBy?.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
    )(values);
    commitMutation({
      mutation: stixSightingRelationshipCreationFromEntityMutation,
      variables: { input: finalValues },
      updater: (store) => {
        if (typeof this.props.onCreate !== 'function') {
          const payload = store.getRootField('stixSightingRelationshipAdd');
          const newEdge = payload.setLinkedRecord(payload, 'node');
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            this.props.paginationOptions,
            newEdge,
          );
        }
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        if (typeof this.props.onCreate === 'function') {
          this.props.onCreate();
        }
      },
    });
  }

  handleResetSelection() {
    this.setState({ step: 0, targetEntity: null });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  handleSelectEntity(stixDomainObject) {
    this.setState({ step: 1, targetEntity: stixDomainObject });
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

  renderDomainObjectSearchResults() {
    const { stixCoreObjectTypes } = this.props;

    if (
      !stixCoreObjectTypes
      || stixCoreObjectTypes.length === 0
    ) {
      return null;
    }

    const { search, open } = this.state;

    const stixDomainObjectsPaginationOptions = {
      search,
      types: stixCoreObjectTypes,
      count: 25,
      orderBy: 'created_at',
      orderMode: 'desc',
    };

    return (
      <div>
        <QueryRenderer
          query={
            stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery
          }
          variables={stixDomainObjectsPaginationOptions}
          render={({ props }) => {
            if (props) {
              return (
                <StixSightingRelationshipCreationFromEntityStixDomainObjectsLines
                  handleSelect={this.handleSelectEntity.bind(this)}
                  data={props}
                />
              );
            }
            return this.renderFakeList();
          }}
        />
        <StixDomainObjectCreation
          display={open}
          inputValue={search}
          paginationOptions={stixDomainObjectsPaginationOptions}
          stixDomainObjectTypes={stixCoreObjectTypes}
        />
      </div>
    );
  }

  renderObservableSearchResults() {
    const { stixCoreObjectTypes, targetStixCyberObservableTypes } = this.props;

    if (
      !targetStixCyberObservableTypes
      || targetStixCyberObservableTypes.length === 0
    ) {
      return null;
    }

    const { search } = this.state;

    return (
      <QueryRenderer
        query={
          stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery
        }
        variables={{
          search,
          types: targetStixCyberObservableTypes,
          count: 50,
          orderBy: 'created_at',
          orderMode: 'desc',
        }}
        render={({ props }) => {
          if (props) {
            return (
              <StixSightingRelationshipCreationFromEntityStixCyberObservablesLines
                handleSelect={this.handleSelectEntity.bind(this)}
                data={props}
              />
            );
          }
          return stixCoreObjectTypes.length === 0 ? (
            this.renderFakeList()
          ) : (
            <div> &nbsp; </div>
          );
        }}
      />
    );
  }

  renderSearchResults() {
    return (
      <div>
        {this.renderDomainObjectSearchResults()}
        {this.renderObservableSearchResults()}
      </div>
    );
  }

  renderSelectEntity() {
    const { classes, t } = this.props;
    const { search } = this.state;

    return (
      <div style={{ height: '100%' }}>
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
            {t('Create a sighting')}
          </Typography>
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              placeholder={`${t('Search')}...`}
              keyword={search}
              onSubmit={this.handleSearch.bind(this)}
            />
          </div>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
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
          {this.renderSearchResults()}
        </div>
      </div>
    );
  }

  renderForm(sourceEntity) {
    const { t, classes, isTo } = this.props;
    const { targetEntity } = this.state;
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (isTo) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }
    const initialValues = {
      confidence: 75,
      attribute_count: 1,
      first_seen: dayStartDate(),
      last_seen: dayStartDate(),
      description: '',
      objectMarking: [],
      createdBy: '',
      x_opencti_negative: false,
    };
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixSightingRelationshipValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={this.handleClose.bind(this)}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            <div className={classes.header}>
              <IconButton
                aria-label="Close"
                className={classes.closeButton}
                onClick={this.handleClose.bind(this)}
                size="large"
              >
                <Close fontSize="small" color="primary" />
              </IconButton>
              <Typography variant="h6">{t('Create a sighting')}</Typography>
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
                      {includes(
                        'Stix-Cyber-Observable',
                        fromEntity.parent_types,
                      )
                        ? t(`entity_${fromEntity.entity_type}`)
                        : t(
                          `entity_${
                            fromEntity.entity_type === 'stix_relation'
                              || fromEntity.entity_type === 'stix-relation'
                              ? fromEntity.parent_types[0]
                              : fromEntity.entity_type
                          }`,
                        )}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {truncate(
                        /* eslint-disable-next-line no-nested-ternary */
                        includes(
                          'Stix-Cyber-Observable',
                          fromEntity.parent_types,
                        )
                          ? fromEntity.observable_value
                          : fromEntity.entity_type === 'stix_relation'
                            || fromEntity.entity_type === 'stix-relation'
                            ? `${fromEntity.from.name} ${String.fromCharCode(
                              8594,
                            )} ${fromEntity.to.name}`
                            : fromEntity.name,
                        20,
                      )}
                    </span>
                  </div>
                </div>
                <div className={classes.middle} style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize="large" />
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
                      {includes('Stix-Cyber-Observable', toEntity.parent_types)
                        ? t(`entity_${toEntity.entity_type}`)
                        : t(
                          `entity_${
                            toEntity.entity_type === 'stix_relation'
                              || toEntity.entity_type === 'stix-relation'
                              ? toEntity.parent_types[0]
                              : toEntity.entity_type
                          }`,
                        )}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {truncate(
                        /* eslint-disable-next-line no-nested-ternary */
                        includes('Stix-Cyber-Observable', toEntity.parent_types)
                          ? toEntity.observable_value
                          : toEntity.entity_type === 'stix_relation'
                            || toEntity.entity_type === 'stix-relation'
                            ? `${toEntity.from.name} ${String.fromCharCode(
                              8594,
                            )} ${toEntity.to.name}`
                            : toEntity.name,
                        20,
                      )}
                    </span>
                  </div>
                </div>
              </div>
              <Field
                component={TextField}
                variant="standard"
                name="attribute_count"
                label={t('Count')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <ConfidenceField
                name="confidence"
                label={t('Confidence level')}
                fullWidth={true}
                containerStyle={fieldSpacingContainerStyle}
              />
              <Field
                component={DateTimePickerField}
                name="first_seen"
                TextFieldProps={{
                  label: t('First seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="last_seen"
                TextFieldProps={{
                  label: t('Last seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
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
              <CreatedByField
                name="createdBy"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={{ marginTop: 20, width: '100%' }}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="x_opencti_negative"
                label={t('False positive')}
                containerstyle={{ marginTop: 20 }}
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
                  color="secondary"
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
    const { classes, entityId, variant, paddingRight } = this.props;

    const { open, step } = this.state;

    return (
      <div>
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
        ) : (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
            style={{ right: paddingRight || 30 }}
          >
            <Add />
          </Fab>
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
            query={stixSightingRelationshipCreationFromEntityQuery}
            variables={{ id: entityId }}
            render={({ props }) => {
              if (props && props.stixCoreObject) {
                return (
                  <div style={{ height: '100%' }}>
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

StixSightingRelationshipCreationFromEntity.propTypes = {
  entityId: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  targetStixCyberObservableTypes: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  variant: PropTypes.string,
  onCreate: PropTypes.func,
  paddingRight: PropTypes.number,
  isTo: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipCreationFromEntity);
