import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import withStyles from '@mui/styles/withStyles';
import { graphql, createFragmentContainer } from 'react-relay';
import { withRouter } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Fab from '@mui/material/Fab';
import {
  Add,
  ArrowDropDown,
  ArrowDropUp,
  Close,
  DoubleArrow,
  DeleteOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Checkbox from '@mui/material/Checkbox';
import { v4 as uuid } from 'uuid';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Slide from '@mui/material/Slide';
import inject18n from '../../../../components/i18n';
import {
  booleanAttributes,
  dateAttributes,
  markdownAttributes,
  numberAttributes,
  resolveIdentityClass,
  resolveIdentityType,
  resolveLocationType,
  typesContainers,
  workbenchAttributes,
} from '../../../../utils/Entity';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import SwitchField from '../../../../components/SwitchField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import MarkDownField from '../../../../components/MarkDownField';
import {
  convertFromStixType,
  convertToStixType,
  truncate,
} from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import ItemBoolean from '../../../../components/ItemBoolean';
import StixItemLabels from '../../../../components/StixItemLabels';
import { defaultValue } from '../../../../utils/Graph';
import StixItemMarkings from '../../../../components/StixItemMarkings';
import { buildDate } from '../../../../utils/Time';
import DynamicResolutionField from '../../common/form/DynamicResolutionField';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
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
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
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
  linesContainer: {
    marginTop: 0,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  sortIcon: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
  },
});

const inlineStylesHeaders = {
  ttype: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  default_value: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  labels: {
    float: 'left',
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  markings: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  in_platform: {
    float: 'left',
    width: '8%',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  ttype: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  default_value: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  labels: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  markings: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  in_platform: {
    float: 'left',
    width: '8%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

export const workbenchFileContentAttributesQuery = graphql`
  query WorkbenchFileContentAttributesQuery($elementType: String!) {
    schemaAttributes(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

const workbenchFileContentMutation = graphql`
  mutation WorkbenchFileContentMutation($file: Upload!, $entityId: String) {
    uploadPending(file: $file, entityId: $entityId) {
      id
    }
  }
`;

class WorkbenchFileContentComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentTab: 0,
      // Bundle
      stixDomainObjects: [],
      stixCyberObservables: [],
      stixCoreRelationships: [],
      containers: [],
      // Control
      sortBy: 'default_value',
      orderAsc: true,
      entityStep: null,
      entityType: null,
      entityId: null,
      deleteEntity: null,
    };
  }

  loadFileContent() {
    const { file } = this.props;
    const url = `/storage/view/${encodeURIComponent(file.id)}`;
    Axios.get(url).then(async (res) => {
      this.setState(this.computeState(res.data.objects));
      return true;
    });
  }

  saveFile() {
    const { file } = this.props;
    const {
      stixDomainObjects,
      stixCyberObservables,
      stixCoreRelationships,
      containers,
    } = this.state;
    let entityId = null;
    if (file.metaData.entity) {
      entityId = file.metaData.entity.standard_id;
    }
    const data = {
      id: `bundle--${uuid()}`,
      type: 'bundle',
      objects: [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...containers,
      ],
    };
    const json = JSON.stringify(data);
    const blob = new Blob([json], { type: 'text/json' });
    const fileToUpload = new File([blob], file.name, {
      type: 'application/json',
    });
    commitMutation({
      mutation: workbenchFileContentMutation,
      variables: { file: fileToUpload, id: entityId },
    });
  }

  componentDidMount() {
    this.loadFileContent();
  }

  // eslint-disable-next-line class-methods-use-this
  resolveMarkings(objects, markingIds) {
    if (markingIds) {
      return objects.filter((n) => markingIds.includes(n.id));
    }
    return [];
  }

  computeState(objects) {
    const { stixDomainObjectTypes, observableTypes, t } = this.props;
    const sdoTypes = [
      ...stixDomainObjectTypes.edges.map((n) => convertToStixType(n.node.id)),
      'marking-definition',
      'identity',
      'location',
    ].filter((n) => !typesContainers.includes(n));
    const scoTypes = observableTypes.edges.map((n) => convertToStixType(n.node.id));
    const stixDomainObjects = objects.filter((n) => sdoTypes.includes(n.type));
    const stixCyberObservables = objects.filter((n) => scoTypes.includes(n.type));
    const containers = objects.filter((n) => typesContainers.includes(n.type));
    return { stixDomainObjects, stixCyberObservables, containers };
  }

  findEntityById(id) {
    return R.head(this.state.stixDomainObjects.filter((n) => n.id === id));
  }

  submitDeleteEntity() {
    const {
      deleteEntity,
      stixDomainObjects,
      stixCyberObservables,
      stixCoreRelationships,
      containers,
    } = this.state;
    let finalStixDomainObjects = stixDomainObjects.filter(
      (n) => n.id !== deleteEntity.id,
    );
    let finalStixCyberObservables = stixCyberObservables.filter(
      (n) => n.id !== deleteEntity.id,
    );
    let finalStixCoreRelationships = stixCoreRelationships.filter(
      (n) => n.id !== deleteEntity.id,
    );
    let finalContainers = containers.filter((n) => n.id !== deleteEntity.id);
    if (deleteEntity.type === 'identity') {
      finalStixDomainObjects = finalStixDomainObjects.map((n) => (n.created_by_ref === deleteEntity.id ? R.dissoc('created_by_ref', n) : n));
      finalStixCyberObservables = finalStixCyberObservables.map((n) => (n.created_by_ref === deleteEntity.id ? R.dissoc('created_by_ref', n) : n));
      finalStixCoreRelationships = finalStixCoreRelationships.map((n) => (n.created_by_ref === deleteEntity.id ? R.dissoc('created_by_ref', n) : n));
      finalContainers = finalContainers.map((n) => (n.created_by_ref === deleteEntity.id ? R.dissoc('created_by_ref', n) : n));
    } else if (deleteEntity.type === 'marking-definition') {
      finalStixDomainObjects = finalStixDomainObjects.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== deleteEntity.id),
        n,
      ));
      finalStixCyberObservables = finalStixCyberObservables.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== deleteEntity.id),
        n,
      ));
      finalStixCoreRelationships = finalStixCoreRelationships.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== deleteEntity.id),
        n,
      ));
      finalContainers = finalContainers.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== deleteEntity.id),
        n,
      ));
    }
    // Impact
    const stixCoreRelationshipsToRemove = finalStixCoreRelationships
      .filter(
        (n) => n.source_ref === deleteEntity.id || n.target_ref === deleteEntity.id,
      )
      .map((n) => n.id);
    finalContainers = finalContainers.map((n) => R.assoc(
      'object_refs',
      n.object_refs.filter(
        (o) => o !== deleteEntity.id && !stixCoreRelationshipsToRemove.includes(o),
      ),
      n,
    ));
    finalStixCoreRelationships = finalContainers.map((n) => R.assoc(
      'object_refs',
      n.object_refs.filter((o) => !stixCoreRelationshipsToRemove.includes(o)),
      n,
    ));
    this.setState({
      stixDomainObjects: finalStixDomainObjects,
      stixCyberObservables: finalStixCyberObservables,
      stixCoreRelationships: finalStixCoreRelationships,
      containers: finalContainers,
      deleteEntity: null,
    });
  }

  handleDeleteEntity(entity) {
    this.setState({ deleteEntity: entity });
  }

  handleCloseDeleteEntity() {
    this.setState({ deleteEntity: null });
  }

  convertCreatedByRef(entity) {
    if (entity && entity.created_by_ref) {
      const createdBy = this.findEntityById(entity.created_by_ref);
      if (createdBy) {
        return {
          label: createdBy.name,
          value: createdBy.id,
          entity: createdBy,
        };
      }
    }
    return '';
  }

  // eslint-disable-next-line class-methods-use-this
  convertLabels(entity) {
    if (entity && entity.labels) {
      return entity.labels.map((n) => ({ label: n, value: n }));
    }
    return [];
  }

  // eslint-disable-next-line class-methods-use-this
  convertExternalReferences(entity) {
    if (entity && entity.external_references) {
      return entity.external_references.map((n) => ({
        label: `[${n.source_name}] ${truncate(
          n.description || n.url || n.external_id,
          150,
        )}`,
        value: n.id,
        entity: n,
      }));
    }
    return [];
  }

  convertMarkings(entity) {
    if (entity && entity.object_marking_refs) {
      return entity.object_marking_refs
        .map((n) => {
          const marking = this.findEntityById(n);
          if (marking) {
            return {
              label: marking.name || marking.definition,
              value: marking.id,
              entity: marking,
            };
          }
          return null;
        })
        .filter((n) => n !== null);
    }
    return [];
  }

  handleChangeTab(_, index) {
    this.setState({ currentTab: index });
  }

  handleOpenEntity(entityType, entityId) {
    this.setState({
      entityStep: 0,
      entityType: convertFromStixType(entityType),
      entityId,
    });
  }

  handleCloseEntity() {
    this.setState({
      entityStep: null,
      entityType: null,
      entityId: null,
    });
  }

  selectEntityType(entityType) {
    this.setState({ entityType });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t, classes } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    ) : (
      <ArrowDropUp classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  renderEntityTypesList() {
    const { t, stixDomainObjectTypes } = this.props;
    const subTypesEdges = stixDomainObjectTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.filter((n) => !typesContainers.includes(n.label)),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItem
            key={subType.label}
            divider={true}
            button={true}
            dense={true}
            onClick={this.selectEntityType.bind(this, subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItem>
        ))}
      </List>
    );
  }

  renderEntityForm() {
    const { entityType, entityId, stixDomainObjects } = this.state;
    const { classes, t } = this.props;
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    let type = entityType;
    if (type === 'Identity' && entity) {
      type = resolveIdentityType(entity.identity_class);
    } else if (type === 'Location' && entity) {
      type = resolveLocationType(entity);
    }
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: type }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: this.convertCreatedByRef(entity),
              objectMarking: this.convertMarkings(entity),
              objectLabel: this.convertLabels(entity),
              externalReferences: this.convertExternalReferences(entity),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributes.edges),
              ),
              workbenchAttributes,
            );
            for (const attribute of attributes) {
              if (R.includes(attribute, dateAttributes)) {
                initialValues[attribute] = entity[attribute]
                  ? buildDate(entity[attribute])
                  : null;
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = entity[attribute] || false;
              } else {
                initialValues[attribute] = entity[attribute] || '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={this.onSubmitEntity.bind(this)}
                onReset={this.onResetEntity.bind(this)}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{ margin: '0 0 20px 0', padding: '0 15px 0 15px' }}
                  >
                    <div>
                      {attributes.map((attribute) => {
                        if (R.includes(attribute, dateAttributes)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute}
                              name={attribute}
                              withSeconds={true}
                              TextFieldProps={{
                                label: attribute,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (R.includes(attribute, numberAttributes)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth={true}
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, booleanAttributes)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, markdownAttributes)) {
                          return (
                            <Field
                              component={MarkDownField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth={true}
                              multiline={true}
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute}
                            name={attribute}
                            label={attribute}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={{ marginTop: 20, width: '100%' }}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
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
                        startIcon={<DoubleArrow />}
                        variant="contained"
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Context')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  }

  renderEntityContext() {
    const { entityType, entityId, stixDomainObjects } = this.state;
    const { classes, t } = this.props;
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    let type = entityType;
    if (type === 'Identity' && entity) {
      type = resolveIdentityType(entity.identity_class);
    } else if (type === 'Location' && entity) {
      type = resolveLocationType(entity);
    }
    const targetsVictimology = [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ];
    const usesAttackPatterns = [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ];
    const targetsVulnerabilities = [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ];
    const attributedToThreats = [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ];
    const isTargetedByThreats = ['Identity', 'Location', 'Event'];
    const hasVulnerabilities = ['System'];
    const initialValues = {};
    if (targetsVictimology.includes(type)) {
      initialValues.targets = '';
    }
    return (
      <Formik
        initialValues={initialValues}
        onSubmit={this.onSubmitEntity.bind(this)}
        onReset={this.onResetEntity.bind(this)}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <Form style={{ margin: '15px 0 20px 0', padding: '0 15px 0 15px' }}>
            {targetsVictimology.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="targets"
                title={t(
                  'Victimology (target relationships to identities and locations)',
                )}
                label={t('Victimology')}
                fullWidth={true}
              />
            )}
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
                color="success"
                onClick={() => submitForm(false)}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Submit')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    );
  }

  onSubmitEntity(values) {
    const { entityType, entityId, stixDomainObjects } = this.state;
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        type: 'marking-definition',
      }),
    );
    const identity = values.createdBy?.entity
      ? {
        ...values.createdBy.entity,
        id: values.createdBy.entity.standard_id || values.createdBy.entity.id,
        type: 'identity',
      }
      : null;
    const finalValues = {
      ...values,
      labels: R.pluck('label', values.objectLabel),
      object_marking_refs: R.pluck('entity', values.objectMarking).map(
        (n) => n.standard_id || n.id,
      ),
      created_by_ref:
        values.createdBy?.entity?.standard_id || values.createdBy?.entity?.id,
      external_references: R.pluck('entity', values.externalReferences),
    };
    const stixType = convertToStixType(entityType);
    const updatedEntity = {
      ...entity,
      ...finalValues,
      id: entity.id ? entity.id : `${stixType}-${uuid()}`,
      type: stixType,
    };
    if (updatedEntity.type === 'identity' && !updatedEntity.identity_class) {
      updatedEntity.identity_class = resolveIdentityClass(entityType);
    } else if (
      updatedEntity.type === 'location'
      && !updatedEntity.x_opencti_location_type
    ) {
      updatedEntity.x_opencti_location_type = entityType;
    }
    this.setState({
      stixDomainObjects: R.uniqBy(R.prop('id'), [
        ...stixDomainObjects.filter((n) => n.id !== updatedEntity.id),
        ...markingDefinitions,
        ...(identity ? [identity] : []),
        updatedEntity,
      ]),
      entityStep: 1,
    });
  }

  onResetEntity() {
    this.handleCloseEntity();
  }

  renderEntities() {
    const { classes, t } = this.props;
    const { entityType, entityStep, stixDomainObjects, sortBy, orderAsc } = this.state;
    const resolvedStixDomainObjects = stixDomainObjects.map((n) => ({
      ...n,
      ttype: t(`entity_${convertFromStixType(n.type)}`),
      default_value: defaultValue(n),
      markings: this.resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixDomainObjects = sort(resolvedStixDomainObjects);
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
            >
              <Checkbox edge="start" checked={false} disableRipple={true} />
            </ListItemIcon>
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
            <ListItemText
              primary={
                <div>
                  {this.SortHeader('ttype', 'Type', true)}
                  {this.SortHeader('default_value', 'Default value', true)}
                  {this.SortHeader('labels', 'Labels', true)}
                  {this.SortHeader('markings', 'Markings', true)}
                  {this.SortHeader('in_platform', 'Already in plat.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedStixDomainObjects.map((object) => {
            const type = convertFromStixType(object.type);
            let secondaryType = '';
            if (type === 'Identity') {
              secondaryType = ` (${t(
                `entity_${resolveIdentityType(object.identity_class)}`,
              )})`;
            }
            if (type === 'Location') {
              secondaryType = ` (${t(
                `entity_${resolveLocationType(object)}`,
              )})`;
            }
            const isInPlatform = true;
            return (
              <ListItem
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                onClick={this.handleOpenEntity.bind(
                  this,
                  object.type,
                  object.id,
                )}
              >
                <ListItemIcon
                  classes={{ root: classes.itemIcon }}
                  style={{ minWidth: 40 }}
                >
                  <Checkbox edge="start" checked={false} disableRipple={true} />
                </ListItemIcon>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.ttype}
                      >
                        {object.ttype}
                        {secondaryType}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.default_value || t('Unknown')}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <StixItemLabels
                          variant="inList"
                          labels={object.labels || []}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        <StixItemMarkings
                          variant="inList"
                          markingDefinitions={object.markings || []}
                          limit={2}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.in_platform}
                      >
                        <ItemBoolean
                          variant="inList"
                          status={isInPlatform}
                          label={isInPlatform ? t('Yes') : t('No')}
                        />
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={this.handleDeleteEntity.bind(this, object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <Fab
          onClick={this.handleOpenEntity.bind(this, null, null)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={entityStep !== null}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseEntity.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseEntity.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Manage an entity')}</Typography>
          </div>
          <div className={classes.container}>
            {!entityType && this.renderEntityTypesList()}
            {entityType && entityStep === 0 && this.renderEntityForm()}
            {entityType && entityStep === 1 && this.renderEntityContext()}
          </div>
        </Drawer>
      </div>
    );
  }

  render() {
    const { classes, file, t } = this.props;
    const { currentTab, deleteEntity } = this.state;
    return (
      <div className={classes.container}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {file.name.replace('.json', '')}
        </Typography>
        <div className="clearfix" />
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={this.handleChangeTab.bind(this)}>
            <Tab label={t('Entities')} />
            <Tab label={t('Observables')} />
            <Tab label={t('Relationships')} />
            <Tab label={t('Containers')} />
          </Tabs>
        </Box>
        {currentTab === 0 && this.renderEntities()}
        <Dialog
          open={deleteEntity !== null}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDeleteEntity.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this entity?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseDeleteEntity.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitDeleteEntity.bind(this)}
            >
              {t('Remove')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

WorkbenchFileContentComponent.propTypes = {
  file: PropTypes.object,
  stixDomainObjectTypes: PropTypes.object,
  observableTypes: PropTypes.object,
  connectorsImport: PropTypes.array,
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const WorkbenchFileContent = createFragmentContainer(
  WorkbenchFileContentComponent,
  {
    connectorsImport: graphql`
      fragment WorkbenchFileContent_connectorsImport on Connector
      @relay(plural: true) {
        id
        name
        active
        only_contextual
        connector_scope
        updated_at
      }
    `,
    file: graphql`
      fragment WorkbenchFileContent_file on File {
        id
        name
        uploadStatus
        lastModified
        lastModifiedSinceMin
        metaData {
          mimetype
          encoding
          list_filters
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
          entity_id
          entity {
            id
            standard_id
            entity_type
            ... on AttackPattern {
              name
            }
            ... on Campaign {
              name
            }
            ... on Report {
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
            ... on StixCyberObservable {
              observable_value
            }
          }
        }
        works {
          id
        }
        ...FileWork_file
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(WorkbenchFileContent);
