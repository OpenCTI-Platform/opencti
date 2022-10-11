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
import { Add, ArrowDropDown, ArrowDropUp, Close } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Checkbox from '@mui/material/Checkbox';
import { v4 as uuid } from 'uuid';
import inject18n from '../../../../components/i18n';
import {
  booleanAttributes,
  dateAttributes,
  markdownAttributes,
  numberAttributes,
  resolveLink,
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
} from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemLabels from '../../../../components/ItemLabels';
import { defaultValue } from '../../../../utils/Graph';
import { stixDomainObjectContentFilesUploadStixDomainObjectMutation } from '../../common/stix_domain_objects/StixDomainObjectContentFiles';

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
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  type: {
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
  type: {
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
      stixDomainObjects: [],
      stixCyberObservables: [],
      stixCoreRelationships: [],
      containers: [],
      openCreate: false,
      createType: null,
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
        ...stixDomainObjects.map((n) => R.dissoc('extras', n)),
        ...stixCyberObservables.map((n) => R.dissoc('extras', n)),
        ...stixCoreRelationships.map((n) => R.dissoc('extras', n)),
        ...containers.map((n) => R.dissoc('extras', n)),
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

  computeState(objects) {
    const { stixDomainObjectTypes, observableTypes } = this.props;
    const sdoTypes = [
      ...stixDomainObjectTypes.edges.map((n) => convertToStixType(n.node.id)),
      'marking-definition',
      'identity',
      'location',
    ].filter((n) => !typesContainers.includes(n));
    const scoTypes = observableTypes.edges.map((n) => convertToStixType(n.node.id));
    const stixDomainObjects = objects
      .filter((n) => sdoTypes.includes(n.type))
      .map((n) => R.assocPath(['extras', 'default_value'], defaultValue(n), n));
    const stixCyberObservables = objects
      .filter((n) => scoTypes.includes(n.type))
      .map((n) => R.assocPath(['extras', 'default_value'], defaultValue(n), n));
    const containers = objects.filter((n) => typesContainers.includes(n.type));
    return { stixDomainObjects, stixCyberObservables, containers };
  }

  handleChangeTab(_, index) {
    this.setState({ currentTab: index });
  }

  handleOpenCreate() {
    this.setState({ openCreate: true });
  }

  handleCloseCreate() {
    this.setState({ openCreate: false, createType: null });
  }

  selectCreateType(createType) {
    this.setState({ createType });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
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

  renderEntitiesList() {
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
            onClick={this.selectCreateType.bind(this, subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItem>
        ))}
      </List>
    );
  }

  onSubmitEntity(values) {
    const { createType, stixDomainObjects } = this.state;
    const entity = { type: convertToStixType(createType), ...values };
    this.setState({ stixDomainObjects: R.append(entity, stixDomainObjects) });
    this.saveFile();
    this.handleCloseCreate();
  }

  onResetEntity() {
    this.handleCloseCreate();
  }

  renderEntityForm() {
    const { createType } = this.state;
    const { classes, t } = this.props;
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: createType }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
              externalReferences: [],
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
                initialValues[attribute] = null;
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = false;
              } else {
                initialValues[attribute] = '';
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
                        variant={'contained'}
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        variant={'contained'}
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Create')}
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

  renderEntities() {
    const { classes, t } = this.props;
    const { createType, openCreate, stixDomainObjects } = this.state;
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
                  {this.SortHeader('type', 'Type', true)}
                  {this.SortHeader('default_value', 'Default value', true)}
                  {this.SortHeader('labels', 'Labels', true)}
                  {this.SortHeader('markings', 'Markings', true)}
                  {this.SortHeader('in_platform', 'Already in plat.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {stixDomainObjects.map((object) => {
            const type = convertFromStixType(object.type);
            const isInPlatform = true;
            return (
              <ListItem classes={{ root: classes.item }} divider={true}>
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
                        style={inlineStyles.type}
                      >
                        {type}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.extras.default_value}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <ItemLabels labels={object.labels} variant="inList" />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        &nbsp;
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
                <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <Fab
          onClick={this.handleOpenCreate.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={openCreate}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseCreate.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseCreate.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create an entity')}</Typography>
          </div>
          <div className={classes.container}>
            {!createType ? this.renderEntitiesList() : this.renderEntityForm()}
          </div>
        </Drawer>
      </div>
    );
  }

  render() {
    const { classes, file, t } = this.props;
    const { currentTab } = this.state;
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
            <Tab label={t('Containers')} />
          </Tabs>
        </Box>
        {currentTab === 0 && this.renderEntities()}
      </div>
    );
  }
}

WorkbenchFileContentComponent.propTypes = {
  file: PropTypes.object,
  stixDomainObjectTypes: PropTypes.array,
  observableTypes: PropTypes.array,
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
