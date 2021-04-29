import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import {
  assoc,
  compose,
  pipe,
  pluck,
  split,
  dissoc,
  includes,
  map,
  filter,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ObjectLabelField from '../form/ObjectLabelField';

const typesWithOpenCTIAliases = [
  'Course-Of-Action',
  'Identity',
  'Individual',
  'Organization',
  'Sector',
  'Position',
  'Location',
  'City',
  'Country',
  'Region',
];

const typesWithoutAliases = ['Indicator', 'Vulnerability'];

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
    zIndex: 2000,
  },
  createButtonSpeedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
});

const stixDomainObjectCreationMutation = graphql`
  mutation StixDomainObjectCreationMutation($input: StixDomainObjectAddInput!) {
    stixDomainObjectAdd(input: $input) {
      id
      entity_type
      parent_types
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition
          }
        }
      }
      ... on AttackPattern {
        name
        description
      }
      ... on Campaign {
        name
        description
      }
      ... on CourseOfAction {
        name
        description
      }
      ... on Individual {
        name
        description
      }
      ... on Organization {
        name
        description
      }
      ... on Sector {
        name
        description
      }
      ... on Indicator {
        name
        description
      }
      ... on Infrastructure {
        name
        description
      }
      ... on IntrusionSet {
        name
        description
      }
      ... on Position {
        name
        description
      }
      ... on City {
        name
        description
      }
      ... on Country {
        name
        description
      }
      ... on Region {
        name
        description
      }
      ... on Malware {
        name
        description
      }
      ... on ThreatActor {
        name
        description
      }
      ... on Tool {
        name
        description
      }
      ... on Vulnerability {
        name
        description
      }
      ... on Incident {
        name
        description
      }
    }
  }
`;

const stixDomainObjectValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  type: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (
  store,
  userId,
  paginationOptions,
  paginationKey,
  newEdge,
) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    paginationKey,
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixDomainObjectCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    let finalValues = pipe(
      assoc('createdBy', values.createdBy.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
      assoc('objectLabel', pluck('value', values.objectLabel)),
    )(values);
    if (finalValues.type !== 'Indicator') {
      finalValues = pipe(
        dissoc('pattern_type'),
        dissoc('pattern'),
      )(finalValues);
    }
    if (includes(finalValues.type, typesWithoutAliases)) {
      finalValues = pipe(
        dissoc('aliases'),
        dissoc('x_opencti_aliases'),
      )(finalValues);
    } else if (includes(finalValues.type, typesWithOpenCTIAliases)) {
      finalValues = pipe(
        dissoc('aliases'),
        assoc(
          'x_opencti_aliases',
          filter((n) => n.length > 0, split(',', finalValues.x_opencti_aliases)),
        ),
      )(finalValues);
    } else {
      finalValues = pipe(
        dissoc('x_opencti_aliases'),
        assoc(
          'aliases',
          filter((n) => n.length > 0, split(',', finalValues.aliases)),
        ),
      )(finalValues);
    }
    commitMutation({
      mutation: stixDomainObjectCreationMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('stixDomainObjectAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          this.props.paginationKey || 'Pagination_stixDomainObjects',
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

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    this.handleClose();
  }

  renderEntityTypesList() {
    const { t, targetStixDomainObjectTypes } = this.props;
    return (
      <Field
        component={SelectField}
        name="type"
        label={t('Entity type')}
        fullWidth={true}
        containerstyle={{ width: '100%' }}
      >
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Organization', 'Identity'].indexOf(r) >= 0,
          ) && <MenuItem value="Organization">{t('Organization')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Sector', 'Identity'].indexOf(r) >= 0,
          ) && <MenuItem value="Sector">{t('Sector')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Individual', 'Identity'].indexOf(r) >= 0,
          ) && <MenuItem value="Individual">{t('Individual')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Threat-Actor'].indexOf(r) >= 0,
          ) && <MenuItem value="Threat-Actor">{t('Threat actor')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Intrusion-Set'].indexOf(r) >= 0,
          ) && <MenuItem value="Intrusion-Set">{t('Intrusion set')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Campaign'].indexOf(r) >= 0,
          ) && <MenuItem value="Campaign">{t('Campaign')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Incident'].indexOf(r) >= 0,
          ) && <MenuItem value="Incident">{t('Incident')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Malware'].indexOf(r) >= 0,
          ) && <MenuItem value="Malware">{t('Malware')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Tool'].indexOf(r) >= 0,
          ) && <MenuItem value="Tool">{t('Tool')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Vulnerability'].indexOf(r) >= 0,
          ) && <MenuItem value="Vulnerability">{t('Vulnerability')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Infrastructure'].indexOf(r) >= 0,
          ) && (
            <MenuItem value="Infrastructure">{t('Infrastructure')}</MenuItem>
          ))}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Attack-Pattern'].indexOf(r) >= 0,
          ) && (
            <MenuItem value="Attack-Pattern">{t('Attack pattern')}</MenuItem>
          ))}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Indicator'].indexOf(r) >= 0,
          ) && <MenuItem value="Indicator">{t('Indicator')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Location', 'City'].indexOf(r) >= 0,
          ) && <MenuItem value="City">{t('City')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Location', 'Country'].indexOf(r) >= 0,
          ) && <MenuItem value="Country">{t('Country')}</MenuItem>)}
        {targetStixDomainObjectTypes === undefined
          || (targetStixDomainObjectTypes.some(
            (r) => ['Stix-Domain-Object', 'Location', 'Region'].indexOf(r) >= 0,
          ) && <MenuItem value="Region">{t('Region')}</MenuItem>)}
      </Field>
    );
  }

  renderClassic() {
    const { t, classes, targetStixDomainObjectTypes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
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
            <Typography variant="h6">{t('Create an entity')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                type: '',
                name: '',
                description: '',
                pattern_type: '',
                pattern: '',
                aliases: '',
                x_opencti_aliases: '',
                createdBy: '',
                objectLabel: [],
                objectMarking: [],
              }}
              validationSchema={stixDomainObjectValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  {this.renderEntityTypesList()}
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    detectDuplicate={targetStixDomainObjectTypes || []}
                  />
                  {!includes(values.type, typesWithoutAliases) && (
                    <Field
                      component={TextField}
                      name={
                        includes(values.type, typesWithOpenCTIAliases)
                          ? 'x_opencti_aliases'
                          : 'aliases'
                      }
                      label={t('Aliases separated by commas')}
                      fullWidth={true}
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {values.type === 'Indicator' && (
                    <div>
                      <Field
                        component={SelectField}
                        name="pattern_type"
                        label={t('Pattern type')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      >
                        <MenuItem value="stix">STIX</MenuItem>
                        <MenuItem value="pcre">PCRE</MenuItem>
                        <MenuItem value="sigma">SIGMA</MenuItem>
                        <MenuItem value="snort">SNORT</MenuItem>
                        <MenuItem value="suricata">Suricata</MenuItem>
                        <MenuItem value="yara">YARA</MenuItem>
                        <MenuItem value="tanium-signal">Tanium Signal</MenuItem>
                      </Field>
                      <Field
                        component={TextField}
                        name="pattern"
                        label={t('Pattern')}
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                        detectDuplicate={['Indicator']}
                      />
                    </div>
                  )}
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
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  }

  renderContextual() {
    const {
      t,
      classes,
      inputValue,
      display,
      defaultCreatedBy,
      defaultMarkingDefinitions,
      targetStixDomainObjectTypes,
    } = this.props;
    const initialValues = {
      type: '',
      name: inputValue,
      description: '',
      aliases: '',
      x_opencti_aliases: '',
      pattern_type: '',
      pattern: '',
      createdBy: defaultCreatedBy
        ? {
          label: defaultCreatedBy.name,
          value: defaultCreatedBy.id,
          type: defaultCreatedBy.entity_type,
        }
        : '',
      objectLabel: [],
      objectMarking: defaultMarkingDefinitions
        ? map(
          (n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          }),
          defaultMarkingDefinitions,
        )
        : [],
    };
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixDomainObjectValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form>
              <Dialog
                open={this.state.open}
                onClose={this.handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  {this.renderEntityTypesList()}
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    detectDuplicate={targetStixDomainObjectTypes || []}
                  />
                  {!includes(values.type, typesWithoutAliases) && (
                    <Field
                      component={TextField}
                      name={
                        includes(values.type, typesWithOpenCTIAliases)
                          ? 'x_opencti_aliases'
                          : 'aliases'
                      }
                      label={t('Aliases separated by commas')}
                      fullWidth={true}
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {values.type === 'Indicator' && (
                    <div>
                      <Field
                        component={SelectField}
                        name="pattern_type"
                        label={t('Pattern type')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      >
                        <MenuItem value="stix">STIX</MenuItem>
                        <MenuItem value="pcre">PCRE</MenuItem>
                        <MenuItem value="sigma">SIGMA</MenuItem>
                        <MenuItem value="snort">SNORT</MenuItem>
                        <MenuItem value="suricata">Suricata</MenuItem>
                        <MenuItem value="yara">YARA</MenuItem>
                        <MenuItem value="tanium-signal">Tanium Signal</MenuItem>
                      </Field>
                      <Field
                        component={TextField}
                        name="pattern"
                        label={t('Pattern')}
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                        detectDuplicate={['Indicator']}
                      />
                    </div>
                  )}
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
                    defaultCreatedBy={defaultCreatedBy}
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
                    defaultMarkingDefinitions={defaultMarkingDefinitions}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

StixDomainObjectCreation.propTypes = {
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  targetStixDomainObjectTypes: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.array,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainObjectCreation);
