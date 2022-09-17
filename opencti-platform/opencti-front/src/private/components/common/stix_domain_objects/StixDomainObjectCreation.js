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
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as R from 'ramda';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ObjectLabelField from '../form/ObjectLabelField';
import ConfidenceField from '../form/ConfidenceField';

export const stixDomainObjectCreationAllTypesQuery = graphql`
  query StixDomainObjectCreationAllTypesQuery {
    sdoTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

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
  'Event',
  'Channel',
  'Narrative',
];

const typesWithoutAliases = ['Indicator', 'Vulnerability', 'Language'];

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
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
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
      revoked
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
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
      ... on System {
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
      ... on Event {
        name
        description
      }
      ... on Channel {
        name
        description
      }
      ... on Narrative {
        name
        description
      }
      ... on Language {
        name
      }
    }
  }
`;

const stixDomainObjectValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string().nullable(),
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
      assoc('confidence', parseInt(values.confidence, 10)),
      assoc('createdBy', values.createdBy?.value),
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
    if (this.props.speeddial) {
      this.props.handleClose();
    } else {
      this.handleClose();
    }
  }

  renderEntityTypesList() {
    const { t, targetStixDomainObjectTypes } = this.props;
    return (
      <QueryRenderer
        query={stixDomainObjectCreationAllTypesQuery}
        render={({ props: data }) => {
          if (data && data.sdoTypes) {
            let result = [];
            result = [
              ...R.pipe(
                R.pathOr([], ['sdoTypes', 'edges']),
                R.map((n) => ({
                  label: t(`entity_${n.node.label}`),
                  value: n.node.label,
                  type: n.node.label,
                })),
              )(data),
              ...result,
            ];
            const entitiesTypes = R.sortWith(
              [R.ascend(R.prop('label'))],
              result,
            );
            const availableEntityTypes = R.filter((n) => {
              if (
                !targetStixDomainObjectTypes
                || targetStixDomainObjectTypes.length === 0
                || targetStixDomainObjectTypes.includes('Stix-Domain-Object')
              ) {
                return true;
              }
              if (
                targetStixDomainObjectTypes.includes('Identity')
                && [
                  'Sector',
                  'Organization',
                  'Individual',
                  'System',
                  'Event',
                ].includes(n.value)
              ) {
                return true;
              }
              if (
                targetStixDomainObjectTypes.includes('Location')
                && ['Region', 'Country', 'City', 'Location'].includes(n.value)
              ) {
                return true;
              }
              return !!targetStixDomainObjectTypes.includes(n.value);
            }, entitiesTypes);
            return (
              <Field
                component={SelectField}
                variant="standard"
                name="type"
                label={t('Entity type')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
              >
                {availableEntityTypes.map((type) => (
                  <MenuItem key={type.value} value={type.value}>
                    {type.label}
                  </MenuItem>
                ))}
              </Field>
            );
          }
          return <div />;
        }}
      />
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
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create an entity')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                type: '',
                name: '',
                confidence: 75,
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
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    detectDuplicate={targetStixDomainObjectTypes || []}
                  />
                  {!includes(values.type, typesWithoutAliases) && (
                    <Field
                      component={TextField}
                      variant="standard"
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
                        variant="standard"
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
                        <MenuItem value="spl">Splunk SPL</MenuItem>
                        <MenuItem value="eql">Elastic EQL</MenuItem>
                      </Field>
                      <Field
                        component={TextField}
                        variant="standard"
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
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
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
      speeddial,
      defaultCreatedBy,
      defaultMarkingDefinitions,
      confidence,
      targetStixDomainObjectTypes,
    } = this.props;
    const initialValues = {
      type: '',
      name: inputValue,
      confidence: confidence || 15,
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
        {!speeddial && (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
          >
            <Add />
          </Fab>
        )}
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
                PaperProps={{ elevation: 1 }}
                open={speeddial ? this.props.open : this.state.open}
                onClose={
                  speeddial
                    ? this.props.handleClose.bind(this)
                    : this.handleClose.bind(this)
                }
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  {this.renderEntityTypesList()}
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    detectDuplicate={targetStixDomainObjectTypes || []}
                  />
                  {!includes(values.type, typesWithoutAliases) && (
                    <Field
                      component={TextField}
                      variant="standard"
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
                        variant="standard"
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
                        <MenuItem value="spl">Splunk SPL</MenuItem>
                        <MenuItem value="eql">Elastic EQL</MenuItem>
                      </Field>
                      <Field
                        component={TextField}
                        variant="standard"
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
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
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
                    color="secondary"
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
  speeddial: PropTypes.bool,
  handleClose: PropTypes.func,
  display: PropTypes.bool,
  open: PropTypes.bool,
  inputValue: PropTypes.string,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.array,
  confidence: PropTypes.number,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainObjectCreation);
