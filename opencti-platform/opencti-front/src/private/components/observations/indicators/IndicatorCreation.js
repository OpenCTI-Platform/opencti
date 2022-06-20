import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { compose, pluck, evolve, path } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import TypesField from '../TypesField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ConfidenceField from '../../common/form/ConfidenceField';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';

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
    right: 280,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  createButtonExports: {
    position: 'fixed',
    bottom: 30,
    right: 590,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
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

const indicatorMutation = graphql`
  mutation IndicatorCreationMutation($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      ...IndicatorLine_node
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number(),
  description: Yup.string().nullable(),
  pattern: Yup.string().required(t('This field is required')),
  pattern_type: Yup.string().required(t('This field is required')),
  valid_from: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  valid_until: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  x_opencti_main_observable_type: Yup.string().required(
    t('This field is required'),
  ),
  x_opencti_detection: Yup.boolean(),
  createObservables: Yup.boolean(),
  x_mitre_platforms: Yup.array(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_indicators',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class IndicatorCreation extends Component {
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

  onSubmit(values, { setSubmitting, setErrors, resetForm }) {
    const adaptedValues = evolve(
      {
        confidence: () => parseInt(values.confidence, 10),
        killChainPhases: pluck('value'),
        createdBy: path(['value']),
        objectMarking: pluck('value'),
        objectLabel: pluck('value'),
        externalReferences: pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: indicatorMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store) => {
        const payload = store.getRootField('indicatorAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          newEdge,
        );
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes, openExports } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={
            openExports ? classes.createButtonExports : classes.createButton
          }
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
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
            <Typography variant="h6">{t('Create an indicator')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                confidence: 75,
                pattern: '',
                pattern_type: '',
                x_opencti_main_observable_type: '',
                x_mitre_platforms: [],
                valid_from: null,
                valid_until: null,
                description: '',
                createdBy: '',
                objectMarking: [],
                killChainPhases: [],
                objectLabel: [],
                externalReferences: [],
                x_opencti_detection: false,
              }}
              validationSchema={indicatorValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  />
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
                  <TypesField
                    name="x_opencti_main_observable_type"
                    label={t('Main observable type')}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  />
                  <Field
                    component={DateTimePickerField}
                    name="valid_from"
                    TextFieldProps={{
                      label: t('Valid from'),
                      variant: 'standard',
                      fullWidth: true,
                      style: { marginTop: 20 },
                    }}
                  />
                  <Field
                    component={DateTimePickerField}
                    name="valid_until"
                    TextFieldProps={{
                      label: t('Valid until'),
                      variant: 'standard',
                      fullWidth: true,
                      style: { marginTop: 20 },
                    }}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="x_mitre_platforms"
                    multiple={true}
                    label={t('Platforms')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value="Android">{t('Android')}</MenuItem>
                    <MenuItem value="macOS">{t('macOS')}</MenuItem>
                    <MenuItem value="Linux">{t('Linux')}</MenuItem>
                    <MenuItem value="Windows">{t('Windows')}</MenuItem>
                  </Field>
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <KillChainPhasesField
                    name="killChainPhases"
                    style={{ marginTop: 20, width: '100%' }}
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
                  <ExternalReferencesField
                    name="externalReferences"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.externalReferences}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="x_opencti_detection"
                    label={t('Detection')}
                    containerstyle={{ marginTop: 20 }}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="createObservables"
                    label={t('Create observables from this indicator')}
                    containerstyle={{ marginTop: 20 }}
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
}

IndicatorCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IndicatorCreation);
