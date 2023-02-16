import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { evolve, path, pluck } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import {
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import TypesField from '../TypesField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';

const useStyles = makeStyles((theme) => ({
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
}));

const indicatorMutation = graphql`
  mutation IndicatorCreationMutation($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      ...IndicatorLine_node
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  indicator_types: Yup.array(),
  confidence: Yup.number(),
  description: Yup.string().nullable(),
  x_opencti_score: Yup.number().nullable(),
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

const IndicatorCreation = ({ paginationOptions }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const adaptedValues = evolve(
      {
        confidence: () => parseInt(values.confidence, 10),
        killChainPhases: pluck('value'),
        createdBy: path(['value']),
        objectMarking: pluck('value'),
        objectLabel: pluck('value'),
        externalReferences: pluck('value'),
        x_opencti_score: () => parseInt(values.x_opencti_score, 10),
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
        sharedUpdater(store, container.getDataID(), paginationOptions, newEdge);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };
  const onReset = () => handleClose();
  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
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
              indicator_types: [],
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
              x_opencti_score: 50,
            }}
            validationSchema={indicatorValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
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
                <OpenVocabField
                  label={t('Indicator types')}
                  type="indicator-type-ov"
                  name="indicator_types"
                  multiple={true}
                  containerStyle={fieldSpacingContainerStyle}
                  onChange={(n, v) => setFieldValue(n, v)}
                />
                <ConfidenceField
                  name="confidence"
                  label={t('Confidence')}
                  fullWidth={true}
                  containerStyle={fieldSpacingContainerStyle}
                />
                <OpenVocabField
                  label={t('Pattern type')}
                  type="pattern_type_ov"
                  name="pattern_type"
                  onChange={(name, value) => setFieldValue(name, value)}
                  containerStyle={fieldSpacingContainerStyle}
                  multiple={false}
                />
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
                <OpenVocabField
                  label={t('Platforms')}
                  type="platforms_ov"
                  name="x_mitre_platforms"
                  onChange={(name, value) => setFieldValue(name, value)}
                  containerStyle={fieldSpacingContainerStyle}
                  multiple={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_score"
                  label={t('Score')}
                  type="number"
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
                  fullWidth={true}
                  containerstyle={{ marginTop: 20 }}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="createObservables"
                  label={t('Create observables from this indicator')}
                  fullWidth={true}
                  containerstyle={{ marginTop: 10 }}
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
};

export default IndicatorCreation;
