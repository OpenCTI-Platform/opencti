import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as R from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
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
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';

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
    right: 30,
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

const infrastructureMutation = graphql`
  mutation InfrastructureCreationMutation($input: InfrastructureAddInput!) {
    infrastructureAdd(input: $input) {
      id
      name
      entity_type
      description
      ...InfrastructureLine_node
    }
  }
`;

export const InfrastructureCreationForm = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    infrastructure_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .min(
        Yup.ref('first_seen'),
        "The last seen date can't be before first seen date",
      )
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  };
  const infrastructureValidator = useSchemaCreationValidation(
    'Infrastructure',
    basicShape,
  );
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const adaptedValues = R.evolve(
      {
        confidence: () => parseInt(values.confidence, 10),
        createdBy: R.path(['value']),
        objectMarking: R.pluck('value'),
        objectLabel: R.pluck('value'),
        externalReferences: R.pluck('value'),
        first_seen: values.first_seen
          ? parse(values.first_seen).format()
          : null,
        last_seen: values.first_seen ? parse(values.last_seen).format() : null,
        killChainPhases: R.pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: infrastructureMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'infrastructureAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  return (
    <Formik
      initialValues={{
        name: '',
        infrastructure_types: [],
        confidence: defaultConfidence ?? 75,
        description: '',
        createdBy: defaultCreatedBy ?? '',
        objectMarking: defaultMarkingDefinitions ?? [],
        objectLabel: [],
        externalReferences: [],
        first_seen: null,
        last_seen: null,
        killChainPhases: [],
      }}
      validationSchema={infrastructureValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Infrastructure']}
          />
          <OpenVocabField
            label={t('Infrastructure types')}
            type="infrastructure-type-ov"
            name="infrastructure_types"
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            onChange={(name, value) => setFieldValue(name, value)}
          />
          <ConfidenceField
            entityType="Infrastructure"
            containerStyle={{ width: '100%', marginTop: 20 }}
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
          <KillChainPhasesField
            name="killChainPhases"
            style={fieldSpacingContainerStyle}
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
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
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
  );
};

const InfrastructureCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();

  const updater = (store) => insertNode(
    store,
    'Pagination_infrastructures',
    paginationOptions,
    'infrastructureAdd',
  );

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
          <Typography variant="h6">{t('Create an infrastructure')}</Typography>
        </div>
        <div className={classes.container}>
          <InfrastructureCreationForm
            updater={updater}
            onCompleted={() => handleClose()}
            onReset={onReset}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default InfrastructureCreation;
