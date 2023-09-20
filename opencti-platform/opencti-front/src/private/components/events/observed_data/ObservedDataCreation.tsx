import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { SimpleFileUpload } from 'formik-mui';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import { handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { parse } from '../../../../utils/Time';
import ConfidenceField from '../../common/form/ConfidenceField';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import {
  ObservedDataCreationMutation,
  ObservedDataCreationMutation$variables,
} from './__generated__/ObservedDataCreationMutation.graphql';
import { ObservedDatasLinesPaginationQuery$variables } from './__generated__/ObservedDatasLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';

const useStyles = makeStyles<Theme>((theme) => ({
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
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const observedDataCreationMutation = graphql`
  mutation ObservedDataCreationMutation($input: ObservedDataAddInput!) {
    observedDataAdd(input: $input) {
      id
      standard_id
      name
      entity_type
      parent_types
      ...ObservedDataLine_node
    }
  }
`;

const OBSERVED_DATA_TYPE = 'Observed-Data';

interface ObservedDataAddInput {
  objects: { value: string }[]
  first_observed: Date | null
  last_observed: Date | null
  number_observed: number
  confidence: number | undefined
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  file: File | undefined,
}

interface ObservedDataFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string, response: { id: string, name: string } | null) => void
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string, label: string }
  defaultMarkingDefinitions?: { value: string, label: string }[]
  defaultConfidence?: number;
}

export const ObservedDataCreationForm: FunctionComponent<ObservedDataFormProps> = ({
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
    objects: Yup.array(),
    first_observed: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    last_observed: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    number_observed: Yup.number().required(t('This field is required')),
    confidence: Yup.number().nullable(),
  };
  const observedDataValidator = useSchemaCreationValidation(
    OBSERVED_DATA_TYPE,
    basicShape,
  );

  const [commit] = useMutation<ObservedDataCreationMutation>(observedDataCreationMutation);

  const onSubmit: FormikConfig<ObservedDataAddInput>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const input: ObservedDataCreationMutation$variables['input'] = {
      objects: values.objects.map((v) => v.value),
      first_observed: parse(values.first_observed).format(),
      last_observed: parse(values.last_observed).format(),
      number_observed: parseInt(String(values.number_observed), 10),
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater) {
          updater(store, 'observedDataAdd', response.observedDataAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  const initialValues = useDefaultValues(
    OBSERVED_DATA_TYPE,
    {
      objects: [],
      first_observed: null,
      last_observed: null,
      number_observed: 1,
      confidence: defaultConfidence,
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={observedDataValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <StixCoreObjectsField
            name="objects"
            style={{ width: '100%' }}
            setFieldValue={setFieldValue}
            values={values.objects}
          />
          <Field
            component={DateTimePickerField}
            name="first_observed"
            TextFieldProps={{
              label: t('First observed'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_observed"
            TextFieldProps={{
              label: t('Last observed'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="number_observed"
            type="number"
            label={t('Number observed')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <ConfidenceField
            entityType="Observed-Data"
            containerStyle={fieldSpacingContainerStyle}
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
          <Field
            component={SimpleFileUpload}
            name="file"
            label={t('Associated file')}
            FormControlProps={{ style: { marginTop: 20, width: '100%' } }}
            InputLabelProps={{ fullWidth: true, variant: 'standard' }}
            InputProps={{ fullWidth: true, variant: 'standard' }}
            fullWidth={true}
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

const ObservedDataCreation = ({ paginationOptions }: {
  paginationOptions: ObservedDatasLinesPaginationQuery$variables
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_observedDatas',
    paginationOptions,
    'observedDataAdd',
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
        elevation={1}
        sx={{ zIndex: 1202 }}
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
          <Typography variant="h6">{t('Create an observed data')}</Typography>
        </div>
        <div className={classes.container}>
          <ObservedDataCreationForm
            updater={updater}
            onCompleted={() => handleClose()}
            onReset={onReset}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default ObservedDataCreation;
