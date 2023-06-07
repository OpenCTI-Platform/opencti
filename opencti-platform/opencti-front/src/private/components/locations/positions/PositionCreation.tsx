import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { SimpleFileUpload } from 'formik-mui';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import {
  PositionCreationMutation,
  PositionCreationMutation$variables,
} from './__generated__/PositionCreationMutation.graphql';
import { PositionsLinesPaginationQuery$variables } from './__generated__/PositionsLinesPaginationQuery.graphql';

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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const positionMutation = graphql`
  mutation PositionCreationMutation($input: PositionAddInput!) {
    positionAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      ...PositionLine_node
    }
  }
`;

interface PositionAddInput {
  name: string
  description: string
  latitude: string
  longitude: string
  street_address: string
  postal_code: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  file: File | undefined
}

interface PositionFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string, label: string }
  defaultMarkingDefinitions?: { value: string, label: string }[]
  inputValue?: string;
}

export const PositionCreationForm: FunctionComponent<PositionFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    latitude: Yup.number()
      .typeError(t('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t('This field must be a number'))
      .nullable(),
    street_address: Yup.string().nullable().max(1000, t('The value is too long')),
    postal_code: Yup.string().nullable().max(1000, t('The value is too long')),
  };
  const positionValidator = useSchemaCreationValidation('Position', basicShape);

  const initialValues = {
    name: '',
    description: '',
    latitude: '',
    longitude: '',
    street_address: '',
    postal_code: '',
    createdBy: defaultCreatedBy ?? '' as unknown as Option,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  };

  const [commit] = useMutation<PositionCreationMutation>(positionMutation);

  const onSubmit: FormikConfig<PositionAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: PositionCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      latitude: parseFloat(values.latitude),
      longitude: parseFloat(values.longitude),
      street_address: values.street_address,
      postal_code: values.postal_code,
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
      updater: (store) => {
        if (updater) {
          updater(store, 'positionAdd');
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

  return <Formik
      initialValues={initialValues}
      validationSchema={positionValidator}
      onSubmit={onSubmit}
      onReset={onReset}>
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
              detectDuplicate={['Position']}
          />
          <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
          />
          <Field
              component={TextField}
              variant="standard"
              name="latitude"
              label={t('Latitude')}
              fullWidth={true}
              style={{ marginTop: 20 }}
          />
          <Field
              component={TextField}
              variant="standard"
              name="longitude"
              label={t('Longitude')}fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="street_address"
                    label={t('Street address')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="postal_code"
                    label={t('Postal code')}
              fullWidth={true}
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
  </Formik>;
};

const PositionCreation = ({ paginationOptions }: { paginationOptions: PositionsLinesPaginationQuery$variables }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_positions',
    paginationOptions,
    'positionAdd',
  );

  return (
      <div>
        <Fab onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}>
          <Add />
        </Fab>
        <Drawer open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}>
          <div className={classes.header}>
            <IconButton aria-label="Close"
              className={classes.closeButton}
              onClick={handleClose}
              size="large"
              color="primary">
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a position')}</Typography>
          </div>
          <div className={classes.container}>
            <PositionCreationForm
                updater={updater}
                onCompleted={() => handleClose()}
                onReset={onReset}
            />
          </div>
        </Drawer>
      </div>
  );
};

export default PositionCreation;
