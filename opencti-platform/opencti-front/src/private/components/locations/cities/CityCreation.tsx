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
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { SimpleFileUpload } from 'formik-mui';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import { CitiesLinesPaginationQuery$variables } from './__generated__/CitiesLinesPaginationQuery.graphql';
import { CityCreationMutation$variables } from './__generated__/CityCreationMutation.graphql';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { Option } from '../../common/form/ReferenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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

const cityMutation = graphql`
  mutation CityCreationMutation($input: CityAddInput!) {
    cityAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      ...CityLine_node
    }
  }
`;

interface CityAddInput {
  name: string
  description: string
  latitude: string
  longitude: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: Option[]
  file: File | undefined
}

interface CityFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void
  onCompleted?: () => void
  defaultCreatedBy?: { value: string, label: string }
  defaultMarkingDefinitions?: { value: string, label: string }[]
}

export const CityCreationForm: FunctionComponent<CityFormProps> = ({ updater, onReset, onCompleted,
  defaultCreatedBy, defaultMarkingDefinitions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    latitude: Yup.number().typeError(t('This field must be a number')).nullable(),
    longitude: Yup.number().typeError(t('This field must be a number')).nullable(),
  };
  const cityValidator = useSchemaCreationValidation('City', basicShape);
  const [commit] = useMutation(cityMutation);

  const onSubmit: FormikConfig<CityAddInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const input: CityCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      latitude: parseFloat(values.latitude),
      longitude: parseFloat(values.longitude),
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'cityAdd');
        }
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

  return <Formik<CityAddInput>
      initialValues={{
        name: '',
        description: '',
        latitude: '',
        longitude: '',
        createdBy: defaultCreatedBy ?? { value: '', label: '' },
        objectMarking: defaultMarkingDefinitions ?? [],
        objectLabel: [],
        externalReferences: [],
        file: undefined,
      }}
      validationSchema={cityValidator}
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
              detectDuplicate={['City']}
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
              label={t('Longitude')}
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

const CityCreation = ({ paginationOptions }: { paginationOptions: CitiesLinesPaginationQuery$variables }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_cities',
    paginationOptions,
    'cityAdd',
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
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary">
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a city')}</Typography>
        </div>
        <div className={classes.container}>
          <CityCreationForm updater={updater} onCompleted={handleClose} onReset={handleClose}/>
        </div>
      </Drawer>
    </div>
  );
};

export default CityCreation;
